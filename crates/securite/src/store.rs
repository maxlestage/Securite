//! Sharded, bounded, self-cleaning in-memory map used by stateful guards.

use std::collections::HashMap;
use std::collections::hash_map::{Entry, RandomState};
use std::hash::{BuildHasher, Hash};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

const SHARDS: usize = 64;
const SWEEP_EVERY: u32 = 4096;

pub(crate) struct ShardedMap<K, V> {
    shards: Box<[Mutex<Shard<K, V>>]>,
    // SipHash with random keys: attacker controlled keys cannot cause HashDoS.
    hasher: RandomState,
    max_per_shard: usize,
    epoch: Instant,
}

struct Shard<K, V> {
    map: HashMap<K, V>,
    ops: u32,
}

impl<K: Hash + Eq, V> ShardedMap<K, V> {
    pub(crate) fn new(max_entries: usize) -> Self {
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    map: HashMap::new(),
                    ops: 0,
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            hasher: RandomState::new(),
            max_per_shard: (max_entries / SHARDS).max(16),
            epoch: Instant::now(),
        }
    }

    /// Monotonic nanoseconds since the store was created.
    #[inline]
    pub(crate) fn now(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    #[inline]
    fn shard(&self, key: &K) -> MutexGuard<'_, Shard<K, V>> {
        let idx = (self.hasher.hash_one(key) as usize) & (SHARDS - 1);
        self.shards[idx]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `f` on the entry for `key`.
    ///
    /// Expired entries are swept periodically. Returns `None` when the shard
    /// is full of live entries and `key` is new (memory exhaustion guard).
    pub(crate) fn update<R>(
        &self,
        key: K,
        expired: impl Fn(&V) -> bool,
        f: impl FnOnce(Entry<'_, K, V>) -> R,
    ) -> Option<R> {
        let mut shard = self.shard(&key);
        shard.ops = shard.ops.wrapping_add(1);
        if shard.ops % SWEEP_EVERY == 0 {
            shard.map.retain(|_, v| !expired(v));
        }
        if shard.map.len() >= self.max_per_shard && !shard.map.contains_key(&key) {
            shard.map.retain(|_, v| !expired(v));
            if shard.map.len() >= self.max_per_shard {
                return None;
            }
        }
        Some(f(shard.map.entry(key)))
    }

    /// Reads the value for `key` without inserting.
    pub(crate) fn get<R>(&self, key: &K, f: impl FnOnce(Option<&mut V>) -> R) -> R {
        let mut shard = self.shard(key);
        f(shard.map.get_mut(key))
    }

    /// Removes `key`.
    pub(crate) fn remove(&self, key: &K) -> Option<V> {
        self.shard(key).map.remove(key)
    }

    /// Visits every live entry.
    pub(crate) fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        for shard in self.shards.iter() {
            let shard = shard.lock().unwrap_or_else(|p| p.into_inner());
            for (k, v) in &shard.map {
                f(k, v);
            }
        }
    }

    /// Total number of entries (approximate under concurrency).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|p| p.into_inner()).map.len())
            .sum()
    }
}
