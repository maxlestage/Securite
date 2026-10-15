//! Server-side sessions hardened after OWASP's Session Management cheat
//! sheet and ASVS V3.
//!
//! * **Unguessable ids**: 256 bits from the operating system RNG.
//! * **Ids never stored**: the store only sees the SHA-256 of the id, so a
//!   leaked store (Redis dump, backup) does not hand out live sessions.
//! * **Fixation protection**: [`SessionManager::login`] gives the session a
//!   new id (and so does [`SessionManager::regenerate`], for any privilege
//!   change); the old id stops working at once.
//! * **Idle and absolute timeouts** (30 minutes and 12 hours by default),
//!   enforced on the server, whatever the cookie says.
//! * **Hardened cookie**: `__Host-` prefix, `Secure`, `HttpOnly`,
//!   `SameSite=Lax`, `Path=/`, no `Domain`.
//! * **Logout** destroys the session server side, expires the cookie and
//!   sends `Clear-Site-Data` so the browser drops cached pages and storage.
//!
//! The [`Sessions`] guard loads the session of each request into the request
//! extensions; handlers change it and send [`SessionManager::commit`]'s
//! `Set-Cookie`.
//!
//! ```
//! use std::sync::Arc;
//! use std::time::Duration;
//! use http::HeaderMap;
//! use securite::session::{MemorySessionStore, SessionManager};
//!
//! let sessions = SessionManager::new(Arc::new(MemorySessionStore::new(100_000)))
//!     .idle_timeout(Duration::from_secs(15 * 60));
//!
//! // Login handler, after the password check:
//! let mut session = sessions.start();
//! sessions.login(&mut session, "user-42");
//! session.insert("theme", "dark");
//! let set_cookie = sessions.commit(&session); // -> `Set-Cookie` header
//!
//! // Next request:
//! let mut headers = HeaderMap::new();
//! let cookie = set_cookie.to_str().unwrap().split(';').next().unwrap().to_owned();
//! headers.insert("cookie", cookie.parse().unwrap());
//! let session = sessions.load(&headers).unwrap();
//! assert_eq!(session.user(), Some("user-42"));
//!
//! // Logout handler: add every header to the response.
//! let headers_to_send = sessions.logout(session);
//! assert_eq!(headers_to_send.len(), 2);
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::{COOKIE, HeaderName, HeaderValue, SET_COOKIE};
use http::{HeaderMap, request};
use sha2::{Digest, Sha256};

use crate::cookies::SameSite;
use crate::guard::impl_layer;
use crate::util::{b64url, cookie_pairs, hex_encode, secure_random};
use crate::{Context, Guard, Rejection};

/// The value of `Clear-Site-Data` sent on logout.
pub const CLEAR_SITE_DATA_LOGOUT: &str = "\"cache\", \"cookies\", \"storage\"";

const ID_BYTES: usize = 32;
const ID_CHARS: usize = 43;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What a store keeps for a session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionData {
    /// Application values.
    pub values: BTreeMap<String, String>,
    /// The authenticated user, if any.
    pub user: Option<String>,
    /// Creation time (Unix seconds), for the absolute timeout.
    pub created_at: u64,
    /// Last activity (Unix seconds), for the idle timeout.
    pub last_seen: u64,
}

/// Where sessions live. Keys are SHA-256 digests of the session ids (64 hex
/// characters), never the ids themselves.
///
/// Implement it over Redis, a database … to share sessions between
/// instances. Calls are synchronous: use a client with short timeouts, and
/// treat a store error as a missing session (`None`), which logs the user
/// out rather than letting them in.
pub trait SessionStore: Send + Sync + 'static {
    /// The data saved under `key`, unless it has expired.
    fn load(&self, key: &str) -> Option<SessionData>;
    /// Saves `data` under `key`, to expire after `ttl`.
    fn save(&self, key: &str, data: &SessionData, ttl: Duration);
    /// Removes `key`.
    fn delete(&self, key: &str);
}

/// In-memory [`SessionStore`] for one instance, bounded: when full, expired
/// sessions are swept, then the session closest to expiry is evicted.
#[derive(Debug)]
pub struct MemorySessionStore {
    map: Mutex<HashMap<String, (SessionData, u64)>>,
    max: usize,
}

impl MemorySessionStore {
    /// A store holding at most `max_sessions` sessions.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max: max_sessions.max(1),
        }
    }

    /// Number of stored sessions (expired ones included until swept).
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SessionStore for MemorySessionStore {
    fn load(&self, key: &str) -> Option<SessionData> {
        let map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.get(key)
            .filter(|(_, exp)| *exp > now_unix())
            .map(|(d, _)| d.clone())
    }

    fn save(&self, key: &str, data: &SessionData, ttl: Duration) {
        let now = now_unix();
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= self.max && !map.contains_key(key) {
            map.retain(|_, (_, exp)| *exp > now);
            if map.len() >= self.max {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, (_, exp))| *exp)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(
            key.to_owned(),
            (data.clone(), now.saturating_add(ttl.as_secs().max(1))),
        );
    }

    fn delete(&self, key: &str) {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
    }
}

/// A session: its data and its (secret) id. Put in the request extensions
/// by the [`Sessions`] guard.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    id: String,
    data: SessionData,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the id: it is a bearer credential.
        f.debug_struct("Session")
            .field("user", &self.data.user)
            .field("values", &self.data.values.len())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// A value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.values.get(key).map(String::as_str)
    }

    /// Sets a value (call [`SessionManager::commit`] to save).
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.values.insert(key.into(), value.into());
    }

    /// Removes a value.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.data.values.remove(key)
    }

    /// The authenticated user.
    pub fn user(&self) -> Option<&str> {
        self.data.user.as_deref()
    }

    /// When the session was created (Unix seconds).
    pub fn created_at(&self) -> u64 {
        self.data.created_at
    }

    /// The stored data.
    pub fn data(&self) -> &SessionData {
        &self.data
    }
}

/// Creates, loads, rotates and destroys sessions. Cheap to clone. See the
/// [module docs](self).
#[derive(Clone)]
pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    cookie: String,
    idle: Duration,
    absolute: Duration,
    secure: bool,
    same_site: SameSite,
}

impl fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManager")
            .field("cookie", &self.cookie)
            .field("idle", &self.idle)
            .field("absolute", &self.absolute)
            .finish_non_exhaustive()
    }
}

fn store_key(id: &str) -> String {
    hex_encode(&Sha256::digest(id.as_bytes()))
}

fn new_id() -> String {
    let mut raw = [0u8; ID_BYTES];
    secure_random(&mut raw);
    b64url(&raw)
}

impl SessionManager {
    /// Sessions in `store`, cookie `__Host-session`, 30 minutes idle timeout,
    /// 12 hours absolute timeout.
    pub fn new(store: Arc<dyn SessionStore>) -> Self {
        Self {
            store,
            cookie: String::from("__Host-session"),
            idle: Duration::from_secs(30 * 60),
            absolute: Duration::from_secs(12 * 3600),
            secure: true,
            same_site: SameSite::Lax,
        }
    }

    /// Name of the cookie (keep the `__Host-` prefix in production: it
    /// forbids `Domain` and requires `Secure` and `Path=/`).
    ///
    /// # Panics
    ///
    /// If the name is not a valid cookie name.
    pub fn cookie_name(mut self, name: &str) -> Self {
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.!#$%&'*+^`|~".contains(&b)),
            "invalid cookie name"
        );
        self.cookie = name.to_owned();
        self
    }

    /// Inactivity after which a session ends.
    pub fn idle_timeout(mut self, idle: Duration) -> Self {
        self.idle = idle.max(Duration::from_secs(1));
        self
    }

    /// Lifetime after which a session ends, even if active.
    pub fn absolute_timeout(mut self, absolute: Duration) -> Self {
        self.absolute = absolute.max(Duration::from_secs(1));
        self
    }

    /// `SameSite` of the cookie (default `Lax`).
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// For `http://localhost` only: no `Secure` attribute, and the
    /// `__Host-` prefix (which needs `Secure`) is dropped from the name.
    pub fn insecure_dev(mut self) -> Self {
        self.secure = false;
        if let Some(rest) = self.cookie.strip_prefix("__Host-") {
            self.cookie = rest.to_owned();
        }
        self
    }

    /// The name of the cookie.
    pub fn cookie(&self) -> &str {
        &self.cookie
    }

    /// A new, empty, anonymous session (not saved until
    /// [`commit`](Self::commit)).
    pub fn start(&self) -> Session {
        let now = now_unix();
        Session {
            id: new_id(),
            data: SessionData {
                created_at: now,
                last_seen: now,
                ..SessionData::default()
            },
        }
    }

    fn expired(&self, data: &SessionData, now: u64) -> bool {
        now.saturating_sub(data.last_seen) > self.idle.as_secs()
            || now.saturating_sub(data.created_at) > self.absolute.as_secs()
    }

    fn ttl(&self, data: &SessionData, now: u64) -> Duration {
        let absolute_left = data
            .created_at
            .saturating_add(self.absolute.as_secs())
            .saturating_sub(now);
        Duration::from_secs(absolute_left.min(self.idle.as_secs()).max(1))
    }

    /// The session of a request, from its cookie. Expired sessions are
    /// deleted; a valid one has its activity time refreshed.
    pub fn load(&self, headers: &HeaderMap) -> Option<Session> {
        self.load_at(headers, now_unix())
    }

    fn load_at(&self, headers: &HeaderMap, now: u64) -> Option<Session> {
        let id = headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(cookie_pairs)
            .filter(|(n, _)| *n == self.cookie)
            .map(|(_, v)| v)
            .find(|v| {
                v.len() == ID_CHARS
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })?;
        let key = store_key(id);
        let mut data = self.store.load(&key)?;
        if self.expired(&data, now) {
            self.store.delete(&key);
            return None;
        }
        data.last_seen = now;
        self.store.save(&key, &data, self.ttl(&data, now));
        Some(Session {
            id: id.to_owned(),
            data,
        })
    }

    /// Saves the session and returns its `Set-Cookie` header.
    pub fn commit(&self, session: &Session) -> HeaderValue {
        let now = now_unix();
        self.store.save(
            &store_key(&session.id),
            &session.data,
            self.ttl(&session.data, now),
        );
        self.cookie_header(&session.id, None)
    }

    fn cookie_header(&self, value: &str, max_age: Option<u64>) -> HeaderValue {
        let mut c = format!(
            "{}={}; Path=/; HttpOnly; SameSite={}",
            self.cookie,
            value,
            match self.same_site {
                SameSite::Strict => "Strict",
                SameSite::Lax => "Lax",
                SameSite::None => "None",
            }
        );
        if self.secure || self.same_site == SameSite::None {
            c.push_str("; Secure");
        }
        if let Some(age) = max_age {
            c.push_str(&format!("; Max-Age={age}"));
        }
        HeaderValue::from_str(&c).expect("cookie names and ids are valid header values")
    }

    /// Gives the session a new id, keeping its data; the old id is deleted
    /// from the store. Call it on every privilege change (anti session
    /// fixation), then [`commit`](Self::commit).
    pub fn regenerate(&self, session: &mut Session) {
        self.store.delete(&store_key(&session.id));
        session.id = new_id();
    }

    /// Logs `user` in: [`regenerate`](Self::regenerate)s the id and records
    /// the user. Then [`commit`](Self::commit).
    pub fn login(&self, session: &mut Session, user: &str) {
        self.regenerate(session);
        session.data.user = Some(user.to_owned());
    }

    /// Destroys the session and returns the headers of the logout response:
    /// an expired `Set-Cookie` and `Clear-Site-Data`.
    pub fn logout(&self, session: Session) -> Vec<(HeaderName, HeaderValue)> {
        self.store.delete(&store_key(&session.id));
        vec![
            (SET_COOKIE, self.cookie_header("", Some(0))),
            (
                HeaderName::from_static("clear-site-data"),
                HeaderValue::from_static(CLEAR_SITE_DATA_LOGOUT),
            ),
        ]
    }

    /// Destroys the session (server side) and returns the expired cookie,
    /// without `Clear-Site-Data` (e.g. when an account is deleted from an
    /// API response).
    pub fn destroy(&self, session: Session) -> HeaderValue {
        self.store.delete(&store_key(&session.id));
        self.cookie_header("", Some(0))
    }
}

/// Guard that loads the session of every request into the request
/// extensions (`req.extensions().get::<Session>()`). Requests without a
/// valid session simply have none.
#[derive(Clone, Debug)]
pub struct Sessions {
    manager: SessionManager,
}

impl Sessions {
    /// The guard for `manager`.
    pub fn new(manager: SessionManager) -> Self {
        Self { manager }
    }
}

impl Guard for Sessions {
    fn name(&self) -> &'static str {
        "sessions"
    }

    fn priority(&self) -> u16 {
        crate::priority::SESSIONS
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        if let Some(session) = self.manager.load(&req.headers) {
            if let Some(user) = session.user() {
                req.extensions.insert(crate::auth::Principal {
                    name: Arc::from(user),
                    scheme: "session",
                });
            }
            req.extensions.insert(session);
        }
        Ok(())
    }
}

impl_layer!(Sessions);

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> (SessionManager, Arc<MemorySessionStore>) {
        let store = Arc::new(MemorySessionStore::new(100));
        (SessionManager::new(store.clone()), store)
    }

    fn headers(set_cookie: &HeaderValue) -> HeaderMap {
        let pair = set_cookie.to_str().unwrap().split(';').next().unwrap();
        let mut h = HeaderMap::new();
        h.insert(COOKIE, pair.parse().unwrap());
        h
    }

    #[test]
    fn cookie_is_hardened() {
        let (m, _) = manager();
        let c = m.commit(&m.start());
        let c = c.to_str().unwrap();
        assert!(c.starts_with("__Host-session="));
        for attr in ["Path=/", "HttpOnly", "SameSite=Lax", "Secure"] {
            assert!(c.contains(attr), "{attr}");
        }
        assert!(!c.contains("Domain"));
        let dev = SessionManager::new(Arc::new(MemorySessionStore::new(1))).insecure_dev();
        let c = dev.commit(&dev.start());
        assert!(c.to_str().unwrap().starts_with("session="));
        assert!(!c.to_str().unwrap().contains("Secure"));
    }

    #[test]
    fn roundtrip_and_store_never_sees_ids() {
        let (m, store) = manager();
        let mut s = m.start();
        s.insert("k", "v");
        let c = m.commit(&s);
        let id = s.id.clone();
        assert!(
            store
                .map
                .lock()
                .unwrap()
                .keys()
                .all(|k| k.len() == 64 && *k != id)
        );
        let loaded = m.load(&headers(&c)).unwrap();
        assert_eq!(loaded.get("k"), Some("v"));
        assert!(!format!("{loaded:?}").contains(&id), "Debug hides the id");
    }

    #[test]
    fn forged_and_malformed_ids() {
        let (m, _) = manager();
        let mut h = HeaderMap::new();
        for bad in [
            "__Host-session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "__Host-session=short",
            "__Host-session=../../../../etc/passwd",
            "session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            h.insert(COOKIE, bad.parse().unwrap());
            assert!(m.load(&h).is_none(), "{bad}");
        }
    }

    #[test]
    fn login_rotates_the_id_against_fixation() {
        let (m, _) = manager();
        // The attacker plants a session id in the victim's browser.
        let planted = m.start();
        let planted_cookie = m.commit(&planted);
        // The victim logs in with it.
        let mut victim = m.load(&headers(&planted_cookie)).unwrap();
        m.login(&mut victim, "alice");
        let fresh = m.commit(&victim);
        assert_ne!(fresh, planted_cookie);
        // The planted id is dead, the new one carries the login.
        assert!(m.load(&headers(&planted_cookie)).is_none());
        assert_eq!(m.load(&headers(&fresh)).unwrap().user(), Some("alice"));
    }

    #[test]
    fn idle_and_absolute_timeouts() {
        let (m, _) = manager();
        let m = m
            .idle_timeout(Duration::from_secs(60))
            .absolute_timeout(Duration::from_secs(300));
        let s = m.start();
        let c = m.commit(&s);
        let h = headers(&c);
        let t0 = s.created_at();
        assert!(m.load_at(&h, t0 + 50).is_some());
        assert!(m.load_at(&h, t0 + 100).is_some(), "activity refreshed");
        assert!(m.load_at(&h, t0 + 200).is_none(), "idle > 60 s");
        let s = m.start();
        let h = headers(&m.commit(&s));
        let t0 = s.created_at();
        for t in (50..=300).step_by(50) {
            assert!(m.load_at(&h, t0 + t).is_some(), "{t}");
        }
        assert!(m.load_at(&h, t0 + 340).is_none(), "absolute > 300 s");
    }

    #[test]
    fn logout_destroys_and_clears() {
        let (m, store) = manager();
        let s = m.start();
        let c = m.commit(&s);
        let session = m.load(&headers(&c)).unwrap();
        let out = m.logout(session);
        assert!(store.is_empty());
        assert!(m.load(&headers(&c)).is_none());
        assert!(out[0].1.to_str().unwrap().contains("Max-Age=0"));
        assert_eq!(out[1].0, "clear-site-data");
    }

    #[test]
    fn bounded_store() {
        let store = MemorySessionStore::new(3);
        for i in 0..10 {
            store.save(
                &format!("k{i}"),
                &SessionData::default(),
                Duration::from_secs(i + 1),
            );
        }
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn guard_inserts_session_and_principal() {
        let (m, _) = manager();
        let mut s = m.start();
        m.login(&mut s, "bob");
        let c = m.commit(&s);
        let pair = c.to_str().unwrap().split(';').next().unwrap().to_owned();
        let mut p = http::Request::builder()
            .header("cookie", pair)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let mut ctx = Context::new(p.method.clone(), p.uri.clone(), None);
        Sessions::new(m).on_request(&mut p, &mut ctx).unwrap();
        assert_eq!(p.extensions.get::<Session>().unwrap().user(), Some("bob"));
        assert_eq!(
            &*p.extensions.get::<crate::auth::Principal>().unwrap().name,
            "bob"
        );
    }
}
