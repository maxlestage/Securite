//! Static files (`site/static`) and the browser bundle (`site/pkg`), read once at startup
//! and served from memory.

use std::collections::BTreeMap;
use std::path::Path;

pub struct Asset {
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
    /// Short content hash, used in `?v=` so that files can be cached forever.
    pub version: String,
}

#[derive(Default)]
pub struct Assets {
    files: BTreeMap<String, Asset>,
}

pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

/// 64-bit FNV-1a, enough to tell versions apart.
pub fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

impl Assets {
    /// Loads every file of `dir` (recursively) under the URL prefix `prefix`.
    pub fn load(&mut self, dir: &Path, prefix: &str) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                self.load(&path, &format!("{prefix}/{name}"));
            } else if let Ok(bytes) = std::fs::read(&path) {
                let version = format!("{:016x}", hash(&bytes))[..10].to_string();
                self.files.insert(
                    format!("{prefix}/{name}"),
                    Asset {
                        bytes,
                        content_type: content_type(&name),
                        version,
                    },
                );
            }
        }
    }

    pub fn get(&self, url: &str) -> Option<&Asset> {
        self.files.get(url)
    }

    /// The link to `url` behind `base`: `url?v=<hash>` for files that exist.
    pub fn url(&self, base: &str, url: &str) -> String {
        match self.files.get(url) {
            Some(asset) => format!("{base}{url}?v={}", asset.version),
            None => format!("{base}{url}"),
        }
    }

    /// Every file, with its URL, sorted by URL.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Asset)> {
        self.files.iter().map(|(url, asset)| (url.as_str(), asset))
    }
}
