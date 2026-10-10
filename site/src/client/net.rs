//! Calls to the playground API of `securite-server`.

use active::State;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use super::{every, now, window};
use crate::islands::{Outcome, Stats, parse_stats, pretty_json};

struct Reply {
    status: u16,
    json: bool,
    request_id: Option<String>,
    body: String,
}

async fn get(url: &str) -> Option<Reply> {
    let response: web_sys::Response = JsFuture::from(window().fetch_with_str(url))
        .await
        .ok()?
        .dyn_into()
        .ok()?;
    let headers = response.headers();
    let json = headers
        .get("content-type")
        .ok()
        .flatten()
        .is_some_and(|t| t.contains("json"));
    let request_id = headers.get("x-request-id").ok().flatten();
    let body = JsFuture::from(response.text().ok()?)
        .await
        .ok()?
        .as_string()
        .unwrap_or_default();
    Some(Reply {
        status: response.status(),
        json,
        request_id,
        body,
    })
}

/// `GET /api/demo?payload=…`: what the shield answered.
pub async fn demo(url: &str) -> Outcome {
    let started = now();
    match get(url).await {
        // Static hosting answers with an HTML page: there is no server to attack.
        Some(reply) if reply.json => Outcome::Done {
            status: reply.status,
            body: pretty_json(&reply.body),
            request_id: reply.request_id,
            ms: now() - started,
        },
        _ => Outcome::Offline,
    }
}

/// Loads `/api/stats` now and every 4 s; stops at the first failure.
pub fn poll_stats(base: &str, stats: State<Option<Stats>>) {
    let url = format!("{base}/api/stats");
    let stopped = std::rc::Rc::new(std::cell::Cell::new(false));
    let load = move || {
        if stopped.get() || !window().navigator().on_line() {
            return;
        }
        let (url, stopped) = (url.clone(), stopped.clone());
        wasm_bindgen_futures::spawn_local(async move {
            match get(&url).await.filter(|r| r.json && r.status == 200) {
                Some(reply) => {
                    let next = parse_stats(&reply.body);
                    if stats.get() != next {
                        stats.set(next);
                    }
                }
                None => stopped.set(true),
            }
        });
    };
    load();
    every(4000, load);
}
