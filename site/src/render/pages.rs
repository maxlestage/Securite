//! Every page of the site, written with active: server-rendered HTML with complete SEO
//! tags, islands where the page is interactive.

use active::Str;
use active::prelude::*;

use super::{AUTHOR, CRATES_IO, DOCS_RS, ECOSYSTEM, LICENSE_PATH, Site};
use crate::docs::{self, CATEGORY_ORDER, category_icon};
use crate::i18n::{Lang, Texts};
use crate::icons::icon;
use crate::islands::{
    self, code_tabs, copy_button, docs_hub, features, lab, live_stats, typewriter,
};
use crate::routes::{Page, Route, doc_href};

/// What a request needs to render a page.
pub struct Ctx<'a> {
    pub site: &'a Site,
    pub route: &'a Route,
    /// Public address with the base path, for canonical and Open Graph URLs.
    pub public: &'a str,
}

impl Ctx<'_> {
    fn base(&self) -> &str {
        &self.site.base
    }

    fn lang(&self) -> Lang {
        self.route.lang
    }

    fn t(&self) -> &'static Texts {
        self.route.lang.t()
    }

    fn href(&self, page: Page) -> String {
        Route::new(self.lang(), page).href(self.base())
    }

    fn doc(&self, slug: &str) -> String {
        doc_href(self.base(), self.lang(), slug)
    }
}

const STACK: &[&str] = &[
    "Vitesse",
    "hyper",
    "tonic",
    "tower",
    "Loco",
    "Leptos",
    "Dioxus",
    "Poem",
    "Salvo",
    "Heroku",
    "Docker",
    "Fly.io",
    "Cloudflare",
    "Kubernetes",
    "tokio",
];

const PIPELINE: [(&str, &str); 6] = [
    ("ban", "Auto-ban"),
    ("filter", "Hygiene"),
    ("gauge", "Rate limit"),
    ("bug", "WAF"),
    ("shield", "CSRF"),
    ("layers", "Headers"),
];

fn external(href: impl Into<Str>) -> Element {
    a().href(href)
        .attr("target", "_blank")
        .attr("rel", "noopener noreferrer")
}

fn brand(href: String) -> Element {
    a().href(href)
        .class("brand")
        .child(span().class("brand-mark").child(icon("shield-check", 22)))
        .child(span().class("brand-name").text("securite"))
}

/// The same page in `lang` (the home page for a missing page).
fn translated(route: &Route, lang: Lang) -> Route {
    match route.page {
        Page::NotFound => Route::new(lang, Page::Home),
        _ => route.with_lang(lang),
    }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

fn lang_switch(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    div()
        .class("lang-switch")
        .child(
            button()
                .class("lang-btn")
                .attr("type", "button")
                .attr("aria-label", t.language)
                .attr("aria-expanded", "false")
                .attr("aria-haspopup", "true")
                .child(icon("language", 18))
                .child(span().text(ctx.lang().code().to_uppercase()))
                .child(icon("chevron-down", 14).class("chev")),
        )
        .child(ul().class("lang-menu").children(Lang::ALL.map(|l| {
            li().child(
                a().href(translated(ctx.route, l).href(ctx.base()))
                    .class(if l == ctx.lang() { "active" } else { "" })
                    .attr("hreflang", l.code())
                    .attr("lang", l.code())
                    .child(span().class("lang-code").text(l.code().to_uppercase()))
                    .text(l.label()),
            )
        })))
}

fn navbar(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    let home = ctx.href(Page::Home);
    let page = &ctx.route.page;
    let link = |href: String, label: &'static str, active: bool| {
        let link = a().href(href).class("nav-link").text(label);
        if active {
            link.class("active").attr("aria-current", "page")
        } else {
            link
        }
    };
    header().class("navbar").child(
        nav()
            .class("nav-inner container")
            .attr("aria-label", "Main")
            .child(brand(home.clone()))
            .child(
                div()
                    .class("nav-links")
                    .child(link(home.clone(), t.nav_home, *page == Page::Home))
                    .child(link(format!("{home}#features"), t.nav_features, false))
                    .child(link(
                        ctx.href(Page::Docs),
                        t.nav_docs,
                        matches!(page, Page::Docs | Page::Doc(_)),
                    ))
                    .child(link(
                        ctx.href(Page::Playground),
                        t.nav_playground,
                        *page == Page::Playground,
                    ))
                    .child(link(format!("{home}#deploy"), t.nav_deploy, false)),
            )
            .child(
                div()
                    .class("nav-actions")
                    .child(lang_switch(ctx))
                    .child(
                        a().href(ctx.doc("quick-start"))
                            .class("btn btn-primary btn-sm nav-cta")
                            .text(t.get_started),
                    )
                    .child(
                        button()
                            .class("icon-btn burger")
                            .attr("type", "button")
                            .attr("aria-label", t.menu)
                            .attr("aria-expanded", "false")
                            .child(icon("menu", 20).class("i-menu"))
                            .child(icon("x", 20).class("i-x")),
                    ),
            ),
    )
}

/// The current year (UTC), for the copyright line.
fn current_year() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = i64::try_from(secs / 86_400).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    yoe + era * 400 + i64::from(month <= 2)
}

/// The signature footer, shared in spirit by every site of the ecosystem: the call to
/// action and the install command, the link columns, the sister projects, the author's
/// signature, the giant wordmark and the legal line.
fn footer_(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    let doc = |slug: &str, label: &'static str| li().child(a().href(ctx.doc(slug)).text(label));
    let ext = |href: String, label: &'static str| li().child(external(href).text(label));
    let cta = div()
        .class("container footer-cta")
        .child(
            a().class("footer-cta-link")
                .href(ctx.doc("quick-start"))
                .child(span().text(t.footer_start))
                .child(Node::from(" "))
                .child(em().text("Securite"))
                .child(icon("arrow-right", 28)),
        )
        .child(install_box(t).attr(
            "aria-label",
            format!(
                "{}: cargo add securite --git https://github.com/maxlestage/Securite",
                t.footer_install
            ),
        ));
    let brand_column = div()
        .class("footer-brand")
        .child(brand(ctx.href(Page::Home)))
        .child(p().class("muted").text(t.footer_tagline))
        .child(
            ul().class("footer-badges")
                .attr("aria-label", "Securite")
                .child(
                    li().class("chip chip-ok")
                        .text(format!("v{}", securite::VERSION)),
                )
                .child(li().class("chip").text(t.footer_rust))
                .child(li().class("chip").child(external(CRATES_IO).text("GitHub"))),
        )
        .child(
            div()
                .class("footer-langs")
                .attr("role", "group")
                .attr("aria-label", t.language)
                .children(Lang::ALL.map(|l| {
                    a().href(translated(ctx.route, l).href(ctx.base()))
                        .class("chip")
                        .class(if l == ctx.lang() { "active" } else { "" })
                        .attr("hreflang", l.code())
                        .attr("lang", l.code())
                        .text(l.label())
                })),
        )
        .child(
            div()
                .class("socials")
                .child(
                    external(CRATES_IO)
                        .class("icon-btn")
                        .attr("aria-label", "GitHub")
                        .child(icon("github", 20)),
                )
                .child(
                    external(DOCS_RS)
                        .class("icon-btn")
                        .attr("aria-label", "docs.rs")
                        .child(icon("book", 20)),
                ),
        );
    let ecosystem =
        nav()
            .class("container footer-eco")
            .attr("aria-label", t.footer_ecosystem)
            .child(
                div()
                    .class("footer-eco-head")
                    .child(h4().text(t.footer_ecosystem))
                    .child(p().class("muted").text(t.footer_ecosystem_text)),
            )
            .child(
                ul().class("eco-grid")
                    .children(ECOSYSTEM.iter().zip(t.footer_projects).map(
                        |((name, url), text)| {
                            let here = *name == "Securite";
                            let mut title = span().class("eco-name").text(*name);
                            if here {
                                title = title.child(span().class("eco-here").text(t.footer_here));
                            }
                            let link = if here {
                                a().href(*url).attr("aria-current", "page")
                            } else {
                                external(*url)
                            };
                            li().child(
                                link.class(if here { "eco current" } else { "eco" })
                                    .child(title)
                                    .child(span().class("eco-text").text(text))
                                    .child(icon("arrow-right", 18)),
                            )
                        },
                    )),
            );
    let credits = div()
        .class("container footer-credits reveal")
        .child(p().class("credits-by").text(t.footer_by))
        .child(
            p().class("credits-name").children(
                AUTHOR
                    .split(' ')
                    .enumerate()
                    .map(|(i, word)| span().style(format!("--i:{i}")).text(word.to_string())),
            ),
        )
        .child(p().class("credits-note").text(t.footer_crafted));
    let wordmark = div()
        .class("wordmark")
        .attr("aria-hidden", "true")
        .children(
            "Securite"
                .chars()
                .enumerate()
                .map(|(i, c)| span().style(format!("--i:{i}")).text(c.to_string())),
        );
    footer()
        .class("footer")
        .child(div().class("footer-glow").attr("aria-hidden", "true"))
        .child(cta)
        .child(
            div()
                .class("container footer-grid")
                .child(brand_column)
                .child(
                    div().child(h4().text(t.footer_product)).child(
                        ul().child(li().child(a().href(ctx.href(Page::Home)).text(t.nav_home)))
                            .child(
                                li().child(
                                    a().href(ctx.href(Page::Playground)).text(t.nav_playground),
                                ),
                            )
                            .child(doc("waf", "WAF"))
                            .child(doc("rate-limit", "Rate limiting"))
                            .child(doc("security-headers", "Security headers")),
                    ),
                )
                .child(
                    div().child(h4().text(t.footer_docs)).child(
                        ul().child(doc("introduction", "Introduction"))
                            .child(doc("quick-start", "Quick start"))
                            .child(doc("shield-presets", "Presets"))
                            .child(doc("custom-guards", "Custom guards"))
                            .child(li().child(a().href(ctx.href(Page::Docs)).text(t.docs_back))),
                    ),
                )
                .child(
                    div().child(h4().text(t.footer_resources)).child(
                        ul().child(ext(CRATES_IO.into(), "GitHub"))
                            .child(ext(DOCS_RS.into(), "docs.rs"))
                            .child(doc("heroku-from-phone", "Heroku"))
                            .child(doc("github-pages", "GitHub Pages"))
                            .child(ext(
                                format!("{}{LICENSE_PATH}", ctx.base()),
                                t.footer_license,
                            )),
                    ),
                ),
        )
        .child(ecosystem)
        .child(credits)
        .child(wordmark)
        .child(
            div()
                .class("container footer-bottom")
                .child(span().text(format!("© {} {}", current_year(), t.footer_rights)))
                .child(external(format!("{}{LICENSE_PATH}", ctx.base())).text(t.footer_proprietary))
                .child(
                    span()
                        .class("made")
                        .text(format!("{} · ", t.footer_made))
                        .child(span().class("rust").text("🦀")),
                ),
        )
}

// ---------------------------------------------------------------------------
// Home page
// ---------------------------------------------------------------------------

fn install_box(t: &'static Texts) -> Element {
    div()
        .class("install-box")
        .child(span().class("prompt").text("$"))
        .child(code().text("cargo add securite --git https://github.com/maxlestage/Securite"))
        .child(copy_button(
            "cargo add securite --git https://github.com/maxlestage/Securite",
            t,
            false,
        ))
}

fn section_head(kicker: &'static str, title: &'static str, subtitle: &'static str) -> Element {
    div()
        .class("section-head reveal")
        .child(p().class("kicker").text(kicker))
        .child(h2().text(title))
        .child(p().class("muted").text(subtitle))
}

fn blob(n: u8) -> Element {
    div()
        .class(format!("blob b{n}"))
        .attr("aria-hidden", "true")
}

fn hero(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    section()
        .class("hero")
        .child(canvas().class("particles").attr("aria-hidden", "true"))
        .child(blob(1))
        .child(blob(2))
        .child(blob(3))
        .child(
            div()
                .class("container hero-inner")
                .child(
                    a().href(ctx.doc("introduction"))
                        .class("badge shine")
                        .child(icon("sparkles", 16))
                        .child(span().text(t.hero_badge))
                        .child(icon("arrow-right", 14)),
                )
                .child(
                    h1().class("hero-title")
                        .child(span().class("line").text(t.hero_title))
                        .child(
                            span()
                                .class("line small")
                                .text(format!("{} ", t.hero_against))
                                .child(island("typewriter", ctx.lang().code(), typewriter)),
                        ),
                )
                .child(p().class("hero-sub").text(t.hero_subtitle))
                .child(
                    div()
                        .class("hero-ctas")
                        .child(
                            a().href(ctx.doc("quick-start"))
                                .class("btn btn-primary btn-lg magnetic")
                                .text(t.hero_cta_primary)
                                .child(icon("arrow-right", 18)),
                        )
                        .child(
                            a().href(ctx.href(Page::Playground))
                                .class("btn btn-ghost btn-lg")
                                .child(icon("bug", 18))
                                .text(t.hero_cta_secondary),
                        ),
                )
                .child(install_box(t)),
        )
        .child(
            div()
                .class("scroll-hint")
                .attr("aria-hidden", "true")
                .child(span()),
        )
}

fn marquee(t: &'static Texts) -> Element {
    let items = || {
        STACK.iter().map(|s| {
            span()
                .class("marquee-item")
                .child(icon("check", 16))
                .text(*s)
        })
    };
    section()
        .class("marquee-section")
        .child(p().class("kicker center").text(t.marquee_title))
        .child(
            div().class("marquee").attr("aria-hidden", "true").child(
                div()
                    .class("marquee-track")
                    .children(items())
                    .children(items()),
            ),
        )
}

/// A number that counts up when it scrolls into view (page motion). The server writes the
/// final value.
fn counter(to: u32, suffix: &'static str) -> Element {
    span()
        .class("counter")
        .attr("data-count", to.to_string())
        .attr("data-suffix", suffix)
        .text(format!("{to}{suffix}"))
}

fn stats(t: &'static Texts) -> Element {
    let stat = |delay: &str, value: Element, label: &'static str| {
        div()
            .class(format!("stat reveal {delay}"))
            .child(value)
            .child(span().text(label))
    };
    section()
        .class("container stats")
        .child(stat(
            "",
            strong().child(counter(19, "")),
            t.stat_middlewares,
        ))
        .child(stat(
            "d1",
            strong().text("≈ ").child(counter(6, " µs")),
            t.stat_overhead,
        ))
        .child(stat(
            "d2",
            strong().child(counter(400, "+")),
            t.stat_signatures,
        ))
        .child(stat("d3", strong().child(counter(0, "")), t.stat_unsafe))
        .child(stat("d4", strong().child(counter(3, "")), t.stat_languages))
}

fn features_section(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    section()
        .id("features")
        .class("section container")
        .child(section_head(
            t.features_kicker,
            t.features_title,
            t.features_subtitle,
        ))
        .child(island(
            "features",
            islands::props(ctx.lang(), ctx.base()),
            features,
        ))
}

fn pipeline(t: &'static Texts) -> Element {
    div()
        .class("pipeline reveal")
        .child(
            div()
                .class("pipe-end client")
                .child(icon("globe", 26))
                .child(span().text(t.pipeline_client)),
        )
        .child(
            div()
                .class("pipe-track")
                .child(div().class("pipe-line").attr("aria-hidden", "true"))
                .children((0..4).map(|i| {
                    span()
                        .class(format!("packet ok d{i}"))
                        .attr("aria-hidden", "true")
                }))
                .children((0..3).map(|i| {
                    span()
                        .class(format!("packet bad d{i}"))
                        .attr("aria-hidden", "true")
                }))
                .child(
                    div()
                        .class("pipe-nodes")
                        .children(PIPELINE.map(|(name, label)| {
                            div()
                                .class("pipe-node")
                                .class(if label == "WAF" { "waf" } else { "" })
                                .child(span().class("node-icon").child(icon(name, 20)))
                                .child(span().class("node-label").text(label))
                        })),
                ),
        )
        .child(
            div()
                .class("pipe-end app")
                .child(icon("server", 26))
                .child(span().text(t.pipeline_app)),
        )
        .child(
            div()
                .class("pipe-legend")
                .child(span().child(i().class("dot ok")).text(t.pipeline_legit))
                .child(span().child(i().class("dot bad")).text(t.pipeline_attack)),
        )
}

fn how_it_works(t: &'static Texts) -> Element {
    section()
        .class("section container")
        .child(section_head(
            t.pipeline_kicker,
            t.pipeline_title,
            t.pipeline_subtitle,
        ))
        .child(pipeline(t))
        .child(
            div()
                .class("principles")
                .children(t.principles.iter().enumerate().map(|(i, step)| {
                    div()
                        .class(format!("principle reveal d{i}"))
                        .child(span().class("principle-num").text(format!("0{}", i + 1)))
                        .child(h3().text(step.title))
                        .child(p().text(step.text))
                })),
        )
}

fn code_showcase(ctx: &Ctx<'_>) -> Element {
    section()
        .class("section container code-section")
        .child(island(
            "code-tabs",
            islands::props(ctx.lang(), ctx.base()),
            code_tabs,
        ))
}

fn playground_teaser(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    let live = ctx.site.live;
    section()
        .id("playground")
        .class("section container")
        .child(section_head(t.play_kicker, t.play_title, t.play_subtitle))
        .child(div().class("reveal").child(island(
            "lab",
            islands::lab_props(ctx.lang(), ctx.base(), true, live),
            lab,
        )))
        .child(
            div()
                .class("reveal center-row")
                .child(island(
                    "live-stats",
                    islands::stats_props(ctx.lang(), ctx.base(), live),
                    live_stats,
                ))
                .child(
                    a().href(ctx.href(Page::Playground))
                        .class("btn btn-ghost")
                        .text(t.play_open)
                        .child(icon("arrow-right", 16)),
                ),
        )
}

fn benchmarks(t: &'static Texts) -> Element {
    // Measured with `cargo bench -p securite` (criterion), see benches/shield.rs.
    let rows: [(&str, &str, f64); 4] = [
        (t.bench_items[0], "6.1 µs", 100.0),
        (t.bench_items[1], "1.9 µs", 31.0),
        (t.bench_items[2], "0.68 µs", 11.0),
        (t.bench_items[3], "3.4 ns", 1.5),
    ];
    section()
        .class("section container bench")
        .child(section_head(
            t.bench_kicker,
            t.bench_title,
            t.bench_subtitle,
        ))
        .child(
            div()
                .class("bench-list")
                .children(rows.iter().enumerate().map(|(i, (label, value, pct))| {
                    div()
                        .class(format!("bench-row reveal d{i}"))
                        .child(
                            div()
                                .class("bench-label")
                                .child(span().text(*label))
                                .child(strong().text(*value)),
                        )
                        .child(
                            div()
                                .class("bench-bar")
                                .child(span().style(format!("--w:{pct}%"))),
                        )
                })),
        )
        .child(p().class("bench-note muted reveal").text(t.bench_note))
}

fn deploy(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    section()
        .id("deploy")
        .class("section container deploy")
        .child(
            div()
                .class("deploy-card reveal")
                .child(
                    div()
                        .class("deploy-copy")
                        .child(
                            p().class("kicker")
                                .child(icon("smartphone", 16))
                                .text(format!(" {}", t.deploy_kicker)),
                        )
                        .child(h2().text(t.deploy_title))
                        .child(p().class("muted").text(t.deploy_subtitle))
                        .child(
                            div().class("hero-ctas").child(
                                a().href(ctx.doc("heroku-from-phone"))
                                    .class("btn btn-primary btn-lg")
                                    .text(t.deploy_guide)
                                    .child(icon("arrow-right", 18)),
                            ),
                        ),
                )
                .child(
                    ol().class("timeline")
                        .children(t.deploy_steps.iter().enumerate().map(|(i, step)| {
                            li().class(format!("reveal d{i}"))
                                .child(span().class("step-num").text((i + 1).to_string()))
                                .child(
                                    div()
                                        .child(h3().text(step.title))
                                        .child(p().text(step.text)),
                                )
                        })),
                )
                .child(
                    div()
                        .class("phone")
                        .attr("aria-hidden", "true")
                        .child(div().class("phone-notch"))
                        .child(
                            div()
                                .class("phone-screen")
                                .child(div().class("phone-line w70"))
                                .child(div().class("phone-line w40"))
                                .child(div().class("phone-btn").text("Deploy"))
                                .child(div().class("phone-progress").child(span()))
                                .child(div().class("phone-ok").child(icon("check", 28))),
                        ),
                ),
        )
}

fn final_cta(ctx: &Ctx<'_>) -> Element {
    let t = ctx.t();
    section().class("section container").child(
        div()
            .class("cta reveal")
            .child(div().class("cta-border").attr("aria-hidden", "true"))
            .child(h2().text(t.cta_title))
            .child(p().class("muted").text(t.cta_subtitle))
            .child(install_box(t))
            .child(
                div().class("hero-ctas").child(
                    a().href(ctx.href(Page::Docs))
                        .class("btn btn-primary btn-lg")
                        .child(icon("book", 18))
                        .text(t.nav_docs),
                ),
            ),
    )
}

fn home(ctx: &Ctx<'_>) -> Node {
    let t = ctx.t();
    fragment([
        hero(ctx),
        marquee(t),
        stats(t),
        features_section(ctx),
        how_it_works(t),
        code_showcase(ctx),
        playground_teaser(ctx),
        benchmarks(t),
        deploy(ctx),
        final_cta(ctx),
    ])
}

// ---------------------------------------------------------------------------
// Documentation
// ---------------------------------------------------------------------------

fn docs_index(ctx: &Ctx<'_>) -> Node {
    let pages = docs::pages(ctx.lang());
    let props = islands::docs_hub_props(
        ctx.lang(),
        ctx.base(),
        pages
            .iter()
            .map(|d| [d.slug, d.category, d.title, d.summary, d.search]),
    );
    island("docs-hub", props, docs_hub)
}

fn category_name(t: &'static Texts, id: &'static str) -> &'static str {
    t.categories
        .iter()
        .find(|c| c.id == id)
        .map_or(id, |c| c.name)
}

fn doc_page(ctx: &Ctx<'_>, page: &'static docs::DocPage, translated: bool) -> Node {
    let (t, lang) = (ctx.t(), ctx.lang());
    let pages = docs::pages(lang);
    let idx = pages.iter().position(|p| p.slug == page.slug);
    let prev = idx
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| pages.get(i));
    let next = idx.and_then(|i| pages.get(i + 1));

    let groups = CATEGORY_ORDER.iter().filter_map(|cat| {
        let items: Vec<_> = pages.iter().filter(|p| p.category == *cat).collect();
        if items.is_empty() {
            return None;
        }
        Some(
            div()
                .class("side-group")
                .child(
                    p().class("side-title")
                        .child(icon(category_icon(cat), 15))
                        .text(category_name(t, cat)),
                )
                .child(ul().children(items.into_iter().map(|p| {
                    let link = a().href(ctx.doc(p.slug)).class("side-link").text(p.title);
                    li().child(if p.slug == page.slug {
                        link.class("active").attr("aria-current", "page")
                    } else {
                        link
                    })
                }))),
        )
    });

    let toc = (!page.toc.is_empty()).then(|| {
        fragment([
            Node::from(p().class("side-title").text(t.docs_on_page)),
            ul().children(page.toc.iter().map(|(id, text, level)| {
                li().class(format!("lvl{level}"))
                    .child(a().href(format!("#{id}")).text(*text))
            }))
            .into(),
        ])
    });

    div()
        .class("doc-layout container")
        .child(
            aside()
                .class("doc-sidebar")
                .child(
                    button()
                        .class("side-toggle")
                        .attr("type", "button")
                        .attr("aria-expanded", "false")
                        .child(icon("menu", 18))
                        .text(t.nav_docs)
                        .child(icon("chevron-down", 16).class("chev")),
                )
                .child(
                    nav()
                        .class("side-nav")
                        .attr("aria-label", t.nav_docs)
                        .child(
                            a().href(ctx.href(Page::Docs))
                                .class("side-back")
                                .child(icon("arrow-left", 15))
                                .text(t.docs_back),
                        )
                        .children(groups),
                ),
        )
        .child(
            article()
                .class("doc-article")
                .child(
                    div()
                        .class("breadcrumbs")
                        .child(a().href(ctx.href(Page::Docs)).text(t.nav_docs))
                        .child(span().text("/"))
                        .child(span().text(category_name(t, page.category))),
                )
                .child(
                    header()
                        .class("doc-header")
                        .child(h1().text(page.title))
                        .child(p().class("lead muted").text(page.summary))
                        .child(
                            (!translated)
                                .then(|| p().class("callout warn small").text(t.docs_missing)),
                        ),
                )
                .child(
                    div()
                        .class("prose")
                        .html(docs::body(page, ctx.base(), lang)),
                )
                .child(
                    nav()
                        .class("prev-next")
                        .child(match prev {
                            Some(p) => a()
                                .href(ctx.doc(p.slug))
                                .class("pn prev")
                                .child(
                                    span()
                                        .class("muted small")
                                        .child(icon("arrow-left", 14))
                                        .text(t.docs_prev),
                                )
                                .child(strong().text(p.title)),
                            None => span(),
                        })
                        .child(next.map(|n| {
                            a().href(ctx.doc(n.slug))
                                .class("pn next")
                                .child(
                                    span()
                                        .class("muted small")
                                        .text(t.docs_next)
                                        .child(icon("arrow-right", 14)),
                                )
                                .child(strong().text(n.title))
                        })),
                ),
        )
        .child(aside().class("doc-toc").child(toc))
        .into()
}

// ---------------------------------------------------------------------------
// Playground and 404
// ---------------------------------------------------------------------------

fn playground(ctx: &Ctx<'_>) -> Node {
    let t = ctx.t();
    let live = ctx.site.live;
    div()
        .class("playground-page")
        .child(
            section()
                .class("page-hero container")
                .child(blob(2))
                .child(p().class("kicker").text(t.play_kicker))
                .child(h1().text(t.play_title))
                .child(p().class("muted lead").text(t.play_subtitle)),
        )
        .child(
            section()
                .class("container section-tight")
                .child(div().class("reveal").child(island(
                    "lab",
                    islands::lab_props(ctx.lang(), ctx.base(), false, live),
                    lab,
                )))
                .child(div().class("reveal center-row").child(island(
                    "live-stats",
                    islands::stats_props(ctx.lang(), ctx.base(), live),
                    live_stats,
                ))),
        )
        .into()
}

fn not_found(ctx: &Ctx<'_>) -> Node {
    let t = ctx.t();
    section()
        .class("not-found container")
        .child(
            div()
                .class("nf-code glitch")
                .attr("data-text", "404")
                .text("404"),
        )
        .child(h1().text(t.nf_title))
        .child(p().class("muted").text(t.nf_text))
        .child(
            a().href(ctx.href(Page::Home))
                .class("btn btn-primary")
                .child(icon("arrow-left", 18))
                .text(t.nf_back),
        )
        .into()
}

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

/// A JSON string literal (JSON-LD).
fn json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The SEO tags of the page.
fn seo(ctx: &Ctx<'_>) -> Seo {
    let (t, lang, route) = (ctx.t(), ctx.lang(), ctx.route);
    let base = Seo::new()
        .site_name("Securite")
        .title_template("%s · securite")
        .base_url(ctx.public)
        .locale(lang.locale())
        .meta_name("author", AUTHOR);
    if route.page == Page::NotFound {
        return base.title(t.nf_title).description(t.nf_text).noindex(true);
    }
    let base = Lang::ALL
        .into_iter()
        .fold(base, |seo, l| {
            seo.alternate(l.code(), route.with_lang(l).path())
        })
        .alternate("x-default", route.with_lang(Lang::En).path())
        .canonical(route.path());
    let url = format!("{}{}", ctx.public, route.path());
    match &route.page {
        Page::Home => base
            .title(t.site_title)
            .title_template("securite · %s")
            .description(t.site_description)
            .json_ld(format!(
                r#"{{"@context":"https://schema.org","@type":"SoftwareSourceCode","name":"Securite","description":{},"url":{},"programmingLanguage":"Rust","license":"{}{LICENSE_PATH}","author":{{"@type":"Person","name":"{AUTHOR}"}},"inLanguage":"{}"}}"#,
                json(t.site_description),
                json(&url),
                ctx.public,
                lang.code()
            )),
        Page::Docs => base.title(t.nav_docs).description(t.docs_subtitle),
        Page::Doc(slug) => match docs::find(lang, slug) {
            Some((page, _)) => base
                .title(page.title)
                .description(page.summary)
                .og_type("article")
                .json_ld(format!(
                    r#"{{"@context":"https://schema.org","@type":"TechArticle","headline":{},"description":{},"url":{},"inLanguage":"{}","isPartOf":{{"@type":"WebSite","name":"Securite"}}}}"#,
                    json(page.title),
                    json(page.summary),
                    json(&url),
                    lang.code()
                ))
                .json_ld(format!(
                    r#"{{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{{"@type":"ListItem","position":1,"name":{},"item":{}}},{{"@type":"ListItem","position":2,"name":{},"item":{}}}]}}"#,
                    json(t.nav_docs),
                    json(&format!("{}{}", ctx.public, Route::new(lang, Page::Docs).path())),
                    json(page.title),
                    json(&url)
                )),
            None => base,
        },
        Page::Playground => base.title(t.nav_playground).description(t.play_subtitle),
        Page::NotFound => base,
    }
}

/// The whole HTML page of `ctx.route`.
pub fn render(ctx: &Ctx<'_>) -> String {
    let t = ctx.t();
    let content = match &ctx.route.page {
        Page::Home => home(ctx),
        Page::Docs => docs_index(ctx),
        Page::Doc(slug) => match docs::find(ctx.lang(), slug) {
            Some((page, translated)) => doc_page(ctx, page, translated),
            None => not_found(ctx),
        },
        Page::Playground => playground(ctx),
        Page::NotFound => not_found(ctx),
    };
    let body = fragment([
        Node::from(div().class("scroll-progress").attr("aria-hidden", "true")),
        div()
            .class("cursor-glow")
            .attr("aria-hidden", "true")
            .into(),
        div().class("bg-grid").attr("aria-hidden", "true").into(),
        a().class("skip-link").href("#main").text(t.skip).into(),
        navbar(ctx).into(),
        main().id("main").class("page-enter").child(content).into(),
        footer_(ctx).into(),
        button()
            .class("back-to-top")
            .attr("type", "button")
            .attr("aria-label", t.back_to_top)
            .child(icon("arrow-up", 20))
            .into(),
    ]);
    document(ctx.site, ctx.lang(), seo(ctx), body)
}

/// The document around `body`: style sheet, icons, manifest, service worker, browser
/// bundle.
fn document(site: &Site, lang: Lang, seo: Seo, body: Node) -> String {
    let base = &site.base;
    let assets = &site.assets;
    let mut doc = Document::new(body)
        .lang(lang.code())
        .seo(seo)
        .stylesheet(assets.url(base, "/static/main.css"))
        .head(format!(
            r#"<meta name="color-scheme" content="dark"/><link rel="icon" href="{}" type="image/svg+xml"/>"#,
            assets.url(base, "/static/favicon.svg")
        ))
        .manifest(&format!("{base}/manifest.webmanifest"), &site.manifest())
        .service_worker(&format!("{base}/sw.js"));
    if site.has_bundle() {
        doc = doc.client(
            assets.url(base, "/pkg/securite_site.js"),
            assets.url(base, "/pkg/securite_site_bg.wasm"),
        );
    }
    doc.render()
}

/// The root page of a static copy (no `Accept-Language` there): links to the three
/// languages, and English after a moment.
/// A JavaScript string literal that cannot close a `<script>` element.
fn js_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\u003c"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The script of the pages a static host serves without knowing the visitor's language: goes
/// to `/{lang}/{target}` for the language of the address (`/fr/…` on a missing page), else the
/// browser's, else English. Without JavaScript, a `<meta>` refresh goes to English.
fn language_redirect(base: &str, target: &str) -> String {
    let codes: Vec<String> = Lang::ALL.iter().map(|l| js_string(l.code())).collect();
    format!(
        concat!(
            "<script>(function(){{var b={base},L=[{codes}],c=null;",
            "var s=location.pathname.slice(b.length).split('/').filter(Boolean)[0];",
            "if(L.indexOf(s)>=0)c=s;",
            "var l=navigator.languages||[navigator.language||''];",
            "for(var i=0;i<l.length&&!c;i++){{var x=String(l[i]).slice(0,2).toLowerCase();",
            "if(L.indexOf(x)>=0)c=x}}",
            "location.replace(b+'/'+(c||'en')+'/'+{target}+location.search+location.hash)}})()</script>",
        ),
        base = js_string(base),
        codes = codes.join(","),
        target = js_string(target),
    )
}

/// The page a static host serves at `/` (`target` empty) and for a missing address (`target`
/// = `404/`): it goes to the visitor's language by itself, and links the languages.
pub fn language_picker(site: &Site, public: &str, target: &str) -> String {
    let base = &site.base;
    let seo = Seo::new()
        .title("Securite")
        .description(Lang::En.t().site_description)
        .base_url(public)
        .canonical(format!("/en/{target}"))
        .noindex(true);
    let body = main()
        .id("main")
        .class("not-found container")
        .child(div().class("nf-code").child(icon("shield-check", 64)))
        .child(h1().text("Securite"))
        .child(div().class("hero-ctas").children(Lang::ALL.map(|l| {
            a().href(format!("{base}/{}/{target}", l.code()))
                .class("btn btn-ghost btn-lg")
                .attr("hreflang", l.code())
                .attr("lang", l.code())
                .text(l.label())
        })));
    Document::new(body)
        .lang("en")
        .seo(seo)
        .stylesheet(site.assets.url(base, "/static/main.css"))
        .head(format!(
            r#"{}<noscript><meta http-equiv="refresh" content="0; url={base}/en/{target}"/></noscript><link rel="icon" href="{}" type="image/svg+xml"/>"#,
            language_redirect(base, target),
            site.assets.url(base, "/static/favicon.svg")
        ))
        .manifest(&format!("{base}/manifest.webmanifest"), &site.manifest())
        .render()
}

#[cfg(test)]
mod tests {
    use super::super::site_dir;
    use super::*;

    fn site(base: &str, live: bool) -> Site {
        Site::load(&site_dir(), base, None, live)
    }

    fn page(site: &Site, path: &str) -> String {
        let route = site.route(path).unwrap();
        site.page(&route, &format!("https://example.com{}", site.base))
    }

    #[test]
    fn home_pages_have_complete_seo_in_their_language() {
        let site = site("", true);
        let fr = page(&site, "/fr/");
        assert!(fr.starts_with(r#"<!DOCTYPE html><html lang="fr">"#));
        assert!(fr.contains("<title>securite · Middlewares de sécurité pour Rust</title>"));
        assert!(fr.contains(r#"<link rel="canonical" href="https://example.com/fr/"/>"#));
        assert!(fr.contains(r#"hreflang="es" href="https://example.com/es/""#));
        assert!(fr.contains(r#"hreflang="x-default" href="https://example.com/en/""#));
        assert!(fr.contains(r#"<meta property="og:locale" content="fr_FR"/>"#));
        assert!(fr.contains("application/ld+json"));
        assert!(fr.contains("Blindez vos API Rust"));
        assert!(fr.contains(r#"<link rel="manifest" href="/manifest.webmanifest"/>"#));
        assert!(fr.contains(r##"<meta name="theme-color" content="#05060a"/>"##));
        assert!(fr.contains(r#"navigator.serviceWorker.register("/sw.js")"#));
        for name in ["typewriter", "features", "code-tabs", "lab", "live-stats"] {
            assert!(fr.contains(&format!(r#"data-island="{name}""#)), "{name}");
        }
        assert!(fr.contains(r#"href="/fr/docs/waf/""#));
    }

    #[test]
    fn doc_pages_render_markdown_behind_the_base_path() {
        let site = site("/Securite", false);
        let html = page(&site, "/es/docs/waf/");
        assert!(
            html.contains("<h1>Firewall de aplicaciones web (WAF)</h1>"),
            "title"
        );
        assert!(html.contains(r#"<div class="prose">"#));
        assert!(html.contains(r#"href="/Securite/es/docs/"#));
        assert!(html.contains(r#"<link rel="stylesheet" href="/Securite/static/main.css?v="#));
        assert!(html.contains(r#"<meta property="og:type" content="article"/>"#));
        assert!(html.contains("TechArticle"));
        assert!(!html.contains("href=\"/docs/"), "unconverted link");
        assert!(!html.contains("href=\"/en/"), "link without base path");
    }

    #[test]
    fn the_static_playground_says_it_needs_the_server() {
        let html = page(&site("/Securite", false), "/en/playground/");
        assert!(html.contains("lab-static"));
        assert!(html.contains("|static\""), "{html}");
        let live = page(&site("", true), "/en/playground/");
        assert!(!live.contains("lab-static"));
    }

    #[test]
    fn the_docs_hub_and_not_found_pages() {
        let site = site("", true);
        let hub = page(&site, "/en/docs/");
        assert!(hub.contains(r#"data-island="docs-hub""#));
        assert!(hub.contains(r#"href="/en/docs/rate-limit/""#));
        let missing = page(&site, "/en/nope/");
        assert!(
            missing.contains(r#"<meta name="robots" content="noindex, follow"/>"#)
                || missing.contains("noindex")
        );
        assert!(!missing.contains(r#"rel="canonical""#));
    }

    #[test]
    fn the_year_is_plausible() {
        assert!((2026..2200).contains(&current_year()));
    }
}
