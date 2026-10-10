use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::code::{CodeWindow, InstallBox};
use crate::components::counter::Counter;
use crate::components::effects::Particles;
use crate::components::pipeline::Pipeline;
use crate::components::playground::{AttackLab, LiveStats};
use crate::components::typewriter::Typewriter;
use crate::hooks::{tilt_handler, tilt_reset, use_reveal};
use crate::icons::Icon;
use crate::{HEROKU_DEPLOY, REPO, Route, use_lang};

mod snippets {
    include!(concat!(env!("OUT_DIR"), "/snippets_gen.rs"));
}

const STACK: &[&str] = &[
    "axum",
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

#[component]
fn Hero() -> Html {
    let t = use_lang().lang.t();
    html! {
        <section class="hero">
            <Particles />
            <div class="blob b1" aria-hidden="true"></div>
            <div class="blob b2" aria-hidden="true"></div>
            <div class="blob b3" aria-hidden="true"></div>
            <div class="container hero-inner">
                <Link<Route> to={Route::Doc { slug: "introduction".into() }} classes="badge shine">
                    <Icon name="sparkles" size={16} />
                    <span>{ t.hero_badge }</span>
                    <Icon name="arrow-right" size={14} />
                </Link<Route>>
                <h1 class="hero-title">
                    <span class="line">{ t.hero_title }</span>
                    <span class="line small">{ t.hero_against }{" "}<Typewriter words={t.hero_words} /></span>
                </h1>
                <p class="hero-sub">{ t.hero_subtitle }</p>
                <div class="hero-ctas">
                    <Link<Route> to={Route::Doc { slug: "quick-start".into() }} classes="btn btn-primary btn-lg magnetic">
                        { t.hero_cta_primary }<Icon name="arrow-right" size={18} />
                    </Link<Route>>
                    <Link<Route> to={Route::Playground} classes="btn btn-ghost btn-lg">
                        <Icon name="bug" size={18} />{ t.hero_cta_secondary }
                    </Link<Route>>
                </div>
                <InstallBox />
            </div>
            <div class="scroll-hint" aria-hidden="true"><span></span></div>
        </section>
    }
}

#[component]
fn Marquee() -> Html {
    let t = use_lang().lang.t();
    let items = || {
        STACK.iter().map(|s| html! { <span class="marquee-item"><Icon name="check" size={16} />{ *s }</span> }).collect::<Html>()
    };
    html! {
        <section class="marquee-section">
            <p class="kicker center">{ t.marquee_title }</p>
            <div class="marquee" aria-hidden="true">
                <div class="marquee-track">{ items() }{ items() }</div>
            </div>
        </section>
    }
}

#[component]
fn Stats() -> Html {
    let t = use_lang().lang.t();
    html! {
        <section class="container stats">
            <div class="stat reveal"><strong><Counter to={19.0} /></strong><span>{ t.stat_middlewares }</span></div>
            <div class="stat reveal d1"><strong>{"≈ "}<Counter to={6.0} suffix=" µs" /></strong><span>{ t.stat_overhead }</span></div>
            <div class="stat reveal d2"><strong><Counter to={400.0} suffix="+" /></strong><span>{ t.stat_signatures }</span></div>
            <div class="stat reveal d3"><strong><Counter to={0.0} /></strong><span>{ t.stat_unsafe }</span></div>
            <div class="stat reveal d4"><strong><Counter to={3.0} /></strong><span>{ t.stat_languages }</span></div>
        </section>
    }
}

#[component]
fn Features() -> Html {
    let t = use_lang().lang.t();
    let filter = use_state(|| None::<&'static str>);
    use_reveal(*filter);
    let cats: Vec<_> = t
        .categories
        .iter()
        .filter(|c| c.id != "start" && c.id != "deploy")
        .collect();
    html! {
        <section id="features" class="section container">
            <div class="section-head reveal">
                <p class="kicker">{ t.features_kicker }</p>
                <h2>{ t.features_title }</h2>
                <p class="muted">{ t.features_subtitle }</p>
            </div>
            <div class="chips center reveal" role="tablist">
                <button class={classes!("chip", filter.is_none().then_some("active"))}
                    onclick={{ let f = filter.clone(); Callback::from(move |_| f.set(None)) }}>{ t.all }</button>
                { for cats.iter().map(|c| {
                    let f = filter.clone();
                    let id = c.id;
                    html! {
                        <button class={classes!("chip", (*filter == Some(id)).then_some("active"))}
                            onclick={Callback::from(move |_| f.set(Some(id)))}>
                            <Icon name={crate::docs::category_icon(id)} size={15} />{ c.name }
                        </button>
                    }
                }) }
            </div>
            <div class="feature-grid">
                { for t.features.iter().filter(|f| filter.is_none_or(|c| c == f.category)).enumerate().map(|(i, f)| {
                    let cat = t.categories.iter().find(|c| c.id == f.category).map(|c| c.name).unwrap_or_default();
                    html! {
                        <Link<Route> to={Route::Doc { slug: f.slug.into() }} classes={classes!("feature-card", "reveal", format!("d{}", i % 4))}>
                            <div class="card-inner" onmousemove={tilt_handler()} onmouseleave={tilt_reset()}>
                                <span class="card-glow" aria-hidden="true"></span>
                                <span class="feature-icon"><Icon name={f.icon} size={22} /></span>
                                <span class="feature-cat">{ cat }</span>
                                <h3>{ f.name }</h3>
                                <p>{ f.desc }</p>
                                <span class="feature-more">{ t.read_docs }<Icon name="arrow-right" size={14} /></span>
                            </div>
                        </Link<Route>>
                    }
                }) }
            </div>
        </section>
    }
}

#[component]
fn HowItWorks() -> Html {
    let t = use_lang().lang.t();
    html! {
        <section class="section container">
            <div class="section-head reveal">
                <p class="kicker">{ t.pipeline_kicker }</p>
                <h2>{ t.pipeline_title }</h2>
                <p class="muted">{ t.pipeline_subtitle }</p>
            </div>
            <Pipeline />
            <div class="principles">
                { for t.principles.iter().enumerate().map(|(i, p)| html! {
                    <div class={classes!("principle", "reveal", format!("d{i}"))}>
                        <span class="principle-num">{ format!("0{}", i + 1) }</span>
                        <h3>{ p.title }</h3>
                        <p>{ p.text }</p>
                    </div>
                }) }
            </div>
        </section>
    }
}

#[component]
fn CodeShowcase() -> Html {
    let t = use_lang().lang.t();
    let tab = use_state(|| 0usize);
    let (html, raw, title) = match *tab {
        0 => (snippets::ONE_LINE, snippets::ONE_LINE_RAW, "main.rs"),
        1 => (snippets::TAILORED, snippets::TAILORED_RAW, "shield.rs"),
        _ => (snippets::STANDALONE, snippets::STANDALONE_RAW, "layers.rs"),
    };
    html! {
        <section class="section container code-section">
            <div class="code-copy reveal">
                <p class="kicker">{ t.code_kicker }</p>
                <h2>{ t.code_title }</h2>
                <p class="muted">{ t.code_subtitle }</p>
                <div class="tabs" role="tablist">
                    { for t.code_tabs.iter().enumerate().map(|(i, label)| {
                        let tab2 = tab.clone();
                        html! {
                            <button role="tab" aria-selected={(*tab == i).to_string()}
                                class={classes!("tab", (*tab == i).then_some("active"))}
                                onclick={Callback::from(move |_| tab2.set(i))}>{ *label }</button>
                        }
                    }) }
                </div>
                <Link<Route> to={Route::Doc { slug: "shield-presets".into() }} classes="btn btn-ghost">
                    { t.read_docs }<Icon name="arrow-right" size={16} />
                </Link<Route>>
            </div>
            <div class="code-stage fade-in" key={*tab}>
                <CodeWindow html={html} raw={raw} title={title} />
            </div>
        </section>
    }
}

#[component]
fn PlaygroundTeaser() -> Html {
    let t = use_lang().lang.t();
    html! {
        <section id="playground" class="section container">
            <div class="section-head reveal">
                <p class="kicker">{ t.play_kicker }</p>
                <h2>{ t.play_title }</h2>
                <p class="muted">{ t.play_subtitle }</p>
            </div>
            <div class="reveal"><AttackLab compact={true} /></div>
            <div class="reveal center-row">
                <LiveStats />
                <Link<Route> to={Route::Playground} classes="btn btn-ghost">{ t.play_open }<Icon name="arrow-right" size={16} /></Link<Route>>
            </div>
        </section>
    }
}

#[component]
fn Benchmarks() -> Html {
    let t = use_lang().lang.t();
    // Measured with `cargo bench -p securite` (criterion), see benches/shield.rs.
    let rows: [(&str, &str, f64); 4] = [
        (t.bench_items[0], "6.1 µs", 100.0),
        (t.bench_items[1], "1.9 µs", 31.0),
        (t.bench_items[2], "0.68 µs", 11.0),
        (t.bench_items[3], "3.4 ns", 1.5),
    ];
    html! {
        <section class="section container bench">
            <div class="section-head reveal">
                <p class="kicker">{ t.bench_kicker }</p>
                <h2>{ t.bench_title }</h2>
                <p class="muted">{ t.bench_subtitle }</p>
            </div>
            <div class="bench-list">
                { for rows.iter().enumerate().map(|(i, (label, value, pct))| html! {
                    <div class={classes!("bench-row", "reveal", format!("d{i}"))}>
                        <div class="bench-label"><span>{ *label }</span><strong>{ *value }</strong></div>
                        <div class="bench-bar"><span style={format!("--w:{pct}%")}></span></div>
                    </div>
                }) }
            </div>
            <p class="bench-note muted reveal">{ t.bench_note }</p>
        </section>
    }
}

#[component]
fn Deploy() -> Html {
    let t = use_lang().lang.t();
    html! {
        <section id="deploy" class="section container deploy">
            <div class="deploy-card reveal">
                <div class="deploy-copy">
                    <p class="kicker"><Icon name="smartphone" size={16} />{" "}{ t.deploy_kicker }</p>
                    <h2>{ t.deploy_title }</h2>
                    <p class="muted">{ t.deploy_subtitle }</p>
                    <div class="hero-ctas">
                        <a class="btn btn-heroku btn-lg" href={HEROKU_DEPLOY} target="_blank" rel="noopener noreferrer">
                            <Icon name="rocket" size={18} />{ t.deploy_button }
                        </a>
                        <Link<Route> to={Route::Doc { slug: "heroku-from-phone".into() }} classes="btn btn-ghost btn-lg">
                            { t.deploy_guide }<Icon name="arrow-right" size={18} />
                        </Link<Route>>
                    </div>
                </div>
                <ol class="timeline">
                    { for t.deploy_steps.iter().enumerate().map(|(i, s)| html! {
                        <li class={classes!("reveal", format!("d{i}"))}>
                            <span class="step-num">{ i + 1 }</span>
                            <div><h3>{ s.title }</h3><p>{ s.text }</p></div>
                        </li>
                    }) }
                </ol>
                <div class="phone" aria-hidden="true">
                    <div class="phone-notch"></div>
                    <div class="phone-screen">
                        <div class="phone-line w70"></div>
                        <div class="phone-line w40"></div>
                        <div class="phone-btn">{"Deploy"}</div>
                        <div class="phone-progress"><span></span></div>
                        <div class="phone-ok"><Icon name="check" size={28} /></div>
                    </div>
                </div>
            </div>
        </section>
    }
}

#[component]
fn FinalCta() -> Html {
    let t = use_lang().lang.t();
    html! {
        <section class="section container">
            <div class="cta reveal">
                <div class="cta-border" aria-hidden="true"></div>
                <h2>{ t.cta_title }</h2>
                <p class="muted">{ t.cta_subtitle }</p>
                <InstallBox />
                <div class="hero-ctas">
                    <Link<Route> to={Route::Docs} classes="btn btn-primary btn-lg">
                        <Icon name="book" size={18} />{ t.nav_docs }
                    </Link<Route>>
                    <a class="btn btn-ghost btn-lg" href={REPO} target="_blank" rel="noopener noreferrer">
                        <Icon name="github" size={18} />{"GitHub"}
                    </a>
                </div>
            </div>
        </section>
    }
}

#[component]
pub fn Home() -> Html {
    let lang = use_lang().lang;
    use_reveal(lang);
    html! {
        <>
            <Hero />
            <Marquee />
            <Stats />
            <Features />
            <HowItWorks />
            <CodeShowcase />
            <PlaygroundTeaser />
            <Benchmarks />
            <Deploy />
            <FinalCta />
        </>
    }
}
