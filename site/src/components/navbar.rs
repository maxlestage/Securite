use yew::prelude::*;
use yew_router::prelude::*;

use crate::i18n::Lang;
use crate::icons::Icon;
use crate::{REPO, Route, scroll_to_id, use_lang};

#[component]
pub fn LangSwitcher() -> Html {
    let ctx = use_lang();
    let open = use_state(|| false);
    let toggle = {
        let open = open.clone();
        Callback::from(move |_| open.set(!*open))
    };
    html! {
        <div class={classes!("lang-switch", open.then_some("open"))}>
            <button class="lang-btn" onclick={toggle} aria-label={ctx.lang.t().language} aria-expanded={open.to_string()}>
                <Icon name="language" size={18} />
                <span>{ ctx.lang.code().to_uppercase() }</span>
                <Icon name="chevron-down" size={14} class="chev" />
            </button>
            <ul class="lang-menu" role="menu">
                { for Lang::ALL.iter().map(|l| {
                    let l = *l;
                    let set = ctx.set.clone();
                    let open = open.clone();
                    let onclick = Callback::from(move |_| { set.emit(l); open.set(false); });
                    html! {
                        <li>
                            <button class={classes!((l == ctx.lang).then_some("active"))} {onclick} role="menuitem">
                                <span class="lang-code">{ l.code().to_uppercase() }</span>{ l.label() }
                            </button>
                        </li>
                    }
                }) }
            </ul>
        </div>
    }
}

#[component]
pub fn Navbar() -> Html {
    let ctx = use_lang();
    let t = ctx.lang.t();
    let open = use_state(|| false);
    let navigator = use_navigator();
    let route = use_route::<Route>();

    let close = {
        let open = open.clone();
        Callback::from(move |_: MouseEvent| open.set(false))
    };
    let goto_section = |id: &'static str| {
        let navigator = navigator.clone();
        let open = open.clone();
        Callback::from(move |e: MouseEvent| {
            e.prevent_default();
            open.set(false);
            if let Some(n) = &navigator {
                n.push(&Route::Home);
            }
            scroll_to_id(id);
        })
    };
    let is = |r: Route| (route.as_ref() == Some(&r)).then_some("active");
    let docs_active = matches!(route, Some(Route::Docs | Route::Doc { .. })).then_some("active");

    html! {
        <header class={classes!("navbar", open.then_some("menu-open"))}>
            <nav class="nav-inner container" aria-label="Main">
                <Link<Route> to={Route::Home} classes="brand">
                    <span class="brand-mark"><Icon name="shield-check" size={22} /></span>
                    <span class="brand-name">{"securite"}</span>
                </Link<Route>>
                <div class="nav-links" onclick={close.clone()}>
                    <Link<Route> to={Route::Home} classes={classes!("nav-link", is(Route::Home))}>{ t.nav_home }</Link<Route>>
                    <a href="/#features" class="nav-link" onclick={goto_section("features")}>{ t.nav_features }</a>
                    <Link<Route> to={Route::Docs} classes={classes!("nav-link", docs_active)}>{ t.nav_docs }</Link<Route>>
                    <Link<Route> to={Route::Playground} classes={classes!("nav-link", is(Route::Playground))}>{ t.nav_playground }</Link<Route>>
                    <a href="/#deploy" class="nav-link" onclick={goto_section("deploy")}>{ t.nav_deploy }</a>
                </div>
                <div class="nav-actions">
                    <LangSwitcher />
                    <a class="icon-btn" href={REPO} target="_blank" rel="noopener noreferrer" aria-label="GitHub">
                        <Icon name="github" />
                    </a>
                    <Link<Route> to={Route::Doc { slug: "quick-start".into() }} classes="btn btn-primary btn-sm nav-cta">
                        { t.get_started }
                    </Link<Route>>
                    <button class="icon-btn burger" aria-label={t.menu} aria-expanded={open.to_string()}
                        onclick={{ let open = open.clone(); Callback::from(move |_| open.set(!*open)) }}>
                        <Icon name={if *open { "x" } else { "menu" }} />
                    </button>
                </div>
            </nav>
        </header>
    }
}
