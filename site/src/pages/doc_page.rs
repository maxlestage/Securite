use gloo::timers::callback::Timeout;
use wasm_bindgen::JsCast;
use web_sys::Element;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::docs::{self, CATEGORY_ORDER, category_icon};
use crate::hooks::{copy_to_clipboard, use_reveal};
use crate::icons::Icon;
use crate::pages::not_found::NotFound;
use crate::{REPO, Route, use_lang};

#[derive(Properties, PartialEq)]
pub struct DocPageProps {
    pub slug: String,
}

#[component]
pub fn DocPageView(props: &DocPageProps) -> Html {
    let lang = use_lang().lang;
    let t = lang.t();
    let navigator = use_navigator();
    let menu_open = use_state(|| false);
    use_reveal((lang, props.slug.clone()));

    // Page bodies are fetched on demand (content-hashed, cached forever).
    let found = docs::find(lang, &props.slug);
    let body = use_state(|| {
        found
            .and_then(|(p, _)| docs::cached(p))
            .map(Ok::<_, String>)
    });
    let wanted = use_mut_ref(|| "");
    {
        let body = body.clone();
        let wanted = wanted.clone();
        use_effect_with(found.map(|(p, _)| p.url), move |_| {
            if let Some((page, _)) = found {
                *wanted.borrow_mut() = page.url;
                match docs::cached(page) {
                    Some(html) => body.set(Some(Ok(html))),
                    None => {
                        body.set(None);
                        wasm_bindgen_futures::spawn_local(async move {
                            let result = docs::body(page).await;
                            // Ignore late answers for a page we already left.
                            if *wanted.borrow() == page.url {
                                body.set(Some(result));
                                scroll_to_hash();
                            }
                        });
                    }
                }
            }
        });
    }

    let Some((page, translated)) = found else {
        return html! { <NotFound /> };
    };
    let pages = docs::pages(lang);
    let idx = pages.iter().position(|p| p.slug == page.slug);
    let prev = idx
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| pages.get(i));
    let next = idx.and_then(|i| pages.get(i + 1));
    let cat_name = t
        .categories
        .iter()
        .find(|c| c.id == page.category)
        .map(|c| c.name)
        .unwrap_or(page.category);

    // Event delegation inside the rendered markdown: copy buttons and
    // internal links (SPA navigation).
    let on_article_click = {
        let navigator = navigator.clone();
        Callback::from(move |e: MouseEvent| {
            let Some(target) = e.target().and_then(|t| t.dyn_into::<Element>().ok()) else {
                return;
            };
            if let Ok(Some(btn)) = target.closest(".copy") {
                let code = btn
                    .closest(".code")
                    .ok()
                    .flatten()
                    .and_then(|c| c.query_selector("code").ok().flatten())
                    .and_then(|c| c.text_content());
                if let Some(code) = code {
                    copy_to_clipboard(&code);
                    btn.set_text_content(Some("✓"));
                    let btn = btn.clone();
                    Timeout::new(1500, move || btn.set_text_content(Some("⧉"))).forget();
                }
                return;
            }
            if let Ok(Some(a)) = target.closest("a") {
                let href = a.get_attribute("href").unwrap_or_default();
                if href.starts_with('/')
                    && !href.starts_with("//")
                    && let (Some(route), Some(nav)) = (
                        Route::recognize(href.split('#').next().unwrap_or("/")),
                        &navigator,
                    )
                {
                    e.prevent_default();
                    nav.push(&route);
                }
            }
        })
    };

    let sidebar = CATEGORY_ORDER
        .iter()
        .map(|cat| {
            let items: Vec<_> = pages.iter().filter(|p| p.category == *cat).collect();
            if items.is_empty() {
                return html! {};
            }
            let name = t.categories.iter().find(|c| c.id == *cat).map(|c| c.name).unwrap_or(cat);
            html! {
                <div class="side-group">
                    <p class="side-title"><Icon name={category_icon(cat)} size={15} />{ name }</p>
                    <ul>
                        { for items.iter().map(|p| html! {
                            <li>
                                <Link<Route> to={Route::Doc { slug: p.slug.into() }}
                                    classes={classes!("side-link", (p.slug == page.slug).then_some("active"))}>
                                    { p.title }
                                </Link<Route>>
                            </li>
                        }) }
                    </ul>
                </div>
            }
        })
        .collect::<Html>();

    let edit_url = format!("{REPO}/edit/master/docs/{}/{}.md", page.lang, page.slug);

    html! {
        <div class="doc-layout container">
            <aside class={classes!("doc-sidebar", menu_open.then_some("open"))}>
                <button class="side-toggle" onclick={{ let m = menu_open.clone(); Callback::from(move |_| m.set(!*m)) }}>
                    <Icon name="menu" size={18} />{ t.nav_docs }<Icon name="chevron-down" size={16} class="chev" />
                </button>
                <nav class="side-nav" onclick={{ let m = menu_open.clone(); Callback::from(move |_| m.set(false)) }}>
                    <Link<Route> to={Route::Docs} classes="side-back"><Icon name="arrow-left" size={15} />{ t.docs_back }</Link<Route>>
                    { sidebar }
                </nav>
            </aside>
            <article class="doc-article">
                <div class="breadcrumbs">
                    <Link<Route> to={Route::Docs}>{ t.nav_docs }</Link<Route>>
                    <span>{"/"}</span>
                    <span>{ cat_name }</span>
                </div>
                <header class="doc-header">
                    <h1>{ page.title }</h1>
                    <p class="lead muted">{ page.summary }</p>
                    if !translated {
                        <p class="callout warn small">{ t.docs_missing }</p>
                    }
                </header>
                <div class="prose" onclick={on_article_click}>
                    { match &*body {
                        Some(Ok(html)) => Html::from_html_unchecked(AttrValue::Rc(html.clone())),
                        Some(Err(e)) => html! { <p class="callout warn">{ format!("⚠ {e}") }</p> },
                        None => html! {
                            <div class="skeleton" aria-busy="true" aria-label="Loading">
                                <span class="sk w90"></span><span class="sk w75"></span><span class="sk w85"></span>
                                <span class="sk block"></span>
                                <span class="sk w60"></span><span class="sk w80"></span>
                            </div>
                        },
                    } }
                </div>
                <div class="doc-footer">
                    <a href={edit_url} target="_blank" rel="noopener noreferrer" class="edit-link">
                        <Icon name="github" size={16} />{ t.docs_edit }
                    </a>
                </div>
                <nav class="prev-next">
                    if let Some(p) = prev {
                        <Link<Route> to={Route::Doc { slug: p.slug.into() }} classes="pn prev">
                            <span class="muted small"><Icon name="arrow-left" size={14} />{ t.docs_prev }</span>
                            <strong>{ p.title }</strong>
                        </Link<Route>>
                    } else { <span></span> }
                    if let Some(n) = next {
                        <Link<Route> to={Route::Doc { slug: n.slug.into() }} classes="pn next">
                            <span class="muted small">{ t.docs_next }<Icon name="arrow-right" size={14} /></span>
                            <strong>{ n.title }</strong>
                        </Link<Route>>
                    }
                </nav>
            </article>
            <aside class="doc-toc">
                if !page.toc.is_empty() {
                    <p class="side-title">{ t.docs_on_page }</p>
                    <ul>
                        { for page.toc.iter().map(|(id, text, level)| html! {
                            <li class={format!("lvl{level}")}><a href={format!("#{id}")}>{ *text }</a></li>
                        }) }
                    </ul>
                }
            </aside>
        </div>
    }
}

/// Scrolls to `location.hash` once the page body is in the DOM.
fn scroll_to_hash() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let hash = window.location().hash().unwrap_or_default();
    let Some(id) = hash.strip_prefix('#').filter(|h| !h.is_empty()) else {
        return;
    };
    let id = id.to_owned();
    Timeout::new(30, move || {
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(&id))
        {
            el.scroll_into_view();
        }
    })
    .forget();
}
