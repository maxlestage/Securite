use web_sys::HtmlInputElement;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::docs::{self, CATEGORY_ORDER, category_icon};
use crate::hooks::{tilt_handler, tilt_reset, use_reveal};
use crate::icons::Icon;
use crate::{Route, use_lang};

#[component]
pub fn DocsIndex() -> Html {
    let lang = use_lang().lang;
    let t = lang.t();
    let query = use_state(String::new);
    let category = use_state(|| None::<&'static str>);
    use_reveal((lang, (*query).clone(), *category));

    let pages = docs::pages(lang);
    let q = query.trim().to_lowercase();
    let matches = |d: &docs::DocPage| {
        q.is_empty()
            || q.split_whitespace()
                .all(|w| d.search.contains(w) || d.slug.contains(w))
    };

    let on_input = {
        let query = query.clone();
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            query.set(input.value());
        })
    };

    let mut any = false;
    let sections = CATEGORY_ORDER
        .iter()
        .filter(|c| category.is_none_or(|sel| sel == **c))
        .map(|cat| {
            let items: Vec<_> = pages.iter().filter(|d| d.category == *cat && matches(d)).collect();
            if items.is_empty() {
                return html! {};
            }
            any = true;
            let info = t.categories.iter().find(|c| c.id == *cat);
            html! {
                <section class="doc-cat">
                    <div class="doc-cat-head reveal">
                        <span class="feature-icon"><Icon name={category_icon(cat)} size={22} /></span>
                        <div>
                            <h2>{ info.map(|c| c.name).unwrap_or(cat) }</h2>
                            <p class="muted">{ info.map(|c| c.desc).unwrap_or_default() }</p>
                        </div>
                        <span class="count">{ format!("{} {}", items.len(), t.docs_pages) }</span>
                    </div>
                    <div class="doc-grid">
                        { for items.iter().enumerate().map(|(i, d)| html! {
                            <Link<Route> to={Route::Doc { slug: d.slug.into() }} classes={classes!("doc-card", "reveal", format!("d{}", i % 4))}>
                                <div class="card-inner" onmousemove={tilt_handler()} onmouseleave={tilt_reset()}>
                                    <span class="card-glow" aria-hidden="true"></span>
                                    <h3>{ d.title }</h3>
                                    <p>{ d.summary }</p>
                                    <span class="feature-more">{ t.read_docs }<Icon name="arrow-right" size={14} /></span>
                                </div>
                            </Link<Route>>
                        }) }
                    </div>
                </section>
            }
        })
        .collect::<Html>();

    html! {
        <div class="docs-hub">
            <section class="page-hero container">
                <div class="blob b1" aria-hidden="true"></div>
                <p class="kicker">{ t.docs_kicker }</p>
                <h1>{ t.docs_title }</h1>
                <p class="muted lead">{ t.docs_subtitle }</p>
                <label class="search">
                    <Icon name="search" size={18} />
                    <input type="search" placeholder={t.docs_search} value={(*query).clone()} oninput={on_input} aria-label={t.docs_search} />
                </label>
                <div class="chips center">
                    <button class={classes!("chip", category.is_none().then_some("active"))}
                        onclick={{ let c = category.clone(); Callback::from(move |_| c.set(None)) }}>{ t.all }</button>
                    { for CATEGORY_ORDER.iter().map(|id| {
                        let c = category.clone();
                        let id: &'static str = id;
                        let name = t.categories.iter().find(|x| x.id == id).map(|x| x.name).unwrap_or(id);
                        html! {
                            <button class={classes!("chip", (*category == Some(id)).then_some("active"))}
                                onclick={Callback::from(move |_| c.set(Some(id)))}>
                                <Icon name={category_icon(id)} size={15} />{ name }
                            </button>
                        }
                    }) }
                </div>
            </section>
            <div class="container">
                { sections }
                if !any {
                    <p class="empty muted">{ t.docs_none }</p>
                }
            </div>
        </div>
    }
}
