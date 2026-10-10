//! securite website — Yew + WebAssembly.

mod components;
mod docs;
mod hooks;
mod i18n;
mod icons;
mod pages;

use i18n::Lang;
use wasm_bindgen::JsCast;
use yew::prelude::*;
use yew_router::prelude::*;

pub const REPO: &str = "https://github.com/maxlestage/Securite";
pub const CRATES_IO: &str = "https://crates.io/crates/securite";
pub const DOCS_RS: &str = "https://docs.rs/securite";
pub const HEROKU_DEPLOY: &str =
    "https://www.heroku.com/deploy?template=https://github.com/maxlestage/Securite";

#[derive(Routable, Clone, PartialEq, Debug)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/docs")]
    Docs,
    #[at("/docs/:slug")]
    Doc { slug: String },
    #[at("/playground")]
    Playground,
    #[not_found]
    #[at("/404")]
    NotFound,
}

/// Current language + setter, shared through a context.
#[derive(Clone, PartialEq)]
pub struct LangCtx {
    pub lang: Lang,
    pub set: Callback<Lang>,
}

#[hook]
pub fn use_lang() -> LangCtx {
    use_context::<LangCtx>().expect("LangCtx provided by App")
}

/// `localStorage` can be missing or throw (private mode): never panic.
fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

fn initial_lang() -> Lang {
    let stored = local_storage()
        .and_then(|s| s.get_item("lang").ok().flatten())
        .and_then(|c| Lang::from_code(&c));
    stored
        .or_else(|| {
            web_sys::window()
                .and_then(|w| w.navigator().language())
                .and_then(|l| Lang::from_code(&l))
        })
        .unwrap_or(Lang::En)
}

fn switch(route: Route) -> Html {
    match route {
        Route::Home => html! { <pages::home::Home /> },
        Route::Docs => html! { <pages::docs_index::DocsIndex /> },
        Route::Doc { slug } => html! { <pages::doc_page::DocPageView {slug} /> },
        Route::Playground => html! { <pages::playground::PlaygroundPage /> },
        Route::NotFound => html! { <pages::not_found::NotFound /> },
    }
}

#[component]
fn Shell() -> Html {
    let location = use_location();
    let path = location
        .as_ref()
        .map(|l| l.path().to_string())
        .unwrap_or_default();

    // Scroll to top on page change.
    use_effect_with(path.clone(), |_| {
        if let Some(w) = web_sys::window()
            && w.location().hash().unwrap_or_default().is_empty()
        {
            w.scroll_to_with_x_and_y(0.0, 0.0);
        }
    });

    html! {
        <>
            <components::effects::ScrollProgress />
            <components::effects::CursorGlow />
            <div class="bg-grid" aria-hidden="true"></div>
            <components::navbar::Navbar />
            <main id="main" key={path.clone()} class="page-enter">
                <Switch<Route> render={switch} />
            </main>
            <components::footer::Footer />
            <components::effects::BackToTop />
        </>
    }
}

#[component]
fn App() -> Html {
    let lang = use_state(initial_lang);

    {
        let lang = *lang;
        use_effect_with(lang, move |lang| {
            if let Some(doc) = web_sys::window().and_then(|w| w.document())
                && let Some(root) = doc.document_element()
            {
                let _ = root.set_attribute("lang", lang.code());
            }
            if let Some(s) = local_storage() {
                let _ = s.set_item("lang", lang.code());
            }
        });
    }

    let ctx = LangCtx {
        lang: *lang,
        set: {
            let lang = lang.clone();
            Callback::from(move |l: Lang| lang.set(l))
        },
    };

    html! {
        <ContextProvider<LangCtx> context={ctx}>
            <BrowserRouter>
                <Shell />
            </BrowserRouter>
        </ContextProvider<LangCtx>>
    }
}

/// Smoothly scrolls to the element with `id` (after the next render).
pub fn scroll_to_id(id: &'static str) {
    gloo::timers::callback::Timeout::new(60, move || {
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(id))
            && let Ok(el) = el.dyn_into::<web_sys::HtmlElement>()
        {
            el.scroll_into_view();
        }
    })
    .forget();
}

fn main() {
    let document = web_sys::window()
        .and_then(|w| w.document())
        .expect("document");
    if let Some(boot) = document.get_element_by_id("boot") {
        boot.remove();
    }
    let root = document.get_element_by_id("app").expect("#app");
    yew::Renderer::<App>::with_root(root).render();
}
