use yew::prelude::*;
use yew_router::prelude::*;

use crate::icons::Icon;
use crate::{Route, use_lang};

#[component]
pub fn NotFound() -> Html {
    let t = use_lang().lang.t();
    html! {
        <section class="not-found container">
            <div class="nf-code glitch" data-text="404">{"404"}</div>
            <h1>{ t.nf_title }</h1>
            <p class="muted">{ t.nf_text }</p>
            <Link<Route> to={Route::Home} classes="btn btn-primary">
                <Icon name="arrow-left" size={18} />{ t.nf_back }
            </Link<Route>>
        </section>
    }
}
