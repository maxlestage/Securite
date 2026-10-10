use yew::prelude::*;

use crate::components::playground::{AttackLab, LiveStats};
use crate::hooks::use_reveal;
use crate::use_lang;

#[component]
pub fn PlaygroundPage() -> Html {
    let lang = use_lang().lang;
    let t = lang.t();
    use_reveal(lang);
    html! {
        <div class="playground-page">
            <section class="page-hero container">
                <div class="blob b2" aria-hidden="true"></div>
                <p class="kicker">{ t.play_kicker }</p>
                <h1>{ t.play_title }</h1>
                <p class="muted lead">{ t.play_subtitle }</p>
            </section>
            <section class="container section-tight">
                <div class="reveal"><AttackLab /></div>
                <div class="reveal center-row"><LiveStats /></div>
            </section>
        </div>
    }
}
