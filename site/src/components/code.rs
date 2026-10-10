use gloo::timers::callback::Timeout;
use yew::prelude::*;

use crate::hooks::copy_to_clipboard;
use crate::icons::Icon;
use crate::use_lang;

#[derive(Properties, PartialEq)]
pub struct CopyProps {
    pub text: AttrValue,
    #[prop_or_default]
    pub class: Classes,
}

#[component]
pub fn CopyButton(props: &CopyProps) -> Html {
    let t = use_lang().lang.t();
    let copied = use_state(|| false);
    let onclick = {
        let copied = copied.clone();
        let text = props.text.clone();
        Callback::from(move |_| {
            copy_to_clipboard(&text);
            copied.set(true);
            let copied = copied.clone();
            Timeout::new(1600, move || copied.set(false)).forget();
        })
    };
    html! {
        <button class={classes!("copy-btn", props.class.clone(), copied.then_some("done"))} {onclick}
                aria-label={t.copy} title={t.copy}>
            <Icon name={if *copied { "check" } else { "copy" }} size={16} />
            <span>{ if *copied { t.copied } else { t.copy } }</span>
        </button>
    }
}

#[derive(Properties, PartialEq)]
pub struct CodeWindowProps {
    /// Pre-highlighted HTML (generated at build time).
    pub html: &'static str,
    pub raw: &'static str,
    #[prop_or("main.rs".into())]
    pub title: AttrValue,
}

/// macOS-like code window with copy button.
#[component]
pub fn CodeWindow(props: &CodeWindowProps) -> Html {
    html! {
        <div class="code-window">
            <div class="code-head">
                <span class="dots"><i></i><i></i><i></i></span>
                <span class="code-lang">{ &props.title }</span>
                <CopyButton text={props.raw} class="small" />
            </div>
            <pre><code>{ Html::from_html_unchecked(AttrValue::Static(props.html)) }</code></pre>
        </div>
    }
}

/// `$ cargo add securite` box.
#[component]
pub fn InstallBox() -> Html {
    html! {
        <div class="install-box">
            <span class="prompt">{"$"}</span>
            <code>{"cargo add securite"}</code>
            <CopyButton text="cargo add securite" />
        </div>
    }
}
