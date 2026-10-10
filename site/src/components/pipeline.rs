use yew::prelude::*;

use crate::icons::Icon;
use crate::use_lang;

const NODES: [(&str, &str); 6] = [
    ("ban", "Auto-ban"),
    ("filter", "Hygiene"),
    ("gauge", "Rate limit"),
    ("bug", "WAF"),
    ("shield", "CSRF"),
    ("layers", "Headers"),
];

/// Animated request pipeline: green packets reach the app, red packets are
/// stopped by the WAF.
#[component]
pub fn Pipeline() -> Html {
    let t = use_lang().lang.t();
    html! {
        <div class="pipeline reveal">
            <div class="pipe-end client">
                <Icon name="globe" size={26} />
                <span>{ t.pipeline_client }</span>
            </div>
            <div class="pipe-track">
                <div class="pipe-line" aria-hidden="true"></div>
                { for (0..4).map(|i| html! {
                    <span class={classes!("packet", "ok", format!("d{i}"))} aria-hidden="true"></span>
                }) }
                { for (0..3).map(|i| html! {
                    <span class={classes!("packet", "bad", format!("d{i}"))} aria-hidden="true"></span>
                }) }
                <div class="pipe-nodes">
                    { for NODES.iter().map(|(icon, label)| html! {
                        <div class={classes!("pipe-node", (*label == "WAF").then_some("waf"))}>
                            <span class="node-icon"><Icon name={*icon} size={20} /></span>
                            <span class="node-label">{ *label }</span>
                        </div>
                    }) }
                </div>
            </div>
            <div class="pipe-end app">
                <Icon name="server" size={26} />
                <span>{ t.pipeline_app }</span>
            </div>
            <div class="pipe-legend">
                <span><i class="dot ok"></i>{ t.pipeline_legit }</span>
                <span><i class="dot bad"></i>{ t.pipeline_attack }</span>
            </div>
        </div>
    }
}
