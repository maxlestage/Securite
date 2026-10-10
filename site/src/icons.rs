//! Inline SVG icons (stroke style, 24×24).

use yew::prelude::*;

fn paths(name: &str) -> Html {
    match name {
        "shield" => html! { <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /> },
        "shield-check" => html! { <>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
        </> },
        "layers" => html! { <>
            <path d="m12 2 10 5-10 5L2 7l10-5z" />
            <path d="m2 17 10 5 10-5" />
            <path d="m2 12 10 5 10-5" />
        </> },
        "globe" => html! { <>
            <circle cx="12" cy="12" r="10" />
            <path d="M2 12h20" />
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </> },
        "cookie" => html! { <>
            <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5" />
            <path d="M8.5 8.5v.01" /><path d="M16 15.5v.01" /><path d="M12 12v.01" /><path d="M11 17v.01" /><path d="M7 14v.01" />
        </> },
        "lock" => html! { <>
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </> },
        "gauge" => html! { <>
            <path d="m12 14 4-4" />
            <path d="M3.34 19a10 10 0 1 1 17.32 0" />
        </> },
        "cpu" => html! { <>
            <rect x="4" y="4" width="16" height="16" rx="2" />
            <rect x="9" y="9" width="6" height="6" />
            <path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2" />
        </> },
        "ban" => html! { <>
            <circle cx="12" cy="12" r="10" />
            <path d="m4.9 4.9 14.2 14.2" />
        </> },
        "package" => html! { <>
            <path d="M16.5 9.4 7.55 4.24" />
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
            <path d="M3.3 7 12 12l8.7-5" /><path d="M12 22V12" />
        </> },
        "filter" => html! { <path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z" /> },
        "terminal" => html! { <>
            <path d="m4 17 6-6-6-6" /><path d="M12 19h8" />
        </> },
        "server" => html! { <>
            <rect x="2" y="2" width="20" height="8" rx="2" />
            <rect x="2" y="14" width="20" height="8" rx="2" />
            <path d="M6 6h.01M6 18h.01" />
        </> },
        "link" => html! { <>
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
        </> },
        "key" => html! { <>
            <circle cx="7.5" cy="15.5" r="5.5" />
            <path d="m21 2-9.6 9.6" /><path d="m15.5 7.5 3 3L22 7l-3-3" />
        </> },
        "file" => html! { <>
            <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
            <path d="M14 2v6h6" /><path d="m9 15 2 2 4-4" />
        </> },
        "bug" => html! { <>
            <path d="m8 2 1.88 1.88M14.12 3.88 16 2" />
            <path d="M9 7.13v-1a3 3 0 1 1 6 0v1" />
            <path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6" />
            <path d="M12 20v-9M6.53 9C4.6 8.8 3 7.1 3 5M6 13H2M3 21c0-2.1 1.7-3.9 3.8-4M20.97 5c0 2.1-1.6 3.8-3.5 4M22 13h-4M17.2 17c2.1.1 3.8 1.9 3.8 4" />
        </> },
        "eye" => html! { <>
            <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z" />
            <circle cx="12" cy="12" r="3" />
        </> },
        "fingerprint" => html! { <>
            <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
            <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
            <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
            <path d="M2 12a10 10 0 0 1 18-6" /><path d="M2 16h.01" />
            <path d="M21.8 16c.2-2 .131-5.354 0-6" />
            <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
            <path d="M8.65 22c.21-.66.45-1.32.57-2" />
            <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
        </> },
        "check" => html! { <>
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <path d="m9 11 3 3L22 4" />
        </> },
        "activity" => html! { <path d="M22 12h-4l-3 9L9 3l-3 9H2" /> },
        "zap" => html! { <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" /> },
        "copy" => html! { <>
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </> },
        "arrow-right" => html! { <><path d="M5 12h14" /><path d="m12 5 7 7-7 7" /></> },
        "arrow-left" => html! { <><path d="M19 12H5" /><path d="m12 19-7-7 7-7" /></> },
        "arrow-up" => html! { <><path d="m5 12 7-7 7 7" /><path d="M12 19V5" /></> },
        "menu" => html! { <><path d="M4 6h16" /><path d="M4 12h16" /><path d="M4 18h16" /></> },
        "x" => html! { <><path d="M18 6 6 18" /><path d="m6 6 12 12" /></> },
        "search" => html! { <><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></> },
        "book" => html! { <>
            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
        </> },
        "rocket" => html! { <>
            <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" />
            <path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z" />
            <path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0" />
            <path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5" />
        </> },
        "smartphone" => html! { <>
            <rect x="5" y="2" width="14" height="20" rx="2" /><path d="M12 18h.01" />
        </> },
        "github" => {
            html! { <>
                <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
                <path d="M9 18c-4.51 2-5-2-7-2" />
            </> }
        }
        "crate" => html! { <>
            <path d="M21 8 12 3 3 8v8l9 5 9-5V8z" /><path d="m3 8 9 5 9-5" /><path d="M12 13v8" />
        </> },
        "sparkles" => html! { <>
            <path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3L12 3z" />
        </> },
        "language" => html! { <>
            <path d="m5 8 6 6" /><path d="m4 14 6-6 2-3" /><path d="M2 5h12" /><path d="M7 2h1" />
            <path d="m22 22-5-10-5 10" /><path d="M14 18h6" />
        </> },
        "chevron-down" => html! { <path d="m6 9 6 6 6-6" /> },
        "play" => html! { <path d="m6 3 14 9-14 9V3z" /> },
        _ => html! { <circle cx="12" cy="12" r="9" /> },
    }
}

#[derive(Properties, PartialEq)]
pub struct IconProps {
    pub name: AttrValue,
    #[prop_or(20)]
    pub size: u32,
    #[prop_or_default]
    pub class: Classes,
}

#[component]
pub fn Icon(props: &IconProps) -> Html {
    let size = props.size.to_string();
    html! {
        <svg class={classes!("icon", props.class.clone())} width={size.clone()} height={size}
             viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            { paths(&props.name) }
        </svg>
    }
}
