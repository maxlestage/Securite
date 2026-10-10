//! Reusable animation hooks.

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::Closure;
use web_sys::{IntersectionObserver, IntersectionObserverEntry, IntersectionObserverInit};
use yew::prelude::*;

/// Adds the `visible` class to every `.reveal` element when it scrolls into
/// view. Re-scans whenever `deps` change.
#[hook]
pub fn use_reveal<D: PartialEq + 'static>(deps: D) {
    use_effect_with(deps, |_| {
        let callback = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
            |entries: js_sys::Array, observer: IntersectionObserver| {
                for entry in entries.iter() {
                    let entry: IntersectionObserverEntry = entry.unchecked_into();
                    if entry.is_intersecting() {
                        let target = entry.target();
                        let _ = target.class_list().add_1("visible");
                        observer.unobserve(&target);
                    }
                }
            },
        );
        let init = IntersectionObserverInit::new();
        init.set_threshold(&wasm_bindgen::JsValue::from_f64(0.12));
        init.set_root_margin("0px 0px -40px 0px");
        let observer =
            IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), &init).ok();
        if let (Some(observer), Some(doc)) =
            (&observer, web_sys::window().and_then(|w| w.document()))
            && let Ok(nodes) = doc.query_selector_all(".reveal:not(.visible)")
        {
            for i in 0..nodes.length() {
                if let Some(node) = nodes.item(i) {
                    observer.observe(node.unchecked_ref());
                }
            }
        }
        move || {
            if let Some(o) = observer {
                o.disconnect();
            }
            drop(callback);
        }
    });
}

/// Returns `true` once the element behind `node` has been seen.
#[hook]
pub fn use_in_view(node: NodeRef) -> bool {
    let seen = use_state(|| false);
    {
        let seen = seen.clone();
        use_effect_with(node, move |node| {
            let setter = seen.clone();
            let callback = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
                move |entries: js_sys::Array, observer: IntersectionObserver| {
                    for entry in entries.iter() {
                        let entry: IntersectionObserverEntry = entry.unchecked_into();
                        if entry.is_intersecting() {
                            setter.set(true);
                            observer.disconnect();
                        }
                    }
                },
            );
            let init = IntersectionObserverInit::new();
            init.set_threshold(&wasm_bindgen::JsValue::from_f64(0.3));
            let observer =
                IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), &init)
                    .ok();
            if let (Some(o), Some(el)) = (&observer, node.cast::<web_sys::Element>()) {
                o.observe(&el);
            }
            move || {
                if let Some(o) = observer {
                    o.disconnect();
                }
                drop(callback);
            }
        });
    }
    *seen
}

/// Whether the user asked for reduced motion.
pub fn prefers_reduced_motion() -> bool {
    web_sys::window()
        .and_then(|w| {
            w.match_media("(prefers-reduced-motion: reduce)")
                .ok()
                .flatten()
        })
        .is_some_and(|m| m.matches())
}

/// Copies `text` to the clipboard.
pub fn copy_to_clipboard(text: &str) {
    if let Some(w) = web_sys::window() {
        let _ = w.navigator().clipboard().write_text(text);
    }
}

/// Tilt + glow effect for cards: sets CSS variables on the hovered element.
pub fn tilt_handler() -> Callback<MouseEvent> {
    Callback::from(|e: MouseEvent| {
        let Some(el) = e
            .current_target()
            .and_then(|t| t.dyn_into::<web_sys::HtmlElement>().ok())
        else {
            return;
        };
        let rect = el.get_bounding_client_rect();
        let x = (f64::from(e.client_x()) - rect.left()) / rect.width();
        let y = (f64::from(e.client_y()) - rect.top()) / rect.height();
        let style = el.style();
        let _ = style.set_property("--mx", &format!("{:.1}%", x * 100.0));
        let _ = style.set_property("--my", &format!("{:.1}%", y * 100.0));
        let _ = style.set_property("--rx", &format!("{:.2}deg", (0.5 - y) * 8.0));
        let _ = style.set_property("--ry", &format!("{:.2}deg", (x - 0.5) * 8.0));
    })
}

/// Resets the tilt when the pointer leaves.
pub fn tilt_reset() -> Callback<MouseEvent> {
    Callback::from(|e: MouseEvent| {
        if let Some(el) = e
            .current_target()
            .and_then(|t| t.dyn_into::<web_sys::HtmlElement>().ok())
        {
            let style = el.style();
            let _ = style.set_property("--rx", "0deg");
            let _ = style.set_property("--ry", "0deg");
        }
    })
}
