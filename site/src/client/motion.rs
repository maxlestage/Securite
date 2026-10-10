//! Page motion that CSS cannot do alone: scroll progress, reveals, counters, the cursor
//! glow, tilting cards, copy buttons, menus and the hero particles.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{
    Element, HtmlElement, IntersectionObserver, IntersectionObserverEntry, IntersectionObserverInit,
};

use super::{
    all, document, later, matches_media, on, on_passive, reduced_motion, request_frame, window,
};

pub fn init() {
    let reduced = reduced_motion();
    scroll_state();
    reveals(reduced);
    counters(reduced);
    clicks();
    if !reduced {
        cursor_glow();
        if matches_media("(pointer: fine)") {
            tilt();
        }
        super::particles::start();
    }
}

fn root() -> HtmlElement {
    document()
        .document_element()
        .expect("<html>")
        .unchecked_into()
}

fn viewport_height() -> f64 {
    window()
        .inner_height()
        .ok()
        .and_then(|h| h.as_f64())
        .unwrap_or(800.0)
}

fn observe(
    elements: &[HtmlElement],
    options: &IntersectionObserverInit,
    f: impl Fn(&IntersectionObserverEntry, &IntersectionObserver) + 'static,
) {
    let callback = Closure::<dyn Fn(js_sys::Array, IntersectionObserver)>::new(
        move |entries: js_sys::Array, io: IntersectionObserver| {
            for entry in entries.iter() {
                if let Ok(entry) = entry.dyn_into::<IntersectionObserverEntry>() {
                    f(&entry, &io);
                }
            }
        },
    );
    if let Ok(io) =
        IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), options)
    {
        for el in elements {
            io.observe(el);
        }
    }
    callback.forget();
}

/// `--scroll` (reading progress, 0 to 1) and `--scrolled` (past the top) on `<html>`:
/// the progress bar, the glassy navbar and the back-to-top button follow them.
fn scroll_state() {
    let root = root();
    let update = move || {
        let w = window();
        let y = w.scroll_y().unwrap_or(0.0);
        let max = (f64::from(root.scroll_height()) - viewport_height()).max(1.0);
        let style = root.style();
        let _ = style.set_property("--scroll", &format!("{:.4}", (y / max).clamp(0.0, 1.0)));
        let _ = style.set_property("--scrolled", if y > 24.0 { "1" } else { "0" });
    };
    update();
    let update = Rc::new(update);
    let ticking = Rc::new(Cell::new(false));
    on_passive(&window(), "scroll", move |_: web_sys::Event| {
        if ticking.replace(true) {
            return;
        }
        let (update, ticking) = (update.clone(), ticking.clone());
        request_frame(move |_| {
            ticking.set(false);
            update();
            false
        });
    });
}

/// `.reveal` elements fade in when they scroll into view. Those already on screen stay
/// visible; the others are hidden only once this code runs (`html.motion`), so the page
/// reads fine before the WebAssembly loads, and without it.
fn reveals(reduced: bool) {
    let elements = all(".reveal:not(.visible)");
    let height = viewport_height();
    let mut later = Vec::new();
    for el in elements {
        let r = el.get_bounding_client_rect();
        if reduced || (r.height() > 0.0 && r.top() < height && r.bottom() > 0.0) {
            let _ = el.class_list().add_1("visible");
        } else {
            later.push(el);
        }
    }
    let _ = root().class_list().add_1("motion");
    let options = IntersectionObserverInit::new();
    options.set_threshold(&JsValue::from_f64(0.12));
    options.set_root_margin("0px 0px -40px 0px");
    observe(&later, &options, |entry, io| {
        if entry.is_intersecting() {
            let target = entry.target();
            let _ = target.class_list().add_1("visible");
            io.unobserve(&target);
        }
    });
}

/// Numbers count up from 0 when they come into view (`data-count`, `data-suffix`).
fn counters(reduced: bool) {
    let elements = all("[data-count]");
    if reduced {
        return;
    }
    let text = |el: &HtmlElement, value: f64| {
        let suffix = el.dataset().get("suffix").unwrap_or_default();
        el.set_text_content(Some(&format!("{value:.0}{suffix}")));
    };
    for el in &elements {
        text(el, 0.0);
    }
    let options = IntersectionObserverInit::new();
    options.set_threshold(&JsValue::from_f64(0.3));
    observe(&elements, &options, move |entry, io| {
        if !entry.is_intersecting() {
            return;
        }
        let el: HtmlElement = entry.target().unchecked_into();
        io.unobserve(&el);
        let target: f64 = el
            .dataset()
            .get("count")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0);
        let start = Cell::new(None::<f64>);
        request_frame(move |now| {
            let t0 = *start.get().get_or_insert(now);
            start.set(Some(t0));
            let t = ((now - t0) / 1600.0).min(1.0);
            text(&el, target * (1.0 - (1.0 - t).powi(3)));
            t < 1.0
        });
    });
}

fn closest(target: Option<web_sys::EventTarget>, selector: &str) -> Option<Element> {
    target
        .and_then(|t| t.dyn_into::<Element>().ok())
        .and_then(|t| t.closest(selector).ok().flatten())
}

fn copy(text: &str) {
    let _ = window().navigator().clipboard().write_text(text);
}

fn set_expanded(button: &Element, open: bool) {
    let _ = button.set_attribute("aria-expanded", if open { "true" } else { "false" });
}

fn close_lang_menus(except: Option<&Element>) {
    for menu in all(".lang-switch.open") {
        if except.is_some_and(|e| e.is_same_node(Some(&menu))) {
            continue;
        }
        let _ = menu.class_list().remove_1("open");
        if let Ok(Some(button)) = menu.query_selector(".lang-btn") {
            set_expanded(&button, false);
        }
    }
}

fn close_mobile_menu() {
    for navbar in all(".navbar.menu-open") {
        let _ = navbar.class_list().remove_1("menu-open");
        if let Ok(Some(burger)) = navbar.query_selector(".burger") {
            set_expanded(&burger, false);
        }
    }
}

/// One click listener for the whole page: copy buttons, menus, back to top.
fn clicks() {
    let doc = document();
    on(&doc, "click", |e: web_sys::MouseEvent| {
        let target = e.target();
        // "Copy" buttons (install box, code windows).
        if let Some(button) = closest(target.clone(), ".copy-btn") {
            let Some(text) = button.get_attribute("data-copy") else {
                return;
            };
            copy(&text);
            let _ = button.class_list().add_1("done");
            let label = button.query_selector("span").ok().flatten();
            if let (Some(label), Some(done)) = (&label, button.get_attribute("data-done")) {
                label.set_text_content(Some(&done));
            }
            let idle = button.get_attribute("aria-label").unwrap_or_default();
            later(1600, move || {
                let _ = button.class_list().remove_1("done");
                if let Some(label) = label {
                    label.set_text_content(Some(&idle));
                }
            });
            return;
        }
        // Copy buttons of the code blocks in the documentation.
        if let Some(button) = closest(target.clone(), ".code .copy") {
            let code = button
                .closest(".code")
                .ok()
                .flatten()
                .and_then(|c| c.query_selector("code").ok().flatten())
                .and_then(|c| c.text_content());
            if let Some(code) = code {
                copy(&code);
                button.set_text_content(Some("✓"));
                later(1500, move || button.set_text_content(Some("⧉")));
            }
            return;
        }
        // Language menu.
        if let Some(button) = closest(target.clone(), ".lang-btn") {
            if let Some(menu) = button.closest(".lang-switch").ok().flatten() {
                close_lang_menus(Some(&menu));
                let open = menu.class_list().toggle("open").unwrap_or(false);
                set_expanded(&button, open);
            }
            return;
        }
        if closest(target.clone(), ".lang-menu").is_none() {
            close_lang_menus(None);
        }
        // Mobile menu: the burger toggles it, a link closes it.
        if let Some(burger) = closest(target.clone(), ".burger") {
            if let Some(navbar) = burger.closest(".navbar").ok().flatten() {
                let open = navbar.class_list().toggle("menu-open").unwrap_or(false);
                set_expanded(&burger, open);
            }
            return;
        }
        if closest(target.clone(), ".nav-links a").is_some() {
            close_mobile_menu();
            return;
        }
        // Documentation sidebar on small screens.
        if let Some(toggle) = closest(target.clone(), ".side-toggle") {
            if let Some(sidebar) = toggle.closest(".doc-sidebar").ok().flatten() {
                let open = sidebar.class_list().toggle("open").unwrap_or(false);
                set_expanded(&toggle, open);
            }
            return;
        }
        if closest(target, ".back-to-top").is_some() {
            let options = web_sys::ScrollToOptions::new();
            options.set_top(0.0);
            options.set_behavior(web_sys::ScrollBehavior::Smooth);
            window().scroll_to_with_scroll_to_options(&options);
        }
    });
    on(&doc, "keydown", |e: web_sys::KeyboardEvent| {
        if e.key() == "Escape" {
            close_lang_menus(None);
            close_mobile_menu();
        }
    });
}

/// Soft radial light following the pointer (`--cx`, `--cy`).
fn cursor_glow() {
    let root = root();
    on_passive(&window(), "pointermove", move |e: web_sys::PointerEvent| {
        let style = root.style();
        let _ = style.set_property("--cx", &format!("{}px", e.client_x()));
        let _ = style.set_property("--cy", &format!("{}px", e.client_y()));
    });
}

/// Cards tilt and light up under the pointer (`--mx`, `--my`, `--rx`, `--ry`).
fn tilt() {
    let current: Rc<RefCell<Option<HtmlElement>>> = Rc::default();
    let reset = |card: &HtmlElement| {
        let style = card.style();
        let _ = style.set_property("--rx", "0deg");
        let _ = style.set_property("--ry", "0deg");
    };
    on_passive(
        &document(),
        "pointermove",
        move |e: web_sys::PointerEvent| {
            let card =
                closest(e.target(), ".card-inner").and_then(|c| c.dyn_into::<HtmlElement>().ok());
            let previous = current.borrow().clone();
            if let Some(previous) = previous
                && card
                    .as_ref()
                    .is_none_or(|c| !c.is_same_node(Some(&previous)))
            {
                reset(&previous);
            }
            if let Some(card) = &card {
                let rect = card.get_bounding_client_rect();
                let x = (f64::from(e.client_x()) - rect.left()) / rect.width();
                let y = (f64::from(e.client_y()) - rect.top()) / rect.height();
                let style = card.style();
                let _ = style.set_property("--mx", &format!("{:.1}%", x * 100.0));
                let _ = style.set_property("--my", &format!("{:.1}%", y * 100.0));
                let _ = style.set_property("--rx", &format!("{:.2}deg", (0.5 - y) * 8.0));
                let _ = style.set_property("--ry", &format!("{:.2}deg", (x - 0.5) * 8.0));
            }
            *current.borrow_mut() = card;
        },
    );
}
