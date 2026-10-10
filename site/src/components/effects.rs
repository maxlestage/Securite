//! Global visual effects: scroll progress, cursor glow, back-to-top and the
//! particle network of the hero.

use std::cell::RefCell;
use std::rc::Rc;

use gloo::events::EventListener;
use gloo::render::{AnimationFrame, request_animation_frame};
use wasm_bindgen::JsCast;
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement};
use yew::prelude::*;

use crate::icons::Icon;

fn root_style() -> Option<web_sys::CssStyleDeclaration> {
    web_sys::window()?
        .document()?
        .document_element()?
        .dyn_into::<web_sys::HtmlElement>()
        .ok()
        .map(|e| e.style())
}

/// Thin gradient bar showing the reading progress.
#[component]
pub fn ScrollProgress() -> Html {
    use_effect_with((), |_| {
        let window = web_sys::window().unwrap();
        let update = {
            let window = window.clone();
            move || {
                let doc = window.document().unwrap().document_element().unwrap();
                let max = f64::from(doc.scroll_height() - doc.client_height()).max(1.0);
                let y = window.scroll_y().unwrap_or(0.0);
                if let Some(style) = root_style() {
                    let _ = style
                        .set_property("--scroll", &format!("{:.4}", (y / max).clamp(0.0, 1.0)));
                    let _ = style.set_property("--scrolled", if y > 24.0 { "1" } else { "0" });
                }
            }
        };
        update();
        let listener = EventListener::new(&window, "scroll", move |_| update());
        move || drop(listener)
    });
    html! { <div class="scroll-progress" aria-hidden="true"></div> }
}

/// Soft radial light following the pointer.
#[component]
pub fn CursorGlow() -> Html {
    use_effect_with((), |_| {
        let window = web_sys::window().unwrap();
        let listener = EventListener::new(&window, "pointermove", |e| {
            let e = e.dyn_ref::<web_sys::MouseEvent>().unwrap();
            if let Some(style) = root_style() {
                let _ = style.set_property("--cx", &format!("{}px", e.client_x()));
                let _ = style.set_property("--cy", &format!("{}px", e.client_y()));
            }
        });
        move || drop(listener)
    });
    html! { <div class="cursor-glow" aria-hidden="true"></div> }
}

/// Floating button appearing after some scrolling.
#[component]
pub fn BackToTop() -> Html {
    let onclick = Callback::from(|_| {
        if let Some(w) = web_sys::window() {
            let opts = web_sys::ScrollToOptions::new();
            opts.set_top(0.0);
            opts.set_behavior(web_sys::ScrollBehavior::Smooth);
            w.scroll_to_with_scroll_to_options(&opts);
        }
    });
    html! {
        <button class="back-to-top" {onclick} aria-label="Back to top">
            <Icon name="arrow-up" />
        </button>
    }
}

struct Particle {
    x: f64,
    y: f64,
    vx: f64,
    vy: f64,
    r: f64,
}

struct Scene {
    particles: Vec<Particle>,
    width: f64,
    height: f64,
    mouse: (f64, f64),
}

fn rand() -> f64 {
    js_sys::Math::random()
}

fn frame(
    canvas: HtmlCanvasElement,
    ctx: CanvasRenderingContext2d,
    scene: Rc<RefCell<Scene>>,
    handle: Rc<RefCell<Option<AnimationFrame>>>,
) {
    {
        let mut s = scene.borrow_mut();
        let (w, h, (mx, my)) = (s.width, s.height, s.mouse);
        ctx.clear_rect(0.0, 0.0, w, h);
        for p in &mut s.particles {
            p.x += p.vx;
            p.y += p.vy;
            if p.x < 0.0 || p.x > w {
                p.vx = -p.vx;
            }
            if p.y < 0.0 || p.y > h {
                p.vy = -p.vy;
            }
            // Gentle attraction towards the pointer.
            let (dx, dy) = (mx - p.x, my - p.y);
            let d2 = dx * dx + dy * dy;
            if d2 < 160.0 * 160.0 && d2 > 1.0 {
                p.x += dx * 0.004;
                p.y += dy * 0.004;
            }
        }
        let n = s.particles.len();
        for i in 0..n {
            for j in (i + 1)..n {
                let (a, b) = (&s.particles[i], &s.particles[j]);
                let d = ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt();
                if d < 120.0 {
                    let alpha = (1.0 - d / 120.0) * 0.35;
                    ctx.set_stroke_style_str(&format!("rgba(125, 211, 252, {alpha:.3})"));
                    ctx.set_line_width(0.7);
                    ctx.begin_path();
                    ctx.move_to(a.x, a.y);
                    ctx.line_to(b.x, b.y);
                    ctx.stroke();
                }
            }
        }
        for p in &s.particles {
            ctx.set_fill_style_str("rgba(167, 139, 250, 0.85)");
            ctx.begin_path();
            let _ = ctx.arc(p.x, p.y, p.r, 0.0, std::f64::consts::TAU);
            ctx.fill();
        }
    }
    let next = {
        let (canvas, ctx, scene, handle2) =
            (canvas.clone(), ctx.clone(), scene.clone(), handle.clone());
        request_animation_frame(move |_| frame(canvas, ctx, scene, handle2))
    };
    *handle.borrow_mut() = Some(next);
}

/// Animated particle network (canvas, pure Rust).
#[component]
pub fn Particles() -> Html {
    let canvas_ref = use_node_ref();
    {
        let canvas_ref = canvas_ref.clone();
        use_effect_with((), move |_| {
            let handle: Rc<RefCell<Option<AnimationFrame>>> = Rc::new(RefCell::new(None));
            let mut listeners = Vec::new();
            if let Some(canvas) = canvas_ref.cast::<HtmlCanvasElement>()
                && !crate::hooks::prefers_reduced_motion()
            {
                let window = web_sys::window().unwrap();
                let dpr = window.device_pixel_ratio().max(1.0);
                let rect = canvas.get_bounding_client_rect();
                let (w, h) = (rect.width().max(320.0), rect.height().max(320.0));
                canvas.set_width((w * dpr) as u32);
                canvas.set_height((h * dpr) as u32);
                let ctx: CanvasRenderingContext2d = canvas
                    .get_context("2d")
                    .ok()
                    .flatten()
                    .unwrap()
                    .unchecked_into();
                let _ = ctx.scale(dpr, dpr);
                let count = ((w * h) / 16000.0).clamp(30.0, 90.0) as usize;
                let particles = (0..count)
                    .map(|_| Particle {
                        x: rand() * w,
                        y: rand() * h,
                        vx: (rand() - 0.5) * 0.45,
                        vy: (rand() - 0.5) * 0.45,
                        r: 1.0 + rand() * 1.6,
                    })
                    .collect();
                let scene = Rc::new(RefCell::new(Scene {
                    particles,
                    width: w,
                    height: h,
                    mouse: (-1000.0, -1000.0),
                }));
                {
                    let scene = scene.clone();
                    let canvas2 = canvas.clone();
                    listeners.push(EventListener::new(&window, "pointermove", move |e| {
                        let e = e.dyn_ref::<web_sys::MouseEvent>().unwrap();
                        let r = canvas2.get_bounding_client_rect();
                        scene.borrow_mut().mouse = (
                            f64::from(e.client_x()) - r.left(),
                            f64::from(e.client_y()) - r.top(),
                        );
                    }));
                }
                frame(canvas, ctx, scene, handle.clone());
            }
            move || {
                handle.borrow_mut().take();
                drop(listeners);
            }
        });
    }
    html! { <canvas ref={canvas_ref} class="particles" aria-hidden="true"></canvas> }
}
