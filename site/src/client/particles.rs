//! The animated particle network behind the hero (canvas, pure Rust).

use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement};

use super::{on_passive, request_frame, window};

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
    /// The canvas is on screen (no drawing while scrolled away).
    visible: bool,
}

fn rand() -> f64 {
    js_sys::Math::random()
}

fn draw(ctx: &CanvasRenderingContext2d, s: &mut Scene) {
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
    ctx.set_line_width(0.7);
    let n = s.particles.len();
    for i in 0..n {
        for j in (i + 1)..n {
            let (a, b) = (&s.particles[i], &s.particles[j]);
            let d = ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt();
            if d < 120.0 {
                let alpha = (1.0 - d / 120.0) * 0.35;
                ctx.set_stroke_style_str(&format!("rgba(125, 211, 252, {alpha:.3})"));
                ctx.begin_path();
                ctx.move_to(a.x, a.y);
                ctx.line_to(b.x, b.y);
                ctx.stroke();
            }
        }
    }
    ctx.set_fill_style_str("rgba(167, 139, 250, 0.85)");
    for p in &s.particles {
        ctx.begin_path();
        let _ = ctx.arc(p.x, p.y, p.r, 0.0, std::f64::consts::TAU);
        ctx.fill();
    }
}

/// Starts the network on every `canvas.particles` of the page.
pub fn start() {
    for el in super::all("canvas.particles") {
        let Ok(canvas) = el.dyn_into::<HtmlCanvasElement>() else {
            continue;
        };
        let Some(ctx) = canvas
            .get_context("2d")
            .ok()
            .flatten()
            .and_then(|c| c.dyn_into::<CanvasRenderingContext2d>().ok())
        else {
            continue;
        };
        let dpr = window().device_pixel_ratio().max(1.0);
        let rect = canvas.get_bounding_client_rect();
        let (w, h) = (rect.width().max(320.0), rect.height().max(320.0));
        canvas.set_width((w * dpr) as u32);
        canvas.set_height((h * dpr) as u32);
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
            visible: true,
        }));
        {
            let (scene, canvas) = (scene.clone(), canvas.clone());
            on_passive(&window(), "pointermove", move |e: web_sys::PointerEvent| {
                let r = canvas.get_bounding_client_rect();
                scene.borrow_mut().mouse = (
                    f64::from(e.client_x()) - r.left(),
                    f64::from(e.client_y()) - r.top(),
                );
            });
        }
        {
            let (scene, canvas) = (scene.clone(), canvas.clone());
            on_passive(&window(), "scroll", move |_: web_sys::Event| {
                let r = canvas.get_bounding_client_rect();
                scene.borrow_mut().visible = r.bottom() > 0.0;
            });
        }
        request_frame(move |_| {
            let mut s = scene.borrow_mut();
            if s.visible {
                draw(&ctx, &mut s);
            }
            true
        });
    }
}
