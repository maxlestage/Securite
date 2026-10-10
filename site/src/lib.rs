//! The securite website, written with [active](https://github.com/maxlestage/Active).
//!
//! - Natively, [`render`] renders every page (complete SEO, islands), the web app
//!   manifest and the service worker; `securite-server` serves them behind its own
//!   `securite` shield and exports them as static files for GitHub Pages.
//! - Compiled to WebAssembly, this crate is the browser bundle: it hydrates the
//!   [`islands`] and runs the page motion (scroll reveals, particles, cursor glow…).

pub mod docs;
pub mod i18n;
pub mod icons;
pub mod islands;
pub mod routes;

#[cfg(not(target_arch = "wasm32"))]
pub mod render;

#[cfg(target_arch = "wasm32")]
mod client;
