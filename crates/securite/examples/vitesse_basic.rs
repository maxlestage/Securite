//! The simplest possible setup: one line of security.
//!
//! ```sh
//! cargo run --example vitesse_basic
//! curl -i "http://127.0.0.1:3000/"
//! curl -i "http://127.0.0.1:3000/?q=1'%20OR%20'1'='1"   # blocked by the WAF
//! ```

use securite::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    // Security headers, WAF, rate limiting, CSRF, request ids …
    app.middleware(Shield::recommended());
    app.get("/", |_req: Request| async { "Hello, secure world!" });

    println!("listening on http://127.0.0.1:3000");
    app.run("127.0.0.1:3000")
}
