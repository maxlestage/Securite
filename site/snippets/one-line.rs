use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Headers, WAF, rate limiting, CSRF, request ids…
app.middleware(Shield::recommended());
app.get("/", |_req: Request| async { "Hello, secure world!" });
