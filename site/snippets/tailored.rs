use securite::prelude::*;
use std::time::Duration;

let shield = Shield::builder()
    .client_ip(ClientIpSource::heroku())
    .guard(SecurityHeaders::strict().csp(ContentSecurityPolicy::strict().with_nonce()))
    .guard(RateLimit::per_second(20).route("/login", Quota::per_minute(5)))
    .guard(Waf::new().paranoia(Paranoia::Medium))
    .guard(AutoBan::new().max_strikes(10).ban_for(Duration::from_secs(900)))
    .guard(Auth::bearer().token("ci", "s3cr3t-token").protect(["/admin"]))
    .on_event(|e| tracing::warn!(guard = e.guard, ip = ?e.client_ip, "blocked"))
    .build();

app.middleware(shield);
