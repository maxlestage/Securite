---
title: Monitor mode
summary: Run guards in report-only mode to measure false positives, then switch to blocking with confidence; the safe way to roll out a WAF or a strict CSP.
category: start
order: 7
---

Turning on a WAF or a strict Content-Security-Policy in front of an existing application is risky: one false positive can block a checkout page or a partner integration. Monitor mode lets a guard report what it *would* have blocked while letting traffic through, so you can tune it against real traffic before enforcing it.

## Enforce and Monitor

Every guard has a `Mode`:

| Mode | When the guard detects a violation |
|---|---|
| `Mode::Enforce` (default) | The request is rejected, a `WARN` event `request blocked` is logged, `blocked` is incremented |
| `Mode::Monitor` | The request continues to the next guards and your handler, an `INFO` event `violation (monitor mode)` is logged, `monitored` is incremented |

In both cases the shield emits a `SecurityEvent` with the same guard, code, status and details; only its `enforced` field differs. A monitored violation does not disable the other guards: an enforcing rate limiter still blocks floods while the WAF is under observation.

## Guards that support monitoring

| Guard | `.monitor()` | Behaviour in monitor mode |
|---|---|---|
| `Waf` | Yes | Attacks are reported with score, rule ids and categories, and reach the handler |
| `RateLimit` | Yes | Over-limit requests pass; responses still show `RateLimit-Remaining: 0` |
| `ConcurrencyLimit` | Yes | Excess concurrent requests pass and are reported |
| `AutoBan` | Yes | Strikes and bans are computed and logged, banned clients are not blocked |
| `IpFilter` | Yes | Denied addresses pass and are reported |
| `HostFilter` | Yes | Unknown `Host` values pass and are reported |
| `BotBlocker` | Yes | Matching user agents pass and are reported |
| `Csrf` | Yes | Cross-site state-changing requests pass and are reported |
| `SecurityHeaders` | No | Use a report-only CSP instead (below) |
| Other built-in guards | No | `Auth`, `Hygiene`, `MethodFilter`, `BodyLimit`, `ContentTypeGuard`, `HttpsRedirect`, `Cors`, `RequestId` and `CookieHardening` always enforce |

`.monitor()` is a builder method, so it chains with the rest of the configuration: `Waf::new().paranoia(Paranoia::Medium).monitor()`. Your own guards opt in by returning `Mode::Monitor` from `mode()`, see [Custom guards](/docs/custom-guards).

## Report-only CSP

`ContentSecurityPolicy::report_only()` sends `Content-Security-Policy-Report-Only` instead of the enforcing header. Browsers then report violations without blocking anything:

```rust
use securite::headers::src;
use securite::prelude::*;

let csp = ContentSecurityPolicy::strict()
    .img_src([src::SELF, src::DATA, "https://images.example.com"])
    .report_uri(["/csp-reports"])
    .report_only();

let shield = ShieldBuilder::recommended()
    .guard(SecurityHeaders::new().csp(csp))
    .guard(Csrf::new().exempt("/csp-reports"))
    .build();
```

Browsers post reports with `application/csp-report` or `application/reports+json`. Exempt the endpoint from CSRF as above, and if your shield contains a `ContentTypeGuard`, allow those media types or skip the path with `.skip("/csp-reports")`.

## A progressive rollout

1. **Observe.** Deploy the WAF with `.monitor()` and the CSP with `.report_only()`. Nothing is blocked yet.
2. **Wait for representative traffic.** A full business cycle, usually one or two weeks, including batch jobs, mobile clients and partner integrations.
3. **Triage.** Each monitored WAF event carries `details` such as `score=… rules=[…] categories=…`. For every false positive, fix the application, skip the path or header (`skip_paths`, `skip_headers`), disable the rule (`disable_rules`) or raise the `threshold`.
4. **Enforce.** Remove `.monitor()`, or switch to the enforcing CSP, and keep alerting on events. Enforcing on one instance first works as a canary.
5. **Tighten.** Raise the paranoia level or narrow the CSP, and repeat the cycle.

An environment variable lets you switch modes without a code change:

```rust
use securite::prelude::*;

// WAF_ENFORCE=1 switches from observation to blocking.
let enforce = std::env::var("WAF_ENFORCE").is_ok_and(|v| v == "1");

let waf = Waf::new()
    .paranoia(Paranoia::Medium)
    .disable_rules([119]) // "sleep(" matched legitimate search queries
    .skip_paths(["/webhooks"]);
let waf = if enforce { waf } else { waf.monitor() };

let shield = ShieldBuilder::recommended().guard(waf).build();
```

> **Warning:** A guard in monitor mode does not protect you: attacks reach your handlers. Keep observation periods short, keep the other guards enforcing and make sure someone actually reads the reports.

## Observing violations

### Event hook

`on_event` receives every event; `enforced` is `false` for monitored ones:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(Waf::new().monitor())
    .on_event(|e| {
        if !e.enforced {
            eprintln!(
                "[monitor] {} {} {} {} would return {} ({})",
                e.guard,
                e.code,
                e.method,
                e.path,
                e.status,
                e.details.unwrap_or("-"),
            );
        }
    })
    .build();
```

### tracing

With `log_events` enabled (the default), events are written under the `securite` target, with the fields `guard`, `code`, `status`, `ip`, `method`, `path`, `request_id` and `details`. Monitored violations are logged at `INFO`, blocks at `WARN`; a filter such as `RUST_LOG=securite=info` shows both.

### Statistics

`shield.stats()` counts monitored violations separately from blocks:

```rust
let stats = shield.stats();
println!(
    "{} requests, {} blocked, {} would have been blocked",
    stats.total, stats.blocked, stats.monitored,
);
println!("{}", stats.to_json());
// {"total":1200,"allowed":1198,"blocked":2,"monitored":37,"by_guard":{"request_id":0,
//  "hygiene":0,"method":0,"body_limit":0,"rate_limit":2,"bot_blocker":0,"waf":37,
//  "csrf":0,"security_headers":0,"cookies":0}}
```

`by_guard` adds blocked and monitored violations per guard. Counters live in memory and restart from zero with the process; export them regularly (see [Events and stats](/docs/events-stats)).

> **Tip:** Monitored requests count as `allowed`, since they did go through. `monitored` is exactly the number of requests enforcement would have refused, legitimate or not: compare it with the attacks you actually identified before switching.
