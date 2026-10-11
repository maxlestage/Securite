---
title: Bot blocker
summary: Drops requests from well-known vulnerability scanners and attack tools by their User-Agent, a cheap filter that removes most automated noise.
category: threats
order: 2
---

A public endpoint receives a constant stream of automated reconnaissance: sqlmap, nikto, nuclei, wpscan, gobuster and friends probing for known vulnerabilities and forgotten files. Most of these tools announce themselves in the `User-Agent` header. `BotBlocker` rejects them with `403 Forbidden` before they reach the WAF and your handlers, which keeps your logs readable and your servers busy with real users.

## Threats mitigated

- Automated vulnerability scanning and footprinting (OWASP Automated Threats OAT-014 and OAT-018), the reconnaissance that precedes the exploitation of A05:2021 Security Misconfiguration and A06:2021 Vulnerable and Outdated Components.
- Off-the-shelf brute-force tools such as hydra (OAT-007 Credential Cracking, A07:2021 Identification and Authentication Failures).
- Optionally, scripts that do not send any `User-Agent` at all.

> **Warning:** The `User-Agent` header is entirely controlled by the client. Any attacker can pretend to be Firefox in one line of code. The bot blocker is a noise filter that removes careless and automated traffic; it is not a security boundary. Real protection comes from the WAF, rate limiting, auto-ban and authentication.

## How it works

1. The guard reads the `User-Agent` header.
2. The allow list is checked first: a match lets the request through.
3. The deny list is matched as case-insensitive substrings, all patterns at once, with a single Aho-Corasick automaton. The cost does not depend on the number of patterns.
4. On a match, the request is rejected with `403`, code `bot_blocked` and the message `Automated clients are not allowed.` The matched pattern is recorded in the audit details only, for example `user-agent matched "sqlmap"`.
5. A request without a `User-Agent` header goes through, unless `block_empty(true)` is set.

The guard runs after the rate limiter and before the WAF.

## The default deny list

`BotBlocker::new()` blocks the fragments listed in `securite::user_agent::DEFAULT_DENY`:

```text
sqlmap, nikto, nmap, masscan, zgrab, nuclei, acunetix, netsparker,
wpscan, joomscan, dirbuster, gobuster, dirb/, feroxbuster, ffuf, wfuzz,
hydra, havij, w3af, openvas, arachni, skipfish, commix, xsstrike,
jaeles, whatweb, zmeu, morfeus, fimap, nessus, qualys, burpcollaborator,
interactsh, censysinspect, "httpx - open-source",
"go-http-client/1.1 (scanner"
```

## Quick start

`BotBlocker::new()` is part of the `recommended`, `strict` and `api` presets. To use it in your own shield:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::builder().guard(BotBlocker::new()).build());
app.get("/", |_req: Request| async { "home" });
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `BotBlocker::new()` | `DEFAULT_DENY` | Blocks the well-known tools listed above. |
| `BotBlocker::empty()` | empty deny list | Starts without any pattern: only yours apply. |
| `.deny(patterns)` | none | Adds deny patterns (case-insensitive substrings). |
| `.allow(patterns)` | none | Patterns that are always allowed, checked before the deny list. |
| `.block_empty(bool)` | `false` | Rejects requests without a `User-Agent` header. |
| `.monitor()` | enforce | Reports matches without blocking. |
| `.check(&str)` | — | Returns the matched deny pattern, if any (`Option<&str>`). |

## Examples

### Browser-only website

A marketing site or a server-rendered application has no reason to serve generic HTTP libraries:

```rust
use securite::prelude::*;

let bots = BotBlocker::new()
    // Generic HTTP clients: fine for a browser-only site, not for a public API.
    .deny(["python-requests", "curl/", "go-http-client", "libwww-perl"])
    .block_empty(true);
```

### Your own security scanner

```rust
use securite::prelude::*;

let bots = BotBlocker::new()
    // Our weekly authenticated scan announces itself with this marker.
    .allow(["acme-security-audit/"]);
```

### Only your own patterns

```rust
use securite::prelude::*;

let bots = BotBlocker::empty().deny(["badbot", "evil-crawler"]);
```

### Testing a User-Agent

```rust
use securite::prelude::*;

let bots = BotBlocker::new();
assert_eq!(bots.check("sqlmap/1.7.2#stable (https://sqlmap.org)"), Some("sqlmap"));
assert_eq!(bots.check("Mozilla/5.0 (compatible; Nmap Scripting Engine)"), Some("nmap"));
assert!(bots.check("Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0").is_none());
```

### Monitor first

Before denying generic clients on an existing service, find out who actually uses them:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(BotBlocker::new().deny(["python-requests"]).monitor())
    .build();
```

## Standalone guard

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(BotBlocker::new().block_empty(true)));
app.get("/", |_req: Request| async { "home" });
```

## Pitfalls and tips

- Matching is by substring: a short pattern catches more than you think. `curl` would also match `curling-club-app/2.0`; prefer `curl/`.
- Allow-list entries can be copied by anyone who knows them. They only bypass the bot blocker, not the WAF or rate limiting; restrict your own scanners by IP address too.
- `block_empty(true)` only rejects requests without a `User-Agent` header. Check that your load balancer health checks, uptime monitors and webhook providers send one before enabling it.
- Some organisations run Qualys or Nessus for compliance scans. Add `.allow(["qualys"])` or `.allow(["nessus"])` if your own scans must go through.
- With `AutoBan` in the same shield, every block counts as a strike: a scanner that keeps trying ends up banned by IP address, including for its requests with a forged browser `User-Agent`.

## Related pages

- [Web application firewall](/docs/waf)
- [Rate limiting](/docs/rate-limit)
- [Auto-ban](/docs/auto-ban)
- [Security events and statistics](/docs/events-stats)
