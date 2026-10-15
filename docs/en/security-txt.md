---
title: security.txt
summary: Publishes an RFC 9116 security.txt so that researchers can report vulnerabilities, and refuses missing contacts, bad expiries, http links and field injection.
category: integrity
order: 7
---

`/.well-known/security.txt` (RFC 9116) tells security researchers how to report a vulnerability. `SecurityTxt` builds a valid file and refuses the usual mistakes.

## Threats mitigated

- **Unreported vulnerabilities**: a researcher who cannot find a contact goes public, or sells the bug.
- **Stale files**: `Expires` is required, must be in the future and at most a year ahead (regenerate it on every deploy with `expires_in`).
- **Spoofed contacts**: `http://` links are refused, and values cannot contain line breaks that would inject fields.

## Quick start

```rust
use std::time::Duration;
use securite::security_txt::{SecurityTxt, CONTENT_TYPE, PATH};

let txt = SecurityTxt::new()
    .contact("mailto:security@example.com")
    .contact("https://example.com/security")
    .expires_in(Duration::from_secs(180 * 24 * 3600))
    .encryption("https://example.com/pgp-key.txt")
    .preferred_languages(["en", "fr", "es"])
    .canonical("https://example.com/.well-known/security.txt")
    .policy("https://example.com/disclosure-policy")
    .render()?; // Err(MissingContact / MissingExpires / BadExpires / InvalidValue)

app.get(PATH, move |_req: Request| {
    let body = txt.clone();
    async move { ([("content-type", CONTENT_TYPE)], body) }
});
```

## Fields

| Method | Field | Allowed values |
|---|---|---|
| `.contact(uri)` | `Contact` (required, repeatable) | `mailto:`, `tel:`, `https://` |
| `.expires_in(d)` / `.expires_at(t)` | `Expires` (required) | future, at most one year |
| `.encryption(uri)` | `Encryption` | `https://`, `openpgp4fpr:`, `dns:` |
| `.acknowledgments(uri)` | `Acknowledgments` | `https://` |
| `.preferred_languages([...])` | `Preferred-Languages` | language tags |
| `.canonical(uri)` | `Canonical` | `https://` |
| `.policy(uri)` | `Policy` | `https://` |
| `.hiring(uri)` | `Hiring` | `https://` |
| `.csaf(uri)` | `CSAF` | `https://` |

## Pitfalls and tips

- Monitor the contact address: an unanswered report is worse than none.
- Signing the file with OpenPGP (cleartext signature) is optional; do it outside the application if you need it.
- Keep the [host filter](/docs/host-filter) in mind: the file must be reachable on every public host name.

## Related pages

- [Security headers](/docs/security-headers)
- [Signed URLs and tokens](/docs/signed-urls)
