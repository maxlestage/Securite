---
title: Password policy
summary: NIST SP 800-63B password rules (length, blocklists, context words, no composition rules) and breached-password checks with Have I Been Pwned's k-anonymity API.
category: access
order: 12
---

`PasswordPolicy` checks new passwords the way NIST SP 800-63B and OWASP ASVS ask: long enough, not too common, not derived from the user's name or e-mail, not trivially repetitive or sequential, and not known from breaches. It does **not** impose "one uppercase, one digit, one symbol": those rules produce `Password1!` and are discouraged by NIST.

## Threats mitigated

- **A07:2021 Identification and Authentication Failures**: weak passwords (CWE-521).
- **Credential stuffing**: passwords already leaked elsewhere, refused through Have I Been Pwned.
- **Targeted guessing**: passwords built from the user name, e-mail or site name.

## Quick start

```rust
use securite::password_policy::PasswordPolicy;

let policy = PasswordPolicy::new().context([&form.username, &form.email, "Acme"]);

if let Err(e) = policy.check(&form.password) {
    // e.violations(): TooShort, TooLong, Common, Context, Repetitive, Sequential …
    return Err(format!("Choose another password: {e}"));
}
let hash = hasher.hash(&form.password)?;
```

Every broken rule is returned, each with a readable message (`Display`).

## Breached passwords (Have I Been Pwned)

With k-anonymity only the first 5 hex characters of the password's SHA-1 leave your server. `securite` builds the request and reads the answer; the HTTP call is yours, with any client:

```rust
use securite::password_policy::hibp::RangeQuery;

let query = RangeQuery::new(&form.password);
let body = http_get(&query.url(), [("Add-Padding", "true")]).await?; // your HTTP client
let count = query.count(&body);
policy.check_with_breaches(&form.password, count)?; // Violation::Breached { count }
```

If the API is unreachable, decide explicitly: refuse the change, or accept it and check again at the next login.

## Rules

| Rule | Default |
|---|---|
| Minimum length | 12 characters (`min_length`, at least 8) |
| Maximum length | 128 characters (`max_length`, at least 64), bounds hashing cost |
| Common passwords | ~200 of the most common, also with digits and symbols around them |
| Context words | `context([...])`: words of 4+ characters, case-insensitive; the local part of e-mails too |
| Repetitive | Too few distinct characters (`aaaaaaaaaaaa`, `abababababab`) |
| Sequential | Mostly one alphabet, digit or keyboard run (`abcdefgh`, `12345678`, `qwertyui`, `azertyui`) |
| Custom blocklist | `blocklist([...])` |

Length is counted in characters, not bytes: every Unicode character and spaces are allowed, so pass phrases work.

## Pitfalls and tips

- Check the policy on sign-up and password change, never on login (old passwords must still log in, then be changed).
- Show all violations at once, and a strength hint, rather than one error at a time.
- Never log the password or the `RangeQuery` suffix (its `Debug` hides it).

## Related pages

- [Password hashing](/docs/passwords)
- [Login throttling](/docs/login-throttle)
- [Two-factor authentication](/docs/two-factor)
