---
title: Two-factor authentication
summary: RFC 6238 time-based one-time passwords compatible with every authenticator app, with replay protection, QR code provisioning and recovery codes.
category: access
order: 8
---

`Totp` implements time-based one-time passwords (RFC 6238), the 6-digit codes of Google Authenticator, Authy, 1Password, Bitwarden or FreeOTP. A second factor stops most account takeovers that start with a leaked, phished or reused password.

## Threats mitigated

- **A07:2021 Identification and Authentication Failures**: accounts protected by a password alone (CWE-308); OWASP ASVS level 2 requires multi-factor authentication.
- **Code replay**: a code seen over a shoulder, in a log or by a phishing proxy is refused once used (RFC 6238 §5.2).
- **Timing leaks**: codes are compared in constant time, every accepted time step is checked without early exit.

## Enrolment

```rust
use securite::totp::{Totp, recovery_codes};

let totp = Totp::generate(); // 160-bit random secret
let uri = totp.provisioning_uri("Example Inc", &user.email);
// otpauth://totp/Example%20Inc:alice%40example.com?secret=JBSWY3DP...&issuer=Example%20Inc
// Render `uri` as a QR code; show `totp.secret_base32()` for manual entry.

// Store the secret (encrypted) with the user only after they typed a valid code:
assert!(totp.verify(&code_typed_by_user));
db.save_totp_secret(user.id, &totp.secret_base32());

// Recovery codes: show them once, store only their hashes.
let codes = recovery_codes(10); // ["k3m7q-2vx9t", ...]
```

## Login

```rust
use securite::totp::Totp;

let totp = Totp::from_base32(&user.totp_secret)?;
match totp.verify_once(&form.code, user.totp_last_step) {
    Some(step) => {
        db.set_totp_last_step(user.id, step); // the same code cannot be used again
        // second factor OK
    }
    None => { /* wrong, expired or replayed code */ }
}
```

`verify_once` refuses every time step up to the one stored at the previous successful login, so a code works only once even within its validity window. Throttle this endpoint with [login throttling](/docs/login-throttle): without a limit, a million combinations fall quickly.

## How it works

- The secret and the current time step (`unix time / 30`) are hashed with HMAC-SHA1 (or SHA-256 / SHA-512), and RFC 4226's dynamic truncation turns the result into 6 to 8 digits. The implementation passes every test vector of RFC 6238.
- One step of clock drift is accepted on each side by default: a code is valid for about 90 seconds.
- Spaces in the typed code are ignored (`123 456`); anything else than ASCII digits of the right length is refused.
- Secrets shorter than 128 bits are refused; `Debug` output never shows the secret, and it is zeroed when the value is dropped.

## Configuration

| Method | Default | Description |
|---|---|---|
| `Totp::generate()` | — | 160-bit secret from the OS CSPRNG. |
| `Totp::new(bytes)` | — | Raw secret; panics under 16 bytes. |
| `Totp::from_base32(s)` | — | Stored secret; case, spaces, dashes and padding ignored. |
| `.algorithm(a)` | `Sha1` | `Sha1`, `Sha256` or `Sha512` (check that your users' apps support them). |
| `.digits(n)` | `6` | 6 to 8. |
| `.period(d)` | 30 s | Length of a time step. |
| `.skew(n)` | `1` | Steps accepted on each side (at most 10). |
| `.verify(code)` / `.verify_at(code, t)` | — | Check without replay protection. |
| `.verify_once(code, last_step)` | — | Check with replay protection; returns the step to store. |
| `.provisioning_uri(issuer, account)` | — | `otpauth://` URI for QR codes. |
| `recovery_codes(n)` | — | `n` single-use codes of 50 random bits. |

## Pitfalls and tips

- Encrypt TOTP secrets at rest: unlike a password hash, the secret must be readable to verify codes.
- Ask for a valid code before enabling 2FA, so a mistyped secret does not lock the user out.
- Hash recovery codes like passwords (for example with [`PasswordHasher`](/docs/passwords)) and delete each one when it is used.
- Keep server clocks synchronised with NTP; widen `skew` only if users report rejected codes.
- TOTP does not stop real-time phishing proxies; WebAuthn / passkeys do. Offer them as well when you can.

## Related pages

- [Login throttling](/docs/login-throttle)
- [Password hashing](/docs/passwords)
- [Authentication](/docs/auth)
