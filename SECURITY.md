# Security policy

`securite` is a security library: we take vulnerabilities very seriously.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Please do not open a public issue.** Write to the author privately (the contact
details are on the crates.io page of `securite`). Include a description, the affected version, a proof of concept if possible
and the impact you foresee. You will get an acknowledgement within 72 hours
and a fix or mitigation plan within 14 days. Fixed vulnerabilities are
published in the changelog and to the RustSec advisory database.

## Scope

* WAF bypasses (a payload from the built-in rule categories that is not
  detected) are welcome as regular issues unless they lead to a concrete
  exploit in the library itself.
* Denial of service of the library (panics, unbounded memory, algorithmic
  complexity) is in scope.
