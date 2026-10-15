---
title: Access control
summary: Symfony-style access_control rules by URL and method, a role hierarchy shared with the Gate, and path canonicalisation that defeats encoding bypasses.
category: access
order: 10
---

`AccessControl` checks roles by URL **before** your handlers run, like Symfony's `access_control`. Rules are tried in order and the first one whose path prefix (and method) matches decides. A `RoleHierarchy` says which roles include which others, and the same hierarchy drives `RoleVoter` in the [Gate](/docs/authorization).

## Threats mitigated

- **A01:2021 Broken Access Control**: forgotten checks on admin routes (CWE-862) and privilege escalation (CWE-269).
- **Path confusion bypasses**: `/ADMIN`, `/%61dmin`, `/%2561dmin`, `//admin`, `/public/../admin`, `/x\..\admin`, `/admin;jsessionid=1` or `/admin%2fusers` are all canonicalised to `/admin/…` before the rules are checked.
- **Default allow**: `deny_unmatched()` turns the rules into an allow-list.

## Quick start

```rust
use http::Method;
use securite::access::{Access, AccessControl, RoleHierarchy};
use securite::prelude::*;

let hierarchy = RoleHierarchy::new()
    .inherit("ROLE_ADMIN", ["ROLE_EDITOR"])
    .inherit("ROLE_EDITOR", ["ROLE_USER"]);

let access = AccessControl::new()
    .hierarchy(hierarchy)
    .public("/login")
    .public("/assets")
    .require_role("/admin", "ROLE_ADMIN")
    .rule_for([Method::POST, Method::PUT, Method::DELETE], "/api/posts", Access::any_role(["ROLE_EDITOR"]))
    .authenticated("/api")
    .deny_unmatched();

let shield = Shield::builder()
    .guard(Auth::jwt(validator).public(["/login", "/assets"])) // or Sessions, or Auth::bearer().grant(…)
    .guard(access)
    .build();
```

Anonymous requests on a protected path get `401 unauthenticated`; authenticated ones without the role get `403 forbidden`. The rule that refused is written in the audit log only.

## Where roles come from

`AccessControl` reads two request extensions, put there by the guards that run before it:

| Source | Extension |
|---|---|
| `Auth::jwt` | `Principal` and `Roles` from the roles claim |
| `Auth::bearer().token("ci", …).grant("ci", ["ROLE_DEPLOY"])` | `Principal` and `Roles` |
| `Sessions` | `Principal` (the session user) |
| Your own guard (priority below 145) | `req.extensions.insert(Roles::new([...]))` |

A request is authenticated when it has a `Principal` or `Roles`.

## Rules

| Method | Requirement |
|---|---|
| `.public(prefix)` | Anyone (`PUBLIC_ACCESS`). |
| `.authenticated(prefix)` | Any authenticated user. |
| `.require_role(prefix, role)` | The role, directly or through the hierarchy. |
| `.rule(prefix, Access::any_role([...]))` / `Access::all_roles([...])` | One of / all of the roles. |
| `.deny(prefix)` | Nobody. |
| `.rule_for(methods, prefix, access)` | Only for these methods. |
| `.deny_unmatched()` / `.authenticate_unmatched()` | What happens when no rule matches (default: allowed). |
| `.monitor()` | Logs refusals without blocking. |

Prefixes cover whole segments: `/admin` covers `/admin` and `/admin/users`, not `/administrator`. Matching ignores ASCII case.

## Roles in the Gate

```rust
use securite::authz::Gate;

let gate = Gate::<User>::new()
    .roles(hierarchy.clone(), |u: &User| u.roles.clone())
    .define_for("edit-post", |u, p: &Post| p.author == u.id);

gate.allows(&user, "ROLE_EDITOR"); // true for an admin, through the hierarchy
```

## Pitfalls and tips

- Put specific rules **before** general ones: the first match wins (`/admin/login` public before `/admin`).
- URL rules protect routes, not objects: keep [authorization](/docs/authorization) for "may this user edit *this* post".
- Hierarchies only grant downwards: `ROLE_USER` never gets `ROLE_ADMIN`; cycles are harmless.

## Related pages

- [Authorization](/docs/authorization)
- [JWT and JWKS](/docs/jwt)
- [Sessions](/docs/sessions)
