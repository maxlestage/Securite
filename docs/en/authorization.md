---
title: Authorization
summary: Gates, policies and voters in the spirit of Laravel and Symfony, deny by default, to decide what each user may do with each resource.
category: access
order: 7
---

Authentication tells you *who* is calling; authorization decides *what* they may do, and on *which* record. `Gate` centralises those rules: abilities without a resource (`"create-post"`), policies on a resource type (`"edit-post"` on a `Post`), and voters that group the rules of a domain. It combines Laravel's `Gate::define` / `Gate::before` with Symfony's voters and decision strategies.

## Threats mitigated

- **A01:2021 Broken Access Control**, the most frequent web risk: insecure direct object references (changing `/invoices/42` into `/invoices/43`), privilege escalation, missing checks on one of many handlers (CWE-284, CWE-639, CWE-862).
- **Fail-open rules**: an ability nobody defined, a resource of an unexpected type or a decision where every voter abstains is a refusal.

## Quick start

```rust
use securite::prelude::*;

struct User { id: u64, admin: bool }
struct Post { author: u64, published: bool }

let gate = Gate::<User>::new()
    // Administrators may do everything.
    .before(|user, _ability| user.admin.then_some(true))
    .define("create-post", |_user| true)
    .define_for("edit-post", |user, post: &Post| post.author == user.id)
    .define_for("view-post", |user, post: &Post| post.published || post.author == user.id);

// In a handler:
let post = load_post(id)?;
gate.authorize_for(&user, "edit-post", &post)?; // Err(Forbidden) when refused
```

Build the gate once at startup and share it (it is `Clone`, `Send` and `Sync`).

## How a decision is made

1. **`before` hooks** run first, in order. `Some(true)` grants, `Some(false)` denies (a banned user), `None` lets the rules decide.
2. **Rules** defined for the ability vote: `define` rules only vote without a resource, `define_for::<R>` rules only vote on a resource of type `R`. Otherwise they abstain.
3. **Voters** vote on every ability; they abstain on what they do not handle.
4. The **strategy** combines the votes. If every vote abstains, the answer is no.

| Strategy | Granted when |
|---|---|
| `Affirmative` (default) | at least one vote grants |
| `Consensus` | more votes grant than deny (a tie denies) |
| `Unanimous` | no vote denies and at least one grants |

## Voters

A voter keeps the rules of one resource type together, like a Symfony voter or a Laravel policy class:

```rust
use std::any::Any;
use securite::authz::{Gate, Strategy, Vote, Voter};

struct InvoiceVoter;

impl Voter<User> for InvoiceVoter {
    fn vote(&self, user: &User, ability: &str, resource: Option<&dyn Any>) -> Vote {
        let Some(invoice) = resource.and_then(|r| r.downcast_ref::<Invoice>()) else {
            return Vote::Abstain;
        };
        match ability {
            "invoice.view" => (invoice.owner == user.id).into(),
            "invoice.refund" => (invoice.owner == user.id && !invoice.refunded).into(),
            _ => Vote::Abstain,
        }
    }
}

let gate = Gate::new()
    .voter(InvoiceVoter)
    .voter(AccountFrozenVoter) // denies everything for frozen accounts
    .strategy(Strategy::Unanimous);
```

With `Unanimous`, one `Deny` wins over any number of grants, which suits rules such as "frozen accounts may not do anything".

## Refusals

`authorize` and `authorize_for` return `Result<(), Forbidden>`. `Forbidden::into_rejection()` turns the error into a `403` [problem response](/docs/error-format) with code `forbidden`; the refused ability is logged in the details and never sent to the client. You can also map `Forbidden` to your own error type, or answer `404` instead of `403` to hide that a record exists.

## API

| Method | Description |
|---|---|
| `Gate::new()` | Empty gate: everything is denied. |
| `.before(f)` | `Fn(&U, &str) -> Option<bool>` run before the rules. |
| `.define(ability, f)` | `Fn(&U) -> bool`, for abilities without a resource. |
| `.define_for(ability, f)` | `Fn(&U, &R) -> bool`, for abilities on a resource of type `R`. |
| `.voter(v)` | Adds a `Voter<U>`. |
| `.strategy(s)` | `Affirmative`, `Consensus` or `Unanimous`. |
| `.allow_if_all_abstain(b)` | Grants when everyone abstains (off by default). |
| `.allows` / `.allows_for` / `.denies` | `bool`. |
| `.any(user, abilities)` / `.all(user, abilities)` | Several abilities without a resource. |
| `.authorize` / `.authorize_for` | `Result<(), Forbidden>`. |
| `.abilities()` | Names of the defined abilities. |

## Pitfalls and tips

- Check authorization on **every** handler that reads or changes a record, including JSON APIs and background exports; load the record first and pass it to the gate.
- The resource type must match exactly: `define_for::<Post>` does not vote on a `&Post` passed as `&&Post`, nor on an `Arc<Post>`; it abstains, which denies.
- Keep `before` hooks short and explicit: a broad `Some(true)` is a skeleton key.
- Rules run synchronously: load what they need (roles, team memberships) before calling the gate.

## Related pages

- [Authentication](/docs/auth)
- [Password hashing](/docs/passwords)
- [Signed URLs](/docs/signed-urls)
- [Error format](/docs/error-format)
