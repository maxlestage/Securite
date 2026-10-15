//! Authorization: **gates**, **policies** and **voters**, after Laravel's
//! `Gate` and Symfony's security voters.
//!
//! Authentication tells *who* the user is ([`Auth`](crate::auth::Auth), your
//! session); authorization decides *what* they may do with *which* resource.
//! Centralising those rules in a [`Gate`] instead of scattering `if` checks
//! through handlers is the main defence against OWASP's #1 risk, broken access
//! control (IDOR, privilege escalation).
//!
//! A gate is **deny by default**: an ability nobody defined, a resource of an
//! unexpected type, or a decision where every voter abstains is a refusal.
//!
//! ```
//! use securite::authz::{Gate, Vote, Voter};
//!
//! struct User { id: u64, admin: bool }
//! struct Post { author: u64, published: bool }
//!
//! let gate = Gate::<User>::new()
//!     // Super administrators may do everything (Laravel's `Gate::before`).
//!     .before(|user, _ability| user.admin.then_some(true))
//!     // An ability without a resource.
//!     .define("create-post", |_user| true)
//!     // An ability on a resource type: a policy rule.
//!     .define_for("edit-post", |user, post: &Post| post.author == user.id)
//!     .define_for("view-post", |user, post: &Post| post.published || post.author == user.id);
//!
//! let alice = User { id: 1, admin: false };
//! let post = Post { author: 2, published: false };
//!
//! assert!(gate.allows(&alice, "create-post"));
//! assert!(!gate.allows_for(&alice, "edit-post", &post));
//! assert!(gate.authorize_for(&alice, "view-post", &post).is_err());
//! assert!(gate.allows_for(&User { id: 9, admin: true }, "edit-post", &post));
//! assert!(!gate.allows(&alice, "delete-everything"), "undefined: denied");
//! ```

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use http::StatusCode;

use crate::Rejection;
use crate::access::RoleHierarchy;

/// A voter's answer (Symfony's `ACCESS_GRANTED`, `ACCESS_DENIED`,
/// `ACCESS_ABSTAIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote {
    /// Grants access.
    Grant,
    /// Denies access.
    Deny,
    /// This voter does not handle the ability or the resource.
    Abstain,
}

impl From<bool> for Vote {
    fn from(allowed: bool) -> Self {
        if allowed { Vote::Grant } else { Vote::Deny }
    }
}

/// Decides on abilities for a family of resources. Implement it to group
/// the rules of one resource type in one place (Symfony voter, Laravel
/// policy).
///
/// ```
/// use std::any::Any;
/// use securite::authz::{Gate, Vote, Voter};
///
/// struct User { id: u64 }
/// struct Invoice { owner: u64, paid: bool }
///
/// struct InvoiceVoter;
///
/// impl Voter<User> for InvoiceVoter {
///     fn vote(&self, user: &User, ability: &str, resource: Option<&dyn Any>) -> Vote {
///         let Some(invoice) = resource.and_then(|r| r.downcast_ref::<Invoice>()) else {
///             return Vote::Abstain;
///         };
///         match ability {
///             "invoice.view" => (invoice.owner == user.id).into(),
///             "invoice.refund" => (invoice.owner == user.id && invoice.paid).into(),
///             _ => Vote::Abstain,
///         }
///     }
/// }
///
/// let gate = Gate::new().voter(InvoiceVoter);
/// let invoice = Invoice { owner: 7, paid: false };
/// assert!(gate.allows_for(&User { id: 7 }, "invoice.view", &invoice));
/// assert!(!gate.allows_for(&User { id: 7 }, "invoice.refund", &invoice));
/// ```
pub trait Voter<U>: Send + Sync + 'static {
    /// Votes on `ability` for `user`, on `resource` when there is one.
    fn vote(&self, user: &U, ability: &str, resource: Option<&dyn Any>) -> Vote;
}

type RolesOf<U> = dyn Fn(&U) -> Vec<String> + Send + Sync;

/// Symfony's `RoleVoter` with its role hierarchy: votes on abilities that
/// start with the role prefix (`ROLE_` by default), grants when the user has
/// the role directly or through the [`RoleHierarchy`], denies otherwise, and
/// abstains on every other ability.
///
/// ```
/// use securite::access::RoleHierarchy;
/// use securite::authz::{Gate, RoleVoter};
///
/// struct User { roles: Vec<String> }
///
/// let hierarchy = RoleHierarchy::new().inherit("ROLE_ADMIN", ["ROLE_EDITOR"]);
/// let gate = Gate::new()
///     .voter(RoleVoter::new(hierarchy, |u: &User| u.roles.clone()))
///     .define("publish", |u: &User| u.roles.iter().any(|r| r == "ROLE_EDITOR"));
///
/// let admin = User { roles: vec!["ROLE_ADMIN".into()] };
/// assert!(gate.allows(&admin, "ROLE_EDITOR"));
/// assert!(!gate.allows(&User { roles: vec![] }, "ROLE_EDITOR"));
/// ```
pub struct RoleVoter<U> {
    hierarchy: RoleHierarchy,
    roles: Arc<RolesOf<U>>,
    prefix: String,
}

impl<U> RoleVoter<U> {
    /// A voter reading the roles of a user with `roles_of`.
    pub fn new<F>(hierarchy: RoleHierarchy, roles_of: F) -> Self
    where
        F: Fn(&U) -> Vec<String> + Send + Sync + 'static,
    {
        Self {
            hierarchy,
            roles: Arc::new(roles_of),
            prefix: String::from("ROLE_"),
        }
    }

    /// The prefix of the abilities this voter handles (default `ROLE_`; an
    /// empty prefix makes every ability a role).
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }
}

impl<U: 'static> Voter<U> for RoleVoter<U> {
    fn vote(&self, user: &U, ability: &str, _resource: Option<&dyn Any>) -> Vote {
        if !ability.starts_with(&self.prefix) {
            return Vote::Abstain;
        }
        self.hierarchy
            .is_granted((self.roles)(user), ability)
            .into()
    }
}

/// How the votes of every rule and voter are combined (Symfony's access
/// decision strategies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Granted as soon as one vote grants (Symfony's default).
    #[default]
    Affirmative,
    /// Granted when more votes grant than deny; a tie denies.
    Consensus,
    /// Granted only if no vote denies and at least one grants.
    Unanimous,
}

/// Refusal returned by [`Gate::authorize`]. Turn it into a `403` with
/// [`Forbidden::into_rejection`], or into your own error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forbidden {
    /// The refused ability.
    pub ability: String,
}

impl Forbidden {
    /// A `403 Forbidden` [`Rejection`] (code `forbidden`) whose details,
    /// logged but never sent to the client, name the ability.
    pub fn into_rejection(self) -> Rejection {
        Rejection::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "You are not allowed to perform this action.",
        )
        .with_details(format!("ability `{}` denied", self.ability))
    }
}

impl fmt::Display for Forbidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ability `{}` denied", self.ability)
    }
}

impl std::error::Error for Forbidden {}

type Before<U> = dyn Fn(&U, &str) -> Option<bool> + Send + Sync;
type Rule<U> = dyn Fn(&U, Option<&dyn Any>) -> Vote + Send + Sync;

/// The authorization gate. Cheap to clone; share one per application. See
/// the [module docs](self).
pub struct Gate<U> {
    before: Vec<Arc<Before<U>>>,
    rules: Vec<(String, Arc<Rule<U>>)>,
    voters: Vec<Arc<dyn Voter<U>>>,
    strategy: Strategy,
    allow_if_all_abstain: bool,
}

impl<U> Clone for Gate<U> {
    fn clone(&self) -> Self {
        Self {
            before: self.before.clone(),
            rules: self.rules.clone(),
            voters: self.voters.clone(),
            strategy: self.strategy,
            allow_if_all_abstain: self.allow_if_all_abstain,
        }
    }
}

impl<U: 'static> fmt::Debug for Gate<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gate")
            .field("abilities", &self.abilities())
            .field("voters", &self.voters.len())
            .field("strategy", &self.strategy)
            .finish()
    }
}

impl<U: 'static> Default for Gate<U> {
    fn default() -> Self {
        Self::new()
    }
}

impl<U: 'static> Gate<U> {
    /// An empty gate: everything is denied.
    pub fn new() -> Self {
        Self {
            before: Vec::new(),
            rules: Vec::new(),
            voters: Vec::new(),
            strategy: Strategy::Affirmative,
            allow_if_all_abstain: false,
        }
    }

    /// A hook run before any rule: `Some(true)` grants, `Some(false)` denies,
    /// `None` lets the rules decide. Hooks run in order; the first answer wins.
    pub fn before<F>(mut self, f: F) -> Self
    where
        F: Fn(&U, &str) -> Option<bool> + Send + Sync + 'static,
    {
        self.before.push(Arc::new(f));
        self
    }

    /// Defines an ability that takes no resource. Defining an ability twice
    /// adds a second rule, combined with the [`Strategy`].
    pub fn define<F>(mut self, ability: &str, f: F) -> Self
    where
        F: Fn(&U) -> bool + Send + Sync + 'static,
    {
        let rule = move |user: &U, resource: Option<&dyn Any>| match resource {
            None => Vote::from(f(user)),
            Some(_) => Vote::Abstain,
        };
        self.rules.push((ability.to_owned(), Arc::new(rule)));
        self
    }

    /// Defines an ability on resources of type `R`. With a resource of
    /// another type (or none) the rule abstains, so it can never grant by
    /// mistake.
    pub fn define_for<R, F>(mut self, ability: &str, f: F) -> Self
    where
        R: Any,
        F: Fn(&U, &R) -> bool + Send + Sync + 'static,
    {
        let rule = move |user: &U, resource: Option<&dyn Any>| match resource
            .and_then(|r| r.downcast_ref::<R>())
        {
            Some(r) => Vote::from(f(user, r)),
            None => Vote::Abstain,
        };
        self.rules.push((ability.to_owned(), Arc::new(rule)));
        self
    }

    /// Adds a [`Voter`], consulted for every ability.
    pub fn voter(mut self, voter: impl Voter<U>) -> Self {
        self.voters.push(Arc::new(voter));
        self
    }

    /// Adds a [`RoleVoter`]: abilities named `ROLE_*` are granted to users
    /// that have the role, directly or through `hierarchy`.
    pub fn roles<F>(self, hierarchy: RoleHierarchy, roles_of: F) -> Self
    where
        F: Fn(&U) -> Vec<String> + Send + Sync + 'static,
    {
        self.voter(RoleVoter::new(hierarchy, roles_of))
    }

    /// How votes are combined (default [`Strategy::Affirmative`]).
    pub fn strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Grants when every rule and voter abstains. Off by default (deny by
    /// default); turning it on is rarely what you want.
    pub fn allow_if_all_abstain(mut self, allow: bool) -> Self {
        self.allow_if_all_abstain = allow;
        self
    }

    /// Defined ability names (sorted, deduplicated).
    pub fn abilities(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.rules.iter().map(|(a, _)| a.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn decide(&self, user: &U, ability: &str, resource: Option<&dyn Any>) -> bool {
        for hook in &self.before {
            if let Some(answer) = hook(user, ability) {
                return answer;
            }
        }
        let (mut grants, mut denies) = (0u32, 0u32);
        let votes = self
            .rules
            .iter()
            .filter(|(a, _)| a == ability)
            .map(|(_, rule)| rule(user, resource))
            .chain(self.voters.iter().map(|v| v.vote(user, ability, resource)));
        for vote in votes {
            match vote {
                Vote::Grant => grants += 1,
                Vote::Deny => denies += 1,
                Vote::Abstain => {}
            }
            if self.strategy == Strategy::Affirmative && grants > 0 {
                return true;
            }
        }
        if grants == 0 && denies == 0 {
            return self.allow_if_all_abstain;
        }
        match self.strategy {
            Strategy::Affirmative => grants > 0,
            Strategy::Consensus => grants > denies,
            Strategy::Unanimous => denies == 0 && grants > 0,
        }
    }

    /// Whether `user` may perform `ability` (no resource).
    pub fn allows(&self, user: &U, ability: &str) -> bool {
        self.decide(user, ability, None)
    }

    /// Whether `user` may perform `ability` on `resource`.
    pub fn allows_for<R: Any>(&self, user: &U, ability: &str, resource: &R) -> bool {
        self.decide(user, ability, Some(resource))
    }

    /// The opposite of [`allows`](Self::allows).
    pub fn denies(&self, user: &U, ability: &str) -> bool {
        !self.allows(user, ability)
    }

    /// Whether `user` may perform at least one of `abilities`.
    pub fn any(&self, user: &U, abilities: &[&str]) -> bool {
        abilities.iter().any(|a| self.allows(user, a))
    }

    /// Whether `user` may perform every one of `abilities` (`false` for an
    /// empty list).
    pub fn all(&self, user: &U, abilities: &[&str]) -> bool {
        !abilities.is_empty() && abilities.iter().all(|a| self.allows(user, a))
    }

    /// `Ok(())` or a [`Forbidden`] error, for `?` in handlers.
    pub fn authorize(&self, user: &U, ability: &str) -> Result<(), Forbidden> {
        if self.allows(user, ability) {
            Ok(())
        } else {
            Err(Forbidden {
                ability: ability.to_owned(),
            })
        }
    }

    /// `Ok(())` or a [`Forbidden`] error, for an ability on a resource.
    pub fn authorize_for<R: Any>(
        &self,
        user: &U,
        ability: &str,
        resource: &R,
    ) -> Result<(), Forbidden> {
        if self.allows_for(user, ability, resource) {
            Ok(())
        } else {
            Err(Forbidden {
                ability: ability.to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct User {
        id: u32,
        roles: &'static [&'static str],
        banned: bool,
    }

    struct Doc {
        owner: u32,
    }

    struct Other;

    fn user(id: u32, roles: &'static [&'static str]) -> User {
        User {
            id,
            roles,
            banned: false,
        }
    }

    fn gate() -> Gate<User> {
        Gate::new()
            .define("admin.panel", |u: &User| u.roles.contains(&"admin"))
            .define_for("doc.edit", |u: &User, d: &Doc| d.owner == u.id)
    }

    #[test]
    fn role_voter_with_hierarchy() {
        let h = RoleHierarchy::new()
            .inherit("ROLE_ADMIN", ["ROLE_EDITOR"])
            .inherit("ROLE_EDITOR", ["ROLE_USER"]);
        let g = Gate::<Vec<String>>::new().roles(h, |u| u.clone());
        let admin = vec!["ROLE_ADMIN".to_string()];
        let user = vec!["ROLE_USER".to_string()];
        assert!(g.allows(&admin, "ROLE_USER"));
        assert!(g.allows(&user, "ROLE_USER"));
        assert!(!g.allows(&user, "ROLE_ADMIN"), "no upward inheritance");
        assert!(
            !g.allows(&admin, "edit"),
            "non-role abilities abstain: denied"
        );
        let g = Gate::<Vec<String>>::new().voter(
            RoleVoter::new(RoleHierarchy::new(), |u: &Vec<String>| u.clone()).prefix("perm:"),
        );
        assert!(g.allows(&vec!["perm:x".to_string()], "perm:x"));
        assert!(!g.allows(&vec!["perm:x".to_string()], "ROLE_X"));
    }

    #[test]
    fn deny_by_default() {
        let g = Gate::<User>::new();
        assert!(!g.allows(&user(1, &["admin"]), "anything"));
        assert!(g.denies(&user(1, &[]), "anything"));
        assert!(g.abilities().is_empty());
    }

    #[test]
    fn abilities_and_policies() {
        let g = gate();
        assert!(g.allows(&user(1, &["admin"]), "admin.panel"));
        assert!(!g.allows(&user(1, &["editor"]), "admin.panel"));
        assert!(g.allows_for(&user(1, &[]), "doc.edit", &Doc { owner: 1 }));
        assert!(
            !g.allows_for(&user(2, &[]), "doc.edit", &Doc { owner: 1 }),
            "IDOR"
        );
        assert_eq!(g.abilities(), ["admin.panel", "doc.edit"]);
    }

    #[test]
    fn wrong_or_missing_resource_never_grants() {
        let g = gate().define_for("doc.view", |_: &User, _: &Doc| true);
        let u = user(1, &["admin"]);
        assert!(!g.allows(&u, "doc.edit"), "resource rule without resource");
        assert!(!g.allows_for(&u, "doc.view", &Other), "wrong type");
        assert!(
            !g.allows_for(&u, "admin.panel", &Doc { owner: 1 }),
            "resource-less rule with a resource"
        );
        assert!(
            !g.allows_for(&u, "doc.view", &&Doc { owner: 1 }),
            "&Doc is another type"
        );
    }

    #[test]
    fn before_hooks() {
        let g = gate()
            .before(|u: &User, _| u.banned.then_some(false))
            .before(|u: &User, _| u.roles.contains(&"root").then_some(true));
        let root = user(9, &["root"]);
        assert!(g.allows(&root, "undefined.ability"));
        assert!(g.allows_for(&root, "doc.edit", &Doc { owner: 1 }));
        let banned_root = User {
            banned: true,
            ..user(9, &["root", "admin"])
        };
        assert!(!g.allows(&banned_root, "admin.panel"), "first hook wins");
    }

    struct Deny;
    impl Voter<User> for Deny {
        fn vote(&self, _: &User, ability: &str, _: Option<&dyn Any>) -> Vote {
            if ability.starts_with("doc.") {
                Vote::Deny
            } else {
                Vote::Abstain
            }
        }
    }

    struct Grant;
    impl Voter<User> for Grant {
        fn vote(&self, _: &User, ability: &str, _: Option<&dyn Any>) -> Vote {
            if ability.starts_with("doc.") {
                Vote::Grant
            } else {
                Vote::Abstain
            }
        }
    }

    #[test]
    fn strategies() {
        let owner = user(1, &[]);
        let doc = Doc { owner: 1 };
        // rule: Grant, Deny voter.
        let g = gate().voter(Deny);
        assert!(g.allows_for(&owner, "doc.edit", &doc), "affirmative");
        assert!(
            !g.clone()
                .strategy(Strategy::Unanimous)
                .allows_for(&owner, "doc.edit", &doc)
        );
        assert!(
            !g.clone()
                .strategy(Strategy::Consensus)
                .allows_for(&owner, "doc.edit", &doc),
            "tie denies"
        );
        let g = g.voter(Grant).strategy(Strategy::Consensus);
        assert!(g.allows_for(&owner, "doc.edit", &doc), "2 grants vs 1 deny");
        // Unanimous with only grants.
        let g = gate().voter(Grant).strategy(Strategy::Unanimous);
        assert!(g.allows_for(&owner, "doc.edit", &doc));
        assert!(!g.allows_for(&user(2, &[]), "doc.edit", &doc));
    }

    #[test]
    fn all_abstain() {
        let g = Gate::<User>::new().voter(Grant);
        assert!(!g.allows(&user(1, &[]), "other"));
        assert!(
            g.clone()
                .allow_if_all_abstain(true)
                .allows(&user(1, &[]), "other")
        );
    }

    #[test]
    fn helpers_and_rejection() {
        let g = gate();
        let admin = user(1, &["admin"]);
        assert!(g.any(&admin, &["nope", "admin.panel"]));
        assert!(!g.all(&admin, &["nope", "admin.panel"]));
        assert!(!g.all(&admin, &[]));
        assert!(g.authorize(&admin, "admin.panel").is_ok());
        let err = g
            .authorize_for(&admin, "doc.edit", &Doc { owner: 5 })
            .unwrap_err();
        assert_eq!(err.ability, "doc.edit");
        let r = err.into_rejection();
        assert_eq!((r.status(), r.code()), (StatusCode::FORBIDDEN, "forbidden"));
        assert!(
            !r.message().contains("doc.edit"),
            "ability not leaked to clients"
        );
        assert!(format!("{g:?}").contains("doc.edit"));
    }

    #[test]
    fn gate_is_shareable() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let g = gate();
        assert_send_sync(&g);
        let g2 = g.clone();
        std::thread::spawn(move || assert!(g2.allows(&user(1, &["admin"]), "admin.panel")))
            .join()
            .unwrap();
    }
}
