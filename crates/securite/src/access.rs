//! Roles, role hierarchies and Symfony-style `access_control`.
//!
//! * [`Roles`] are the roles of the current user, put in the request
//!   extensions by authentication: [`Auth::grant`](crate::auth::Auth::grant),
//!   the `roles` claim of a JWT (`Auth::jwt`, feature `jwt`), or your own
//!   guard or session middleware.
//! * A [`RoleHierarchy`] says which roles include which others
//!   (`ROLE_ADMIN` ⊃ `ROLE_EDITOR` ⊃ `ROLE_USER`), like Symfony's
//!   `role_hierarchy`.
//! * [`AccessControl`] is a guard that checks roles by URL before your
//!   handlers run, like Symfony's `access_control`: the **first** matching rule
//!   decides, an anonymous request on a protected path gets `401`, an
//!   authenticated one without the role gets `403`.
//!
//! Paths are compared after canonicalisation (percent-decoding, `\` as `/`,
//! `;params` removed, `//` and dot segments resolved, ASCII case folded), so
//! `/%61dmin`, `/ADMIN`, `//admin`, `/public/../admin` or `/admin;x=1` are all
//! `/admin` for the rules: encoding tricks do not bypass them.
//!
//! ```
//! use http::Method;
//! use securite::access::{Access, AccessControl, RoleHierarchy};
//! use securite::prelude::*;
//!
//! let hierarchy = RoleHierarchy::new()
//!     .inherit("ROLE_ADMIN", ["ROLE_EDITOR"])
//!     .inherit("ROLE_EDITOR", ["ROLE_USER"]);
//!
//! let access = AccessControl::new()
//!     .hierarchy(hierarchy)
//!     .public("/login")
//!     .require_role("/admin", "ROLE_ADMIN")
//!     .rule_for([Method::POST, Method::PUT, Method::DELETE], "/api/posts", Access::any_role(["ROLE_EDITOR"]))
//!     .authenticated("/api")
//!     .deny_unmatched();
//!
//! let shield = Shield::builder()
//!     .guard(Auth::bearer().token("ci", "a-long-ci-token").grant("ci", ["ROLE_EDITOR"]).public(["/login"]))
//!     .guard(access)
//!     .build();
//! ```

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;

use http::{Method, StatusCode, request};

use crate::auth::Principal;
use crate::guard::impl_layer;
use crate::util::{normalize_prefix, path_matches, percent_decode};
use crate::{Context, Guard, Mode, Rejection, priority};

/// The roles of the authenticated user, in the request extensions.
///
/// ```
/// use securite::access::Roles;
///
/// let roles: Roles = ["ROLE_USER", "ROLE_BILLING"].into_iter().collect();
/// assert!(roles.contains("ROLE_BILLING"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roles(Arc<[String]>);

impl Roles {
    /// Roles from any list of names (duplicates are removed).
    pub fn new<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        roles.into_iter().collect()
    }

    /// Whether the role is in the list (no hierarchy: see
    /// [`RoleHierarchy::is_granted`]).
    pub fn contains(&self, role: &str) -> bool {
        self.0.iter().any(|r| r == role)
    }

    /// The roles.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Whether there is no role.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of roles.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<S: Into<String>> FromIterator<S> for Roles {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        let mut seen = BTreeSet::new();
        let roles: Vec<String> = iter
            .into_iter()
            .map(Into::into)
            .filter(|r| !r.is_empty() && seen.insert(r.clone()))
            .collect();
        Roles(roles.into())
    }
}

/// Which roles include which others (Symfony's `role_hierarchy`).
///
/// Cycles are harmless: every role is visited once.
///
/// ```
/// use securite::access::RoleHierarchy;
///
/// let h = RoleHierarchy::new()
///     .inherit("ROLE_ADMIN", ["ROLE_EDITOR", "ROLE_BILLING"])
///     .inherit("ROLE_EDITOR", ["ROLE_USER"]);
/// assert!(h.is_granted(["ROLE_ADMIN"], "ROLE_USER"));
/// assert!(!h.is_granted(["ROLE_EDITOR"], "ROLE_ADMIN"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct RoleHierarchy {
    children: HashMap<String, Vec<String>>,
}

impl RoleHierarchy {
    /// An empty hierarchy: every role only grants itself.
    pub fn new() -> Self {
        Self::default()
    }

    /// `role` also grants every role in `includes` (and what they include).
    pub fn inherit<I, S>(mut self, role: &str, includes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.children
            .entry(role.to_owned())
            .or_default()
            .extend(includes.into_iter().map(Into::into));
        self
    }

    /// Every role reachable from `roles`, themselves included.
    pub fn reachable<I, S>(&self, roles: I) -> BTreeSet<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = BTreeSet::new();
        let mut stack: Vec<String> = roles.into_iter().map(|r| r.as_ref().to_owned()).collect();
        while let Some(role) = stack.pop() {
            if let Some(children) = self.children.get(&role) {
                stack.extend(children.iter().filter(|c| !out.contains(*c)).cloned());
            }
            out.insert(role);
        }
        out
    }

    /// Whether `roles` (directly or through the hierarchy) include `role`.
    pub fn is_granted<I, S>(&self, roles: I, role: &str) -> bool
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<String> = roles.into_iter().map(|r| r.as_ref().to_owned()).collect();
        while let Some(r) = stack.pop() {
            if r == role {
                return true;
            }
            if seen.insert(r.clone()) {
                if let Some(children) = self.children.get(&r) {
                    stack.extend(children.iter().cloned());
                }
            }
        }
        false
    }
}

/// What a rule of [`AccessControl`] requires.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Access {
    /// Anyone, even anonymous (Symfony's `PUBLIC_ACCESS`).
    Public,
    /// Any authenticated user (Symfony's `IS_AUTHENTICATED`).
    Authenticated,
    /// At least one of these roles.
    AnyRole(Vec<String>),
    /// Every one of these roles.
    AllRoles(Vec<String>),
    /// Nobody (`403` for everyone).
    Deny,
}

impl Access {
    /// [`Access::AnyRole`] from any list.
    pub fn any_role<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Access::AnyRole(roles.into_iter().map(Into::into).collect())
    }

    /// [`Access::AllRoles`] from any list.
    pub fn all_roles<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Access::AllRoles(roles.into_iter().map(Into::into).collect())
    }
}

#[derive(Debug, Clone)]
struct Rule {
    prefix: String,
    methods: Option<Vec<Method>>,
    access: Access,
}

/// Role checks by URL, before the handlers (Symfony's `access_control`). See
/// the [module docs](self).
///
/// Run it after the guard that authenticates (it reads the [`Principal`] and
/// [`Roles`] extensions): its priority, [`priority::ACCESS_CONTROL`], comes
/// right after [`Auth`](crate::auth::Auth). A custom authentication guard
/// must use a lower priority.
#[derive(Debug, Clone)]
pub struct AccessControl {
    rules: Vec<Rule>,
    hierarchy: Arc<RoleHierarchy>,
    unmatched: Access,
    mode: Mode,
}

impl Default for AccessControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Canonical form of a request path for rule matching. See the module docs.
pub(crate) fn canonical_path(path: &str) -> String {
    // Decode twice at most: `%252e` is a literal `%2e` for the router, but
    // stays suspicious enough to be compared in its decoded form.
    let once = percent_decode(path, false);
    let decoded = percent_decode(&once, false);
    let mut segments: Vec<&str> = Vec::new();
    for raw in decoded.split(['/', '\\']) {
        let seg = raw.split(';').next().unwrap_or("");
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::with_capacity(decoded.len() + 1);
    for s in &segments {
        out.push('/');
        out.push_str(s);
    }
    if out.is_empty() {
        out.push('/');
    }
    out.make_ascii_lowercase();
    out
}

fn rule_prefix(prefix: impl Into<String>) -> String {
    let p = canonical_path(&normalize_prefix(prefix));
    if p.len() > 1 { p } else { String::from("/") }
}

impl AccessControl {
    /// No rule: every request passes (until rules or
    /// [`deny_unmatched`](Self::deny_unmatched) are added).
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            hierarchy: Arc::new(RoleHierarchy::new()),
            unmatched: Access::Public,
            mode: Mode::Enforce,
        }
    }

    /// The role hierarchy used by every rule.
    pub fn hierarchy(mut self, hierarchy: RoleHierarchy) -> Self {
        self.hierarchy = Arc::new(hierarchy);
        self
    }

    /// Adds a rule for every method. Rules are checked in the order they are
    /// added; the first one whose prefix matches decides.
    pub fn rule(mut self, prefix: impl Into<String>, access: Access) -> Self {
        self.rules.push(Rule {
            prefix: rule_prefix(prefix),
            methods: None,
            access,
        });
        self
    }

    /// Adds a rule for some methods only.
    pub fn rule_for<M>(mut self, methods: M, prefix: impl Into<String>, access: Access) -> Self
    where
        M: IntoIterator<Item = Method>,
    {
        self.rules.push(Rule {
            prefix: rule_prefix(prefix),
            methods: Some(methods.into_iter().collect()),
            access,
        });
        self
    }

    /// `prefix` is open to everyone.
    pub fn public(self, prefix: impl Into<String>) -> Self {
        self.rule(prefix, Access::Public)
    }

    /// `prefix` needs an authenticated user.
    pub fn authenticated(self, prefix: impl Into<String>) -> Self {
        self.rule(prefix, Access::Authenticated)
    }

    /// `prefix` needs `role` (or a role that includes it).
    pub fn require_role(self, prefix: impl Into<String>, role: &str) -> Self {
        self.rule(prefix, Access::any_role([role]))
    }

    /// `prefix` is closed to everyone.
    pub fn deny(self, prefix: impl Into<String>) -> Self {
        self.rule(prefix, Access::Deny)
    }

    /// Requests that no rule matches need an authenticated user (default:
    /// they pass). Secure default for applications whose pages are private.
    pub fn authenticate_unmatched(mut self) -> Self {
        self.unmatched = Access::Authenticated;
        self
    }

    /// Requests that no rule matches are refused (`403`): an allow-list.
    pub fn deny_unmatched(mut self) -> Self {
        self.unmatched = Access::Deny;
        self
    }

    /// Monitor-only mode: violations are logged, not blocked.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    /// The decision for a request, without running the guard (useful in
    /// tests and handlers).
    pub fn check(
        &self,
        method: &Method,
        path: &str,
        authenticated: bool,
        roles: &Roles,
    ) -> Result<(), Rejection> {
        let path = canonical_path(path);
        let (access, prefix) = self
            .rules
            .iter()
            .find(|r| {
                path_matches(&path, &r.prefix)
                    && r.methods.as_ref().is_none_or(|m| m.contains(method))
            })
            .map_or((&self.unmatched, "(unmatched)"), |r| {
                (&r.access, r.prefix.as_str())
            });
        let granted = |role: &String| self.hierarchy.is_granted(roles.iter(), role);
        let allowed = match access {
            Access::Public => return Ok(()),
            Access::Deny => false,
            Access::Authenticated => authenticated,
            Access::AnyRole(r) => authenticated && r.iter().any(granted),
            Access::AllRoles(r) => authenticated && r.iter().all(granted),
        };
        if allowed {
            return Ok(());
        }
        if !authenticated && !matches!(access, Access::Deny) {
            return Err(Rejection::new(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "Authentication required.",
            )
            .with_details(format!("access_control rule `{prefix}`")));
        }
        Err(Rejection::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "You are not allowed to access this resource.",
        )
        .with_details(format!(
            "access_control rule `{prefix}` requires {access:?}"
        )))
    }
}

impl Guard for AccessControl {
    fn name(&self) -> &'static str {
        "access_control"
    }

    fn priority(&self) -> u16 {
        priority::ACCESS_CONTROL
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        let roles = req.extensions.get::<Roles>().cloned().unwrap_or_default();
        let authenticated =
            req.extensions.get::<Principal>().is_some() || req.extensions.get::<Roles>().is_some();
        self.check(&req.method, req.uri.path(), authenticated, &roles)
    }
}

impl_layer!(AccessControl);

impl fmt::Display for Roles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn hierarchy() -> RoleHierarchy {
        RoleHierarchy::new()
            .inherit("ROLE_ADMIN", ["ROLE_EDITOR"])
            .inherit("ROLE_EDITOR", ["ROLE_USER"])
    }

    fn acl() -> AccessControl {
        AccessControl::new()
            .hierarchy(hierarchy())
            .public("/admin/login")
            .require_role("/admin", "ROLE_ADMIN")
            .rule_for([Method::POST], "/posts", Access::any_role(["ROLE_EDITOR"]))
            .public("/posts")
            .rule("/billing", Access::all_roles(["ROLE_USER", "ROLE_BILLING"]))
            .deny("/internal")
            .authenticated("/account")
    }

    fn run(acl: &AccessControl, method: Method, path: &str, roles: Option<&[&str]>) -> u16 {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(r) = roles {
            b = b.extension(Roles::new(r.iter().copied()));
        }
        let mut p = b.body(()).unwrap().into_parts().0;
        let mut ctx = Context::new(p.method.clone(), p.uri.clone(), None);
        match acl.on_request(&mut p, &mut ctx) {
            Ok(()) => 200,
            Err(r) => r.status().as_u16(),
        }
    }

    #[test]
    fn hierarchy_and_cycles() {
        let h = hierarchy().inherit("ROLE_USER", ["ROLE_ADMIN"]); // cycle
        assert!(h.is_granted(["ROLE_ADMIN"], "ROLE_USER"));
        assert!(h.is_granted(["ROLE_USER"], "ROLE_ADMIN"));
        assert!(!h.is_granted(["ROLE_X"], "ROLE_USER"));
        let all = hierarchy().reachable(["ROLE_ADMIN"]);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn rules_first_match_wins() {
        let a = acl();
        assert_eq!(run(&a, Method::GET, "/admin/login", None), 200);
        assert_eq!(run(&a, Method::GET, "/admin", None), 401);
        assert_eq!(
            run(&a, Method::GET, "/admin/users", Some(&["ROLE_EDITOR"])),
            403
        );
        assert_eq!(
            run(&a, Method::GET, "/admin/users", Some(&["ROLE_ADMIN"])),
            200
        );
        assert_eq!(run(&a, Method::GET, "/posts/1", None), 200);
        assert_eq!(run(&a, Method::POST, "/posts", None), 401);
        assert_eq!(run(&a, Method::POST, "/posts", Some(&["ROLE_USER"])), 403);
        assert_eq!(run(&a, Method::POST, "/posts", Some(&["ROLE_ADMIN"])), 200);
        assert_eq!(run(&a, Method::GET, "/billing", Some(&["ROLE_ADMIN"])), 403);
        assert_eq!(
            run(
                &a,
                Method::GET,
                "/billing",
                Some(&["ROLE_ADMIN", "ROLE_BILLING"])
            ),
            200
        );
        assert_eq!(
            run(&a, Method::GET, "/internal", Some(&["ROLE_ADMIN"])),
            403
        );
        assert_eq!(run(&a, Method::GET, "/internal", None), 403);
        assert_eq!(run(&a, Method::GET, "/account", Some(&[])), 200);
        assert_eq!(run(&a, Method::GET, "/elsewhere", None), 200);
        assert_eq!(
            run(&a, Method::GET, "/administrator", None),
            200,
            "segment boundary"
        );
    }

    #[test]
    fn encoding_tricks_do_not_bypass_rules() {
        let a = acl();
        for path in [
            "/ADMIN",
            "/Admin/users",
            "//admin",
            "/%61dmin",
            "/%2561dmin",
            "/admin;jsessionid=1",
            "/admin/",
            "/./admin",
            "/posts/../admin",
            "/posts/%2e%2e/admin",
            "/x\\..\\admin",
            "/admin%2fusers",
        ] {
            assert_eq!(run(&a, Method::GET, path, None), 401, "{path}");
        }
        // `/admin/login` is public but not `/admin/login/../users`.
        assert_eq!(run(&a, Method::GET, "/admin/login/../users", None), 401);
    }

    #[test]
    fn unmatched_defaults() {
        let deny = AccessControl::new().public("/").deny_unmatched();
        assert_eq!(run(&deny, Method::GET, "/x", None), 200, "`/` matches all");
        let deny = AccessControl::new().public("/health").deny_unmatched();
        assert_eq!(run(&deny, Method::GET, "/x", Some(&["ROLE_ADMIN"])), 403);
        let auth = AccessControl::new().authenticate_unmatched();
        assert_eq!(run(&auth, Method::GET, "/x", None), 401);
        assert_eq!(run(&auth, Method::GET, "/x", Some(&["ROLE_USER"])), 200);
    }

    #[test]
    fn principal_counts_as_authenticated() {
        let a = AccessControl::new().authenticated("/");
        let mut p = Request::builder()
            .uri("/x")
            .extension(Principal {
                name: "bot".into(),
                scheme: "bearer",
            })
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let mut ctx = Context::new(p.method.clone(), p.uri.clone(), None);
        assert!(a.on_request(&mut p, &mut ctx).is_ok());
    }

    #[test]
    fn roles_type() {
        let r = Roles::new(["A", "B", "A", ""]);
        assert_eq!(r.len(), 2);
        assert_eq!(r.to_string(), "A,B");
        assert!(Roles::default().is_empty());
    }
}
