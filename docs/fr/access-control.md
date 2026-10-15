---
title: Contrôle d'accès
summary: Des règles access_control à la Symfony par URL et méthode, une hiérarchie de rôles partagée avec la Gate, et une canonicalisation des chemins qui déjoue les contournements par encodage.
category: access
order: 10
---

`AccessControl` vérifie les rôles par URL **avant** vos handlers, comme l'`access_control` de Symfony. Les règles sont essayées dans l'ordre et la première dont le préfixe (et la méthode) correspond décide. Une `RoleHierarchy` dit quels rôles en incluent d'autres, et la même hiérarchie anime le `RoleVoter` de la [Gate](/docs/authorization).

## Menaces couvertes

- **A01:2021 Contrôle d'accès défaillant** : vérifications oubliées sur les routes d'administration (CWE-862) et élévation de privilèges (CWE-269).
- **Contournements par confusion de chemin** : `/ADMIN`, `/%61dmin`, `/%2561dmin`, `//admin`, `/public/../admin`, `/x\..\admin`, `/admin;jsessionid=1` ou `/admin%2fusers` sont tous ramenés à `/admin/…` avant l'examen des règles.
- **Autorisation par défaut** : `deny_unmatched()` fait des règles une liste blanche.

## Démarrage rapide

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
    .guard(Auth::jwt(validator).public(["/login", "/assets"])) // ou Sessions, ou Auth::bearer().grant(…)
    .guard(access)
    .build();
```

Une requête anonyme sur un chemin protégé reçoit `401 unauthenticated` ; une requête authentifiée sans le rôle reçoit `403 forbidden`. La règle qui a refusé n'est écrite que dans le journal d'audit.

## D'où viennent les rôles

`AccessControl` lit deux extensions de la requête, déposées par les guards qui passent avant lui :

| Source | Extension |
|---|---|
| `Auth::jwt` | `Principal` et `Roles` tirés du claim des rôles |
| `Auth::bearer().token("ci", …).grant("ci", ["ROLE_DEPLOY"])` | `Principal` et `Roles` |
| `Sessions` | `Principal` (l'utilisateur de la session) |
| Votre propre guard (priorité inférieure à 145) | `req.extensions.insert(Roles::new([...]))` |

Une requête est authentifiée quand elle a un `Principal` ou des `Roles`.

## Règles

| Méthode | Exigence |
|---|---|
| `.public(préfixe)` | Tout le monde (`PUBLIC_ACCESS`). |
| `.authenticated(préfixe)` | Tout utilisateur authentifié. |
| `.require_role(préfixe, rôle)` | Le rôle, directement ou par la hiérarchie. |
| `.rule(préfixe, Access::any_role([...]))` / `Access::all_roles([...])` | L'un des rôles / tous les rôles. |
| `.deny(préfixe)` | Personne. |
| `.rule_for(méthodes, préfixe, accès)` | Seulement pour ces méthodes. |
| `.deny_unmatched()` / `.authenticate_unmatched()` | Ce qui arrive quand aucune règle ne correspond (par défaut : autorisé). |
| `.monitor()` | Journalise les refus sans bloquer. |

Les préfixes couvrent des segments entiers : `/admin` couvre `/admin` et `/admin/users`, pas `/administrator`. La comparaison ignore la casse ASCII.

## Les rôles dans la Gate

```rust
use securite::authz::Gate;

let gate = Gate::<User>::new()
    .roles(hierarchy.clone(), |u: &User| u.roles.clone())
    .define_for("edit-post", |u, p: &Post| p.author == u.id);

gate.allows(&user, "ROLE_EDITOR"); // vrai pour un admin, par la hiérarchie
```

## Pièges et conseils

- Placez les règles précises **avant** les générales : la première qui correspond l'emporte (`/admin/login` public avant `/admin`).
- Les règles d'URL protègent des routes, pas des objets : gardez les [autorisations](/docs/authorization) pour « cet utilisateur peut-il modifier *cet* article ».
- Une hiérarchie n'accorde que vers le bas : `ROLE_USER` n'obtient jamais `ROLE_ADMIN` ; les cycles sont sans danger.

## Pages liées

- [Autorisations](/docs/authorization)
- [JWT et JWKS](/docs/jwt)
- [Sessions](/docs/sessions)
