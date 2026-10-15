---
title: Control de acceso
summary: Reglas access_control al estilo de Symfony por URL y método, una jerarquía de roles compartida con la Gate y una canonicalización de rutas que frustra los rodeos por codificación.
category: access
order: 10
---

`AccessControl` comprueba los roles por URL **antes** de sus handlers, como el `access_control` de Symfony. Las reglas se prueban en orden y decide la primera cuyo prefijo (y método) coincide. Una `RoleHierarchy` indica qué roles incluyen a otros, y la misma jerarquía mueve el `RoleVoter` de la [Gate](/docs/authorization).

## Amenazas mitigadas

- **A01:2021 Pérdida de control de acceso**: comprobaciones olvidadas en rutas de administración (CWE-862) y escalada de privilegios (CWE-269).
- **Rodeos por confusión de ruta**: `/ADMIN`, `/%61dmin`, `/%2561dmin`, `//admin`, `/public/../admin`, `/x\..\admin`, `/admin;jsessionid=1` o `/admin%2fusers` se convierten todos en `/admin/…` antes de examinar las reglas.
- **Permitir por defecto**: `deny_unmatched()` convierte las reglas en una lista blanca.

## Inicio rápido

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
    .guard(Auth::jwt(validator).public(["/login", "/assets"])) // o Sessions, o Auth::bearer().grant(…)
    .guard(access)
    .build();
```

Una petición anónima en una ruta protegida recibe `401 unauthenticated`; una autenticada sin el rol recibe `403 forbidden`. La regla que rechazó solo se escribe en el registro de auditoría.

## De dónde vienen los roles

`AccessControl` lee dos extensiones de la petición, que dejan los guards que se ejecutan antes:

| Origen | Extensión |
|---|---|
| `Auth::jwt` | `Principal` y `Roles` del claim de roles |
| `Auth::bearer().token("ci", …).grant("ci", ["ROLE_DEPLOY"])` | `Principal` y `Roles` |
| `Sessions` | `Principal` (el usuario de la sesión) |
| Su propio guard (prioridad inferior a 145) | `req.extensions.insert(Roles::new([...]))` |

Una petición está autenticada cuando tiene un `Principal` o `Roles`.

## Reglas

| Método | Exigencia |
|---|---|
| `.public(prefijo)` | Cualquiera (`PUBLIC_ACCESS`). |
| `.authenticated(prefijo)` | Cualquier usuario autenticado. |
| `.require_role(prefijo, rol)` | El rol, directamente o por la jerarquía. |
| `.rule(prefijo, Access::any_role([...]))` / `Access::all_roles([...])` | Uno de los roles / todos. |
| `.deny(prefijo)` | Nadie. |
| `.rule_for(métodos, prefijo, acceso)` | Solo para esos métodos. |
| `.deny_unmatched()` / `.authenticate_unmatched()` | Qué pasa cuando ninguna regla coincide (por defecto: permitido). |
| `.monitor()` | Registra los rechazos sin bloquear. |

Los prefijos cubren segmentos enteros: `/admin` cubre `/admin` y `/admin/users`, no `/administrator`. La comparación ignora mayúsculas y minúsculas ASCII.

## Los roles en la Gate

```rust
use securite::authz::Gate;

let gate = Gate::<User>::new()
    .roles(hierarchy.clone(), |u: &User| u.roles.clone())
    .define_for("edit-post", |u, p: &Post| p.author == u.id);

gate.allows(&user, "ROLE_EDITOR"); // verdadero para un admin, por la jerarquía
```

## Trampas y consejos

- Ponga las reglas concretas **antes** que las generales: gana la primera que coincide (`/admin/login` público antes que `/admin`).
- Las reglas por URL protegen rutas, no objetos: use la [autorización](/docs/authorization) para «¿puede este usuario editar *este* artículo?».
- Una jerarquía solo concede hacia abajo: `ROLE_USER` nunca obtiene `ROLE_ADMIN`; los ciclos son inofensivos.

## Páginas relacionadas

- [Autorización](/docs/authorization)
- [JWT y JWKS](/docs/jwt)
- [Sesiones](/docs/sessions)
