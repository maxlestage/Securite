---
title: Autorización
summary: Gates, policies y voters al estilo de Laravel y Symfony, con denegación por defecto, para decidir qué puede hacer cada usuario con cada recurso.
category: access
order: 7
---

La autenticación le dice *quién* llama; la autorización decide *qué* puede hacer, y sobre *qué* registro. `Gate` centraliza esas reglas: habilidades sin recurso (`"create-post"`), policies sobre un tipo de recurso (`"edit-post"` sobre un `Post`) y voters que agrupan las reglas de un dominio. Combina `Gate::define` / `Gate::before` de Laravel con los voters y las estrategias de decisión de Symfony.

## Amenazas mitigadas

- **A01:2021 Pérdida de control de acceso**, el riesgo web más frecuente: referencias directas inseguras a objetos (cambiar `/invoices/42` por `/invoices/43`), escalada de privilegios, comprobaciones olvidadas en uno de tantos handlers (CWE-284, CWE-639, CWE-862).
- **Reglas que fallan en abierto**: una habilidad que nadie definió, un recurso de un tipo inesperado o una decisión en la que todos los voters se abstienen equivalen a una denegación.

## Inicio rápido

```rust
use securite::prelude::*;

struct User { id: u64, admin: bool }
struct Post { author: u64, published: bool }

let gate = Gate::<User>::new()
    // Los administradores pueden hacerlo todo.
    .before(|user, _ability| user.admin.then_some(true))
    .define("create-post", |_user| true)
    .define_for("edit-post", |user, post: &Post| post.author == user.id)
    .define_for("view-post", |user, post: &Post| post.published || post.author == user.id);

// En un handler:
let post = load_post(id)?;
gate.authorize_for(&user, "edit-post", &post)?; // Err(Forbidden) si se deniega
```

Construya la gate una vez al arrancar y compártala (es `Clone`, `Send` y `Sync`).

## Cómo se toma una decisión

1. Los **hooks `before`** se ejecutan primero, en orden. `Some(true)` concede, `Some(false)` deniega (un usuario bloqueado), `None` deja decidir a las reglas.
2. Votan las **reglas** definidas para la habilidad: las reglas `define` solo votan sin recurso, las reglas `define_for::<R>` solo sobre un recurso de tipo `R`. Si no, se abstienen.
3. Los **voters** votan en cada habilidad; se abstienen en lo que no gestionan.
4. La **estrategia** combina los votos. Si todos se abstienen, la respuesta es no.

| Estrategia | Se concede cuando |
|---|---|
| `Affirmative` (por defecto) | al menos un voto concede |
| `Consensus` | hay más votos que conceden que votos que deniegan (el empate deniega) |
| `Unanimous` | ningún voto deniega y al menos uno concede |

## Voters

Un voter agrupa las reglas de un tipo de recurso, como un voter de Symfony o una clase policy de Laravel:

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
    .voter(AccountFrozenVoter) // deniega todo a las cuentas congeladas
    .strategy(Strategy::Unanimous);
```

Con `Unanimous`, un solo `Deny` gana a cualquier número de concesiones, lo que encaja con reglas como «una cuenta congelada no puede hacer nada».

## Denegaciones

`authorize` y `authorize_for` devuelven `Result<(), Forbidden>`. `Forbidden::into_rejection()` convierte el error en una [respuesta problem](/docs/error-format) `403` con el código `forbidden`; la habilidad denegada se registra en los detalles y nunca se envía al cliente. También puede convertir `Forbidden` en su propio tipo de error, o responder `404` en lugar de `403` para ocultar que un registro existe.

## API

| Método | Descripción |
|---|---|
| `Gate::new()` | Gate vacía: todo se deniega. |
| `.before(f)` | `Fn(&U, &str) -> Option<bool>` ejecutado antes de las reglas. |
| `.define(ability, f)` | `Fn(&U) -> bool`, para habilidades sin recurso. |
| `.define_for(ability, f)` | `Fn(&U, &R) -> bool`, para habilidades sobre un recurso de tipo `R`. |
| `.voter(v)` | Añade un `Voter<U>`. |
| `.strategy(s)` | `Affirmative`, `Consensus` o `Unanimous`. |
| `.allow_if_all_abstain(b)` | Concede cuando todos se abstienen (desactivado por defecto). |
| `.allows` / `.allows_for` / `.denies` | `bool`. |
| `.any(user, abilities)` / `.all(user, abilities)` | Varias habilidades sin recurso. |
| `.authorize` / `.authorize_for` | `Result<(), Forbidden>`. |
| `.abilities()` | Nombres de las habilidades definidas. |

## Errores frecuentes y consejos

- Compruebe la autorización en **cada** handler que lee o modifica un registro, incluidas las API JSON y las exportaciones en segundo plano; cargue primero el registro y páselo a la gate.
- El tipo de recurso debe coincidir exactamente: `define_for::<Post>` no vota sobre un `&Post` pasado como `&&Post`, ni sobre un `Arc<Post>`; se abstiene, lo que deniega.
- Mantenga los hooks `before` cortos y explícitos: un `Some(true)` demasiado amplio es una llave maestra.
- Las reglas se ejecutan de forma síncrona: cargue lo que necesiten (roles, pertenencia a equipos) antes de llamar a la gate.

## Páginas relacionadas

- [Autenticación](/docs/auth)
- [Hash de contraseñas](/docs/passwords)
- [URL firmadas](/docs/signed-urls)
- [Formato de errores](/docs/error-format)
