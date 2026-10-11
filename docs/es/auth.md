---
title: Autenticación
summary: Tokens bearer, claves de API, HTTP Basic o su propio validador como JWT, con los secretos almacenados como resúmenes SHA-256 y comparados en tiempo constante.
category: access
order: 3
---

`Auth` coloca una comprobación de credenciales delante de sus rutas. Admite los esquemas que necesitan la mayoría de los servicios (tokens bearer, claves de API en una cabecera propia, HTTP Basic) y le permite conectar su propia lógica de validación, por ejemplo la verificación de JWT. Los secretos se guardan como resúmenes SHA-256 y se comparan en tiempo constante con cada una de las credenciales configuradas, y la identidad autenticada se entrega a sus handlers.

## Amenazas que mitiga

- **A01:2021 Broken Access Control**: paneles de administración, APIs internas y endpoints de métricas accesibles sin credenciales.
- **A07:2021 Identification and Authentication Failures**: comparaciones de tokens que filtran información a través del tiempo de respuesta (CWE-208), credenciales verificadas de forma desigual de un handler a otro.
- **A02:2021 Cryptographic Failures**: secretos en claro olvidados en ficheros de configuración; con `token_sha256`, su configuración solo contiene un resumen.

## Funcionamiento

1. **Selección de rutas.** Una petición está protegida cuando su ruta coincide con alguno de los prefijos `protect` (todas las rutas si no se configura ninguno) y con ninguno de los prefijos `public`. Los prefijos se comparan por segmentos: `/api` cubre `/api` y `/api/orders`, pero no `/apiary`.
2. **Peticiones preflight.** Las peticiones `OPTIONS` pasan por defecto, porque los navegadores nunca adjuntan credenciales a los preflights de CORS.
3. **Extracción.** La credencial se lee según el esquema: `Authorization: Bearer …`, una cabecera propia o `Authorization: Basic …`.
4. **Verificación.** El secreto presentado se resume con SHA-256 y se compara con cada resumen configurado mediante una igualdad en tiempo constante, sin salida anticipada. Ni la longitud ni la posición de la credencial coincidente pueden deducirse de los tiempos de respuesta.
5. **Resultado.** Si tiene éxito, se inserta un `Principal` en las extensiones de la petición. Si falla, la petición se rechaza con `401 Unauthorized`, el código `unauthorized`, el mensaje `Authentication required.` y un desafío `WWW-Authenticate`.

El guard se ejecuta tarde en la cadena, después de la limitación de peticiones, el bloqueador de bots, el WAF y las comprobaciones CSRF, de modo que los intentos de fuerza bruta se frenan antes de comprobar ninguna credencial.

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let token = std::env::var("API_TOKEN").expect("API_TOKEN must be set");

let mut app = App::new();
app.middleware(
    ShieldBuilder::recommended()
        .guard(
            Auth::bearer()
                .token("ci-pipeline", &token)
                .protect(["/api"])
                .public(["/api/health"]),
        )
        .build(),
);
app.get("/api/health", |_req: Request| async { "ok" });
app.get("/api/orders", |_req: Request| async { "[]" });
```

```bash
curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/api/orders
```

## Esquemas

### Tokens bearer

`Auth::bearer()` lee `Authorization: Bearer <token>` (el nombre del esquema no distingue mayúsculas). Registre tantos tokens como necesite, cada uno con una etiqueta que se convierte en el nombre del principal: así sabe qué cliente ha llamado.

### Claves de API

```rust
use securite::prelude::*;

let partner_key = std::env::var("PARTNER_ACME_KEY").expect("PARTNER_ACME_KEY must be set");
let auth = Auth::api_key("x-api-key").token("partner-acme", &partner_key);
```

El valor de la cabecera se compara tal cual se recibe.

### HTTP Basic

```rust
use securite::prelude::*;

let password = std::env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set");
let auth = Auth::basic("Admin area").user("admin", &password);
```

Se almacena el resumen de `user:password`, y el nombre del principal es el nombre de usuario. Las credenciales Basic viajan en cada petición: utilícelas solo sobre HTTPS.

### Validación personalizada

`Auth::custom` entrega el token bearer y la cabecera de la petición a su función, que devuelve el nombre del principal cuando el token es válido. Más abajo encontrará un ejemplo completo con JWT.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Auth::bearer()` | — | `Authorization: Bearer <token>`. |
| `Auth::api_key(header)` | — | Clave en una cabecera propia; provoca un pánico si el nombre de cabecera no es válido. |
| `Auth::basic(realm)` | — | Autenticación HTTP Basic con el realm indicado. |
| `Auth::custom(f)` | — | Token bearer comprobado por `Fn(&str, &request::Parts) -> Option<String>`. |
| `.token(label, secret)` | ninguno | Token o clave de API aceptado; provoca un pánico si el secreto tiene menos de 8 bytes. |
| `.token_sha256(label, hex)` | ninguno | Token aceptado, indicado por su resumen SHA-256 en hexadecimal; provoca un pánico si no son 64 caracteres hexadecimales. |
| `.user(user, password)` | ninguno | Usuario de Basic; provoca un pánico si el nombre contiene `:`. |
| `.realm(realm)` | `restricted` | Realm anunciado en `WWW-Authenticate` (se eliminan las comillas y las barras invertidas). |
| `.protect(prefixes)` | todas las rutas | Solo estos prefijos de ruta exigen credenciales. |
| `.public(prefixes)` | ninguno | Prefijos de ruta que nunca exigen credenciales; prevalecen sobre `protect`. |
| `.protect_options()` | `OPTIONS` permitido | Exige también credenciales en las peticiones `OPTIONS`. |

## Mantener los secretos fuera de su configuración

Con `token_sha256`, en su configuración o en sus variables de entorno solo se guarda el resumen de un token. Calcúlelo así:

```bash
# printf %s does not append a newline (echo would, and the digest would change).
printf %s "s3cr3t-token-from-vault" | sha256sum
# 316c2c9705150d9a064339f9af33986ffd585a65b1d3ff481c5a9941d45abe1f  -
```

```rust
use securite::prelude::*;

let auth = Auth::bearer()
    .token_sha256("deploy-bot", "316c2c9705150d9a064339f9af33986ffd585a65b1d3ff481c5a9941d45abe1f")
    .protect(["/deploy"]);
```

Las credenciales Basic se verifican mediante el resumen de `user:password`, así que `token_sha256` también funciona con `Auth::basic`; la etiqueta pasa entonces a ser el nombre del principal:

```bash
printf %s "admin:correct horse battery staple" | sha256sum
# 1ced36b78267abc485730b6921c0fe42edac8704d5fabe97bf6bb09b46b4164a  -
```

```rust
use securite::prelude::*;

let auth = Auth::basic("Admin area")
    .token_sha256("admin", "1ced36b78267abc485730b6921c0fe42edac8704d5fabe97bf6bb09b46b4164a")
    .protect(["/admin"]);
```

> **Consejo:** genere los tokens con un generador criptográficamente seguro, por ejemplo `openssl rand -hex 32`. Un simple resumen SHA-256 es suficiente para tokens con tanta entropía, pero no protegería una contraseña humana corta frente a un ataque de fuerza bruta offline: use contraseñas Basic largas y aleatorias.

## La extensión `Principal`

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn whoami(req: Request) -> String {
    // name: the credential label (or the Basic user name)
    // scheme: "bearer", "api_key", "basic" or "custom"
    match req.get::<Principal>() {
        Some(principal) => format!("authenticated as {} via {}", principal.name, principal.scheme),
        None => "anonymous".to_owned(),
    }
}

let token = std::env::var("API_TOKEN").expect("API_TOKEN must be set");
let mut app = App::new();
app.middleware(Shield::builder().guard(Auth::bearer().token("ci-pipeline", &token)).build());
app.get("/api/whoami", whoami);
```

`Principal` solo se inserta en las rutas protegidas: en una ruta pública, `req.get::<Principal>()` es `None`.

## El desafío `WWW-Authenticate`

Cada `401` incluye un desafío que indica al cliente qué esquema debe usar:

```text
Bearer realm="restricted"
ApiKey realm="restricted", header="x-api-key"
Basic realm="Admin area", charset="UTF-8"
```

`Auth::custom` envía un desafío `Bearer`. Con Basic, los navegadores muestran su diálogo de inicio de sesión nativo.

## Peticiones OPTIONS

Los preflights de CORS nunca llevan credenciales, así que `Auth` deja pasar `OPTIONS` por defecto. Cuando hay un guard `Cors` configurado, este responde a los preflights antes incluso de que se ejecute `Auth`. Si su API nunca se llama desde un navegador, `.protect_options()` cierra también esa puerta.

## Conectar una validación JWT

`Auth::custom` acepta cualquier función síncrona. Aquí con el crate `jsonwebtoken`:

```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use securite::prelude::*;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
}

let key = DecodingKey::from_secret(
    std::env::var("JWT_SECRET").expect("JWT_SECRET must be set").as_bytes(),
);
let mut validation = Validation::new(Algorithm::HS256);
validation.set_audience(&["orders-api"]);
validation.set_issuer(&["https://auth.example.com"]);

let auth = Auth::custom(move |token, _req| {
    // Signature, expiry, audience and issuer are checked by `decode`.
    decode::<Claims>(token, &key, &validation)
        .ok()
        .map(|data| data.claims.sub)
})
.protect(["/api"])
.public(["/api/health"]);
```

El validador se ejecuta en la ruta de la petición: limítelo a trabajo de CPU (verificación de firmas, búsquedas en memoria). Cargue las claves de firma o el JWKS al arrancar y refrésquelos en una tarea en segundo plano en lugar de obtenerlos en cada petición. El segundo argumento da acceso a la cabecera de la petición, por ejemplo para leer una cabecera de tenant.

## Varios esquemas en una misma aplicación

Un `Shield` contiene un solo guard por nombre, así que un segundo `Auth` sustituiría al primero. Use en su lugar shields de un solo guard en routers separados: cada uno protege únicamente lo que vive bajo su prefijo de montaje:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let admin_password = std::env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set");
let partner_key = std::env::var("PARTNER_ACME_KEY").expect("PARTNER_ACME_KEY must be set");

let mut admin = Router::new();
admin.middleware(Shield::from(Auth::basic("Admin area").user("admin", &admin_password)));
admin.get("/dashboard", |_req: Request| async { "admin" });

let mut partners = Router::new();
partners.middleware(Shield::from(Auth::api_key("x-api-key").token("partner-acme", &partner_key)));
partners.get("/orders", |_req: Request| async { "[]" });

let mut app = App::new();
app.middleware(Shield::recommended());
app.get("/", |_req: Request| async { "public home" });
app.mount("/admin", admin);
app.mount("/partners", partners);
```

## Errores comunes y consejos

- Sirva las rutas autenticadas solo por HTTPS (`HttpsRedirect` y HSTS); de lo contrario, los tokens y las contraseñas Basic viajan en claro.
- Rote los tokens sin interrupciones: añada el nuevo token con una nueva etiqueta, despliegue, migre los clientes y después retire el antiguo.
- `401` es un estado penalizable por defecto de `AutoBan`: con el [bloqueo automático](/docs/auto-ban) activado, los clientes que insisten en adivinar credenciales quedan bloqueados automáticamente. Añada además un `RateLimit` estricto en los endpoints de tipo inicio de sesión.
- `.public` siempre prevalece sobre `.protect`: compruebe que un prefijo público no cubra por descuido una subruta sensible.
- Con `Auth::custom`, la comparación en tiempo constante es responsabilidad de su validador; las bibliotecas de verificación de firmas ya se ocupan de ello.

## Páginas relacionadas

- [Filtrado por IP](/docs/ip-filter)
- [Bloqueo automático](/docs/auto-ban)
- [Limitación de peticiones](/docs/rate-limit)
- [Redirección HTTPS](/docs/https-redirect)
- [CORS](/docs/cors)
- [Firmas de webhooks](/docs/webhook-signatures)
- [Eventos de seguridad y estadísticas](/docs/events-stats)
