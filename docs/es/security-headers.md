---
title: Cabeceras de seguridad
summary: Cabeceras de respuesta al estilo Helmet, con una Content-Security-Policy estricta (nonces o hashes), HSTS, aislamiento cross-origin y eliminación de huellas del servidor.
category: browser
order: 1
---

`SecurityHeaders` añade a cada respuesta las cabeceras que recomienda el [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), incluidas las respuestas de error que generan los demás guards. También incluye un builder tipado para la `Content-Security-Policy`, con nonces por petición y hashes para scripts inline. Todos los presets de `Shield` lo incorporan.

## La amenaza

El navegador hace todo lo que sus respuestas le permiten. Sin instrucciones explícitas, ejecuta scripts inyectados, deja que otros sitios incrusten sus páginas en frames, adivina tipos de contenido y recurre a HTTP sin cifrar. Estas cabeceras cierran esas puertas:

- **Cross-site scripting** (OWASP Top 10 2021 A03 Injection): una CSP estricta impide que se ejecuten scripts inyectados, incluso cuando se cuela un fallo de escapado.
- **Clickjacking**: `frame-ancestors 'none'` y `X-Frame-Options: DENY` prohíben la inserción en frames.
- **Detección del tipo MIME**: `X-Content-Type-Options: nosniff`.
- **Degradación de protocolo y SSL stripping** (A02 Cryptographic Failures): `Strict-Transport-Security`.
- **Fugas cross-origin y canales laterales tipo Spectre**: COOP, CORP y, opcionalmente, COEP aíslan su origen.
- **Identificación del servidor**: se eliminan `Server`, `X-Powered-By` y cabeceras similares.

La ausencia de estas cabeceras es uno de los hallazgos más habituales de la categoría A05 Security Misconfiguration.

## Cómo funciona

El guard tiene prioridad 900, por lo que se ejecuta después de los guards que bloquean. En la petición solo actúa si los nonces están activados: obtiene 128 bits del generador criptográfico del sistema operativo, los codifica en base64url y los guarda en la extensión de petición `CspNonce`. En la respuesta:

1. elimina `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` y `X-Runtime`;
2. añade cada cabecera configurada **solo si el handler no la ha definido ya** (salvo con `overwrite(true)`);
3. escribe la CSP sustituyendo el nonce. Si un guard que se ejecuta antes rechazó la petición, no se generó ningún nonce: la política se envía entonces completa, sin la fuente del nonce, nunca truncada.

La política se genera y se valida una sola vez, al construir el guard: un valor inválido provoca un pánico al arrancar, nunca durante una petición.

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::builder().guard(SecurityHeaders::new()).build());
    app.get("/", |_req: Request| async { "Hello" });
    app
}
```

Añadir un guard con el mismo nombre sustituye al existente, así que endurecer un preset cabe en una línea:

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    ShieldBuilder::recommended()
        .guard(SecurityHeaders::strict()) // replaces the preset's SecurityHeaders::new()
        .build()
}
```

## Cabeceras por defecto

| Cabecera | `new()` | `strict()` | `api()` |
|---|---|---|---|
| `Content-Security-Policy` | `ContentSecurityPolicy::strict()` | igual | `ContentSecurityPolicy::api()` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | igual | igual |
| `X-Content-Type-Options` | `nosniff` | igual | igual |
| `X-Frame-Options` | `DENY` | igual | igual |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `no-referrer` | `no-referrer` |
| `Permissions-Policy` | desactiva 15 funciones (ver más abajo) | igual | igual |
| `Cross-Origin-Opener-Policy` | `same-origin` | igual | igual |
| `Cross-Origin-Resource-Policy` | `same-origin` | igual | igual |
| `Cross-Origin-Embedder-Policy` | no se envía | `require-corp` | no se envía |
| `Origin-Agent-Cluster` | `?1` | igual | igual |
| `X-DNS-Prefetch-Control` | `off` | igual | igual |
| `X-Download-Options` | `noopen` | igual | igual |
| `X-Permitted-Cross-Domain-Policies` | `none` | igual | igual |
| `X-XSS-Protection` | `0` (el antiguo filtro XSS es perjudicial) | igual | igual |
| `Cache-Control` | no se envía | no se envía | `no-store` |

La `Permissions-Policy` por defecto asigna una lista vacía a `accelerometer`, `autoplay`, `camera`, `display-capture`, `encrypted-media`, `geolocation`, `gyroscope`, `magnetometer`, `microphone`, `midi`, `payment`, `picture-in-picture`, `screen-wake-lock`, `usb` y `xr-spatial-tracking`. `publickey-credentials-get` no se restringe, así que las passkeys (inicio de sesión WebAuthn) funcionan por defecto.

`ContentSecurityPolicy::strict()` genera `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`. `ContentSecurityPolicy::api()` genera `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.

## Configuración

### SecurityHeaders

| Método | Valor por defecto | Descripción |
|---|---|---|
| `new()` / `strict()` / `api()` | — | Presets descritos arriba. |
| `csp(policy)` / `content_security_policy(policy)` | `ContentSecurityPolicy::strict()` | Define la CSP. Acepta una política o un `Option`. |
| `hsts(Option<Hsts>)` | `Hsts::default()` | Configura HSTS; `None` lo elimina. |
| `frame_options(&str)` | `DENY` | `X-Frame-Options` (`DENY` o `SAMEORIGIN`). |
| `referrer_policy(&str)` | `strict-origin-when-cross-origin` | `Referrer-Policy`. |
| `permissions_policy(&str)` | ver arriba | `Permissions-Policy`. |
| `cross_origin_opener_policy(&str)` | `same-origin` | COOP. |
| `cross_origin_resource_policy(&str)` | `same-origin` | CORP (`same-origin`, `same-site`, `cross-origin`). |
| `cross_origin_embedder_policy(&str)` | no se envía | COEP (`require-corp`, `credentialless`). |
| `cache_control(&str)` | no se envía | `Cache-Control`. |
| `set(name, value)` | — | Define o sustituye cualquier cabecera. Provoca un pánico si el nombre o el valor no son válidos. |
| `unset(name)` | — | Elimina una cabecera configurada; `unset("content-security-policy")` desactiva la CSP. |
| `overwrite(bool)` | `false` | Con `true`, sustituye las cabeceras que ya definieron los handlers. |
| `keep_fingerprinting_headers()` | cabeceras eliminadas | Conserva `Server`, `X-Powered-By` y similares. |
| `policy()` | — | Devuelve la CSP configurada, si la hay. |

### ContentSecurityPolicy

| Método | Valor por defecto | Descripción |
|---|---|---|
| `new()` | vacía | Política vacía. |
| `strict()` / `api()` | — | Presets descritos arriba. |
| `default_src`, `script_src`, `script_src_elem`, `script_src_attr`, `style_src`, `style_src_elem`, `style_src_attr`, `img_src`, `font_src`, `connect_src`, `media_src`, `object_src`, `frame_src`, `child_src`, `worker_src`, `manifest_src`, `frame_ancestors`, `base_uri`, `form_action`, `sandbox`, `report_to`, `report_uri` | según el preset | Definen (sustituyen) la directiva correspondiente con las fuentes indicadas. |
| `directive(name, sources)` | — | Define o sustituye cualquier directiva. |
| `add_sources(name, sources)` | — | Añade fuentes a una directiva y la crea si no existe. El nombre se normaliza (sin espacios, en minúsculas). |
| `remove_directive(name)` | — | Elimina una directiva, por ejemplo `upgrade-insecure-requests` para el desarrollo por HTTP sin cifrar. |
| `upgrade_insecure_requests()` | activa en `strict()` | Añade `upgrade-insecure-requests`. |
| `require_trusted_types()` | inactiva | Añade `require-trusted-types-for 'script'` (XSS basado en DOM). |
| `with_nonce()` | inactiva | Nonce nuevo en cada petición, añadido a `script-src`, `script-src-elem` y `style-src`. Si falta `script-src`, añade uno formado por las fuentes de `default-src` y el nonce. |
| `report_only()` | inactiva | Envía `Content-Security-Policy-Report-Only` en su lugar. |
| `hashes_for_inline_scripts(html)` | — | Devuelve las fuentes `'sha256-…'` de cada `<script>` inline de `html`. |
| `hashes_for_inline_styles(html)` | — | Lo mismo para los elementos `<style>` inline. |

Las palabras clave de fuente están en `securite::headers::src`: `SELF`, `NONE`, `UNSAFE_INLINE`, `UNSAFE_EVAL`, `WASM_UNSAFE_EVAL`, `STRICT_DYNAMIC`, `UNSAFE_HASHES`, `DATA`, `BLOB` y `HTTPS`. También sirven cadenas simples como `"https://cdn.example.com"`. Una fuente que contenga `;`, `,` o un carácter de control provoca un pánico, lo que descarta la inyección de cabeceras. `policy.to_string()` muestra el valor generado.

### Hsts

`securite::headers::Hsts` es una estructura sencilla con campos públicos: `max_age` (dos años por defecto), `include_subdomains` (`true` por defecto) y `preload` (`false` por defecto). Ningún preset activa `preload`, ni siquiera `strict()`; actívelo de forma explícita:

```rust
use securite::headers::Hsts;
use securite::prelude::*;

pub fn headers() -> SecurityHeaders {
    // Only once the domain and every sub-domain are HTTPS only.
    SecurityHeaders::strict().hsts(Some(Hsts { preload: true, ..Hsts::default() }))
}
```

## Ejemplos

### Nonces en páginas renderizadas en el servidor

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn index(req: Request) -> Html<String> {
    let nonce = req.get::<CspNonce>().map(|n| n.0.clone()).unwrap_or_default();
    Html(format!(
        r#"<!doctype html>
<script nonce="{nonce}">console.log("runs: it carries the nonce");</script>
<script>console.log("blocked: no nonce");</script>"#
    ))
}

pub fn app() -> App {
    let headers = SecurityHeaders::new().csp(ContentSecurityPolicy::strict().with_nonce());
    let mut app = App::new();
    app.middleware(Shield::builder().guard(headers).build());
    app.get("/", index);
    app
}
```

### Hashes para aplicaciones de una sola página

Vite y otros bundlers similares inyectan un script de arranque inline en `index.html`, y los front-ends Rust renderizados en el servidor escriben uno para arrancar su bundle WebAssembly (este sitio, construido con [Active](https://active-c1883a966650.herokuapp.com/), permite así su cargador y el registro de su service worker). Calcule su hash al arrancar y mantenga un `script-src` estricto:

```rust
use securite::headers::src;
use securite::prelude::*;
use vitesse::prelude::*;

pub fn spa(index_html: String) -> App {
    let csp = ContentSecurityPolicy::strict()
        .add_sources("script-src", ContentSecurityPolicy::hashes_for_inline_scripts(&index_html))
        .add_sources("script-src", [src::WASM_UNSAFE_EVAL]); // Rust/WASM front-ends
    let mut app = App::new();
    app.middleware(Shield::from(SecurityHeaders::new().csp(csp)));
    app.get("/", move |_req: Request| {
        let html = index_html.clone();
        async move { Html(html) }
    });
    app
}
```

### Una política strict-dynamic

Es la política basada en nonces que recomiendan las buenas prácticas actuales. Los navegadores que entienden los nonces ignoran `https:` y `'unsafe-inline'`, que solo sirven de respaldo para navegadores antiguos:

```rust
use securite::headers::src;
use securite::prelude::*;

pub fn policy() -> ContentSecurityPolicy {
    ContentSecurityPolicy::new()
        .script_src([src::STRICT_DYNAMIC, src::HTTPS, src::UNSAFE_INLINE])
        .object_src([src::NONE])
        .base_uri([src::NONE])
        .frame_ancestors([src::NONE])
        .with_nonce()
}
```

### Despliegue en modo report-only y Trusted Types

```rust
use securite::prelude::*;

pub fn rollout() -> SecurityHeaders {
    SecurityHeaders::new()
        .csp(
            ContentSecurityPolicy::strict()
                .require_trusted_types()
                .report_to(["csp"])
                .report_only(),
        )
        .set("reporting-endpoints", r#"csp="https://example.com/csp-reports""#)
}
```

Recoja las infracciones durante unos días, corríjalas y después elimine `report_only()`.

### Relajar una cabecera en una sola ruta

Por defecto prevalecen las cabeceras que define el handler, de modo que una ruta puede ser la excepción:

```rust
use vitesse::prelude::*;

// This widget may be framed by a partner site; CSP frame-ancestors overrides X-Frame-Options.
pub async fn widget(_req: Request) -> Response {
    res::html("<p>Embeddable widget</p>")
        .header("content-security-policy", "default-src 'self'; frame-ancestors https://partner.example.com")
}
```

### HSTS a medida y desarrollo local

```rust
use std::time::Duration;

use securite::headers::Hsts;
use securite::prelude::*;

pub fn headers(dev: bool) -> SecurityHeaders {
    if dev {
        // Plain-HTTP local development: no HSTS, no upgrade-insecure-requests.
        return SecurityHeaders::new()
            .hsts(None)
            .csp(ContentSecurityPolicy::strict().remove_directive("upgrade-insecure-requests"));
    }
    SecurityHeaders::new().hsts(Some(Hsts {
        max_age: Duration::from_secs(31_536_000), // one year
        include_subdomains: true,
        preload: false,
    }))
}
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(SecurityHeaders::strict()));
    app.get("/", |_req: Request| async { "ok" });
    app
}
```

## Errores comunes y consejos

> **Atención:** `preload` es difícil de revertir. En cuanto un dominio sirve esa directiva, puede enviarse a la lista de precarga HSTS de los navegadores, y todos sus subdominios quedarán limitados a HTTPS durante meses. Ningún preset la envía: actívela solo de forma deliberada, como se muestra en la sección Hsts anterior.

- **Contenido multimedia y pagos**: la `Permissions-Policy` por defecto desactiva también en sus propias páginas `encrypted-media`, `autoplay` y `payment`; las passkeys (`publickey-credentials-get`) no se restringen. Sustitúyala, por ejemplo con `permissions_policy("camera=(), microphone=(), geolocation=(), payment=(self)")`.
- **Frames**: para permitir que sus propias páginas lo incrusten, cambie ambas cabeceras: `.frame_options("SAMEORIGIN")` y `frame_ancestors([src::SELF])` en la CSP.
- **Recursos públicos**: CORP `same-origin` impide que otros sitios incrusten sus imágenes o fuentes. Un servidor de recursos públicos necesita `cross_origin_resource_policy("cross-origin")`.
- **COEP**: `require-corp`, incluido en `strict()`, bloquea los recursos cross-origin que no lo aceptan mediante CORP o CORS. `credentialless` es una alternativa más flexible.
- **Nonces**: `with_nonce()` también añade el nonce a `style-src`, donde `'unsafe-inline'` pasa a ignorarse. Los atributos `style="…"` inline necesitan `style_src_attr([src::UNSAFE_INLINE])`. Si la política no tiene `script-src`, `with_nonce()` añade uno formado por las fuentes de `default-src` y el nonce (`script-src 'self' 'nonce-…'` tras `default-src 'self'`), de modo que los ficheros de script del mismo origen se siguen cargando.
- **Caché**: no deje nunca que una caché compartida almacene una página HTML con nonce. El HTML estático debe usar hashes.
- **Nonce ausente**: sin `with_nonce()`, `req.get::<CspNonce>()` es `None`.
- **HTTP sin cifrar**: `upgrade-insecure-requests` rompe los subrecursos de un sitio servido por HTTP simple, por ejemplo en una dirección de la red local. Elimínela en ese caso con `ContentSecurityPolicy::strict().remove_directive("upgrade-insecure-requests")`, como en el ejemplo de desarrollo local anterior.
- **Sobrescritura**: por defecto prevalecen las cabeceras de los handlers. Use `.overwrite(true)` si ninguna ruta debe poder debilitar la política.
- **Proxies**: las cabeceras de identificación solo se eliminan de las respuestas que atraviesan la capa; un proxy inverso puede añadir su propia cabecera `Server`.

> **Consejo:** despliegue siempre cualquier cambio de CSP primero con `report_only()` y aplíquelo después.

## Páginas relacionadas

- [CORS](/docs/cors)
- [Endurecimiento de cookies](/docs/cookies)
- [Redirección a HTTPS](/docs/https-redirect)
- [Protección CSRF](/docs/csrf)
- [Shield y presets](/docs/shield-presets)
