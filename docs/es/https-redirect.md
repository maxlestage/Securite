---
title: Redirección a HTTPS
summary: Redirige las peticiones HTTP sin cifrar a HTTPS con un 308 y tiene en cuenta los proxies que terminan TLS, como Heroku, Render, AWS ALB o Cloudflare.
category: browser
order: 4
---

`HttpsRedirect` envía cada petición HTTP sin cifrar a su equivalente `https://` con un `308 Permanent Redirect`. Lee el esquema original en la URI de la petición o en las cabeceras que fija su proxy de terminación TLS, y no interfiere con el desarrollo local.

## La amenaza

Con HTTP sin cifrar, cualquiera que esté en el camino de red (Wi-Fi pública, router comprometido, proveedor de acceso) puede leer y modificar el tráfico: credenciales, cookies de sesión, páginas y descargas. Un atacante activo puede además mantener a la víctima en HTTP indefinidamente («SSL stripping»). Es la categoría A02 Cryptographic Failures del OWASP Top 10 2021; las cheat sheets de OWASP Transport Layer Security y HTTP Strict Transport Security, así como la prueba WSTG-CONF-07, tratan el tema.

Una redirección por sí sola no basta, porque la primera petición sigue viajando sin cifrar. La configuración robusta es:

1. `HttpsRedirect` lleva a HTTPS a los visitantes que llegan por HTTP;
2. [HSTS](/docs/security-headers), enviado en las respuestas HTTPS, obliga al navegador a usar HTTPS directamente en las visitas siguientes;
3. opcionalmente, la precarga de HSTS elimina incluso la primerísima petición HTTP.

## Cómo funciona

El guard se ejecuta con la prioridad 75, después del baneo, el filtrado de IP, la higiene y el filtrado de métodos, y justo después de `HostFilter` (70): cuando ambos están en el mismo shield, la redirección solo se construye a partir de un host validado. Sigue ejecutándose antes de la limitación de tasa y del WAF. Determina el esquema en este orden:

1. el esquema de la URI de la petición, si esta usa una URI absoluta;
2. si `trust_forwarded_proto` está activado (por defecto), el valor situado más a la derecha de `X-Forwarded-Proto`, el que escribió el proxy más cercano, con el mismo modelo de confianza que `ClientIpSource::XForwardedFor`;
3. si no, el parámetro `proto=` de la cabecera estándar `Forwarded`;
4. si no hay ninguna de estas informaciones, el esquema es desconocido y **no ocurre nada**, lo que mantiene operativo el desarrollo local.

Si la petición llega por HTTP sin cifrar y su ruta no está exenta, el shield responde `308 Permanent Redirect` con `Location: https://<host><ruta>?<consulta>`. El host procede de la URI o de la cabecera `Host`, sin su puerto. A diferencia de `301` y `302`, un `308` conserva el método y el cuerpo. La redirección es un cortocircuito benigno: cuerpo vacío, no se registra como ataque ni se contabiliza como bloqueo. Un host ausente o mal formado produce `400 Bad Request` con el código `https_required`.

`/.well-known/acme-challenge/` está exenta por defecto para que la validación HTTP-01 de Let's Encrypt siga funcionando.

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let shield = Shield::builder()
        .guard(HttpsRedirect::new())
        .guard(SecurityHeaders::new()) // HSTS for the following visits
        .build();

    let mut app = App::new();
    app.middleware(shield);
    app.get("/", |_req: Request| async { "secure" });
    app
}
```

`Shield::strict()` ya incluye `HttpsRedirect::new()`. El guard se llama `https_redirect`.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `HttpsRedirect::new()` | confía en las cabeceras del proxy, exime ACME | Configuración recomendada. |
| `trust_forwarded_proto(bool)` | `true` | Lee `X-Forwarded-Proto` (el valor más a la derecha) y `Forwarded`. Con `false`, solo una URI de petición absoluta puede revelar el esquema. |
| `exempt(prefix)` | `/.well-known/acme-challenge/` | Añade un prefijo de ruta que nunca se redirige. Se puede llamar varias veces. |

Los prefijos respetan los límites de segmento: `/health` abarca `/health` y `/health/live`, pero no `/healthz`. Si falta la barra inicial, se añade automáticamente.

## Ejemplos

### Detrás de un PaaS o de un balanceador de carga

Heroku, Render, Fly.io, AWS ALB y Cloudflare terminan TLS y fijan `X-Forwarded-Proto`. Las comprobaciones de salud suelen usar HTTP sin cifrar, así que exímalas:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let shield = Shield::builder()
        .client_ip(ClientIpSource::heroku())
        .guard(HttpsRedirect::new().exempt("/health"))
        .guard(SecurityHeaders::new())
        .build();

    let mut app = App::new();
    app.middleware(shield);
    app.get("/", |_req: Request| async { "secure" });
    app.get("/health", |_req: Request| async { "ok" });
    app
}
```

### Comprobar la redirección con curl

```bash
curl -i http://127.0.0.1:3000/path?x=1 \
  -H "Host: example.com" \
  -H "X-Forwarded-Proto: http"
```

```text
HTTP/1.1 308 Permanent Redirect
location: https://example.com/path?x=1
```

### Terminar TLS en su propio proceso

Si la aplicación sirve HTTPS por sí misma y solo escucha en el puerto 80 para redirigir, las peticiones de ese puerto no llevan información de esquema. Márquelas como HTTP sin cifrar antes de que actúe el shield y añada `HostFilter` al mismo shield para que el host se valide antes de la redirección:

```rust
use securite::http::HeaderValue;
use securite::prelude::*;
use vitesse::prelude::*;

// Served on port 80 only; the real application listens on 443.
pub fn port_80_app() -> App {
    let shield = Shield::builder()
        .guard(HostFilter::new(["example.com", "www.example.com"])) // priority 70
        .guard(HttpsRedirect::new()) // priority 75: only sees allowed hosts
        .build();

    let mut app = App::new();
    // Primer middleware, así que se ejecuta primero: aquí todo llega por HTTP sin cifrar.
    app.middleware(|mut req: Request, next: Next| async move {
        req.headers_mut()
            .insert("x-forwarded-proto", HeaderValue::from_static("http"));
        next.run(req).await
    });
    app.middleware(shield);
    app.fallback(|_req: Request| async { StatusCode::NOT_FOUND }); // reached by exempt paths only
    app
}
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(HttpsRedirect::new()));
    app.get("/", |_req: Request| async { "ok" });
    app
}
```

## Errores comunes y consejos

> **Consejo:** la cabecera `Location` se construye a partir de la cabecera `Host`, y un `308` puede guardarse en caché. Añada [HostFilter](/docs/host-filter) al mismo `Shield`: se ejecuta con la prioridad 70, antes que `HttpsRedirect` (75), de modo que un host falsificado se rechaza con `421` en lugar de redirigirse. Con capas independientes, coloque `HostFilter` por fuera de `HttpsRedirect`.

- **Sin esquema no hay redirección**: si ni la URI ni una cabecera del proxy revelan el esquema, el guard no hace nada. Compruébelo en preproducción con el comando curl anterior.
- **Confíe en el proxy, no en el cliente**: `X-Forwarded-Proto` solo es fiable si su proxy lo establece. El guard lee el valor situado más a la derecha, escrito por el proxy más cercano a su aplicación, por lo que se ignora cualquier valor que el cliente haya colocado a su izquierda. Con `trust_forwarded_proto(false)`, un servidor sin proxy solo redirige las peticiones con URI absoluta.
- **Proxies encadenados**: cuando varios proxies añaden cada uno un valor a `X-Forwarded-Proto`, el situado más a la derecha solo describe el último salto. Si ese salto usa HTTP sin cifrar, todas las peticiones se redirigen: haga que el proxy más cercano a su aplicación transmita el esquema del cliente en lugar de añadir el suyo.
- **Puertos**: la redirección apunta siempre al puerto HTTPS por defecto, el 443.
- **API**: un cliente que sigue la redirección ya ha enviado su token sin cifrar. Para una API pura, es preferible no escuchar en HTTP en absoluto.
- **Comprobaciones de salud**: un balanceador que comprueba por HTTP recibiría un `308` y marcaría la instancia como no disponible; exima su ruta.

> **Consejo:** combine la redirección con el HSTS de [SecurityHeaders](/docs/security-headers) y las cookies seguras de [CookieHardening](/docs/cookies): juntos mantienen las sesiones lejos de HTTP sin cifrar.

## Páginas relacionadas

- [Cabeceras de seguridad](/docs/security-headers)
- [Filtro de hosts](/docs/host-filter)
- [Endurecimiento de cookies](/docs/cookies)
- [IP del cliente](/docs/client-ip)
