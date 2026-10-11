---
title: Filtrado de métodos
summary: Permita solo los métodos HTTP que usa su aplicación, rechace TRACE, CONNECT y los verbos WebDAV, y bloquee las cabeceras de sobrescritura de método.
category: traffic
order: 6
---

`MethodFilter` es una lista blanca global de métodos HTTP. Las peticiones con cualquier otro método se rechazan con `405 Method Not Allowed` y una cabecera `Allow`, antes de que el enrutamiento, la limitación de peticiones o el WAF les dediquen un solo instante. Por defecto, también rechaza las cabeceras de sobrescritura de método.

## Amenazas que mitiga

* **Cross-Site Tracing (XST)**: `TRACE` devuelve la petición tal cual, cookies y cabeceras de autorización incluidas, lo que puede anular la protección `HttpOnly` cuando un proxy o un framework lo implementa.
* **Abuso de proxy**: `CONNECT` convierte un servidor o un proxy mal configurado en un túnel abierto.
* **Superficie de ataque inesperada**: los verbos WebDAV (`PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK` …) y los métodos personalizados llegan a código que nadie ha probado, y son de los favoritos de los escáneres.
* **Elusión del control de acceso mediante sobrescritura de método**: cabeceras como `X-HTTP-Method-Override: DELETE` hacen que los frameworks o proxies que las respetan traten un `POST` como otro método, saltándose las reglas escritas para el método real (OWASP A01:2021, Broken Access Control).

## Funcionamiento

```text
request ----> method in allow-list?
                no  -> 405 method_not_allowed + Allow: GET, HEAD, POST, ...
                yes -> override header present and not allowed?
                         yes -> 400 method_override
                         no  -> next guard
```

* La lista blanca por defecto es `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`.
* El valor de la cabecera `Allow` se calcula una sola vez, al construir el filtro.
* Las cabeceras de sobrescritura bloqueadas son `X-HTTP-Method-Override`, `X-HTTP-Method` y `X-Method-Override`, sea cual sea su valor.
* El guard se ejecuta con prioridad 60, después de `Hygiene` y antes de `HostFilter`, `BodyLimit`, CORS y la limitación de peticiones.

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::builder().guard(MethodFilter::new()).build());
app.get("/", |_req: Request| async { "hello" });
```

`MethodFilter::new()` ya forma parte de los preajustes `recommended`, `strict` y `api`.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `MethodFilter::new()` | – | `GET HEAD POST PUT PATCH DELETE OPTIONS`, cabeceras de sobrescritura bloqueadas. |
| `MethodFilter::only(methods)` | – | Exactamente estos métodos (sustituye la lista por defecto). Entra en pánico con una lista vacía. |
| `MethodFilter::read_only()` | – | Solo `GET HEAD OPTIONS`. |
| `.allow_method_override()` | bloqueadas | Acepta las cabeceras de sobrescritura de método (clientes heredados). |

## Ejemplos

### Un sitio de solo lectura

Un sitio de documentación, una página de estado o un espejo público nunca necesitan escrituras:

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .guard(MethodFilter::read_only())
    .build();
```

### Una lista exacta con un método personalizado

`only` sustituye la lista por defecto, así que enumere todo lo que necesite, incluidos verbos personalizados como un `PURGE` de caché:

```rust
use securite::http::Method;
use securite::prelude::*;

let purge = Method::from_bytes(b"PURGE").expect("valid method");
let filter = MethodFilter::only([
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::OPTIONS,
    purge,
]);
```

### Clientes heredados que necesitan la sobrescritura de método

Algunos formularios HTML antiguos y clientes de la época de SOAP solo saben enviar `GET` y `POST`. Si su framework depende de las cabeceras de sobrescritura, vuelva a activarlas de forma explícita:

```rust
use securite::prelude::*;

let filter = MethodFilter::new().allow_method_override();
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(MethodFilter::read_only()));
app.get("/", |_req: Request| async { "hello" });
```

## Cabeceras de respuesta

Un método rechazado recibe una cabecera `Allow` con los métodos aceptados, como exige la RFC 9110:

```text
HTTP/1.1 405 Method Not Allowed
allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Method Not Allowed","status":405,"code":"method_not_allowed","detail":"Method not allowed."}
```

Una cabecera de sobrescritura recibe `400 Bad Request` con el código `method_override`. El método rechazado se anota en los detalles de auditoría del evento de seguridad (`method=TRACE`), nunca en la respuesta al cliente.

## Errores comunes y consejos

* **Mantenga `OPTIONS` si usa CORS**: los navegadores envían las peticiones de verificación previa (preflight) con `OPTIONS`, y el filtrado de métodos se ejecuta antes que el guard de CORS. Sin él, cada preflight entre orígenes falla con `405`.
* **Mantenga `HEAD` junto a `GET`**: las sondas de disponibilidad, los rastreadores y los comprobadores de enlaces lo usan, y Vitesse responde a `HEAD` en todas las rutas `GET`.
* `MethodFilter` es global. Las restricciones de método por ruta siguen siendo cosa de su router (Vitesse responde `405` a una ruta conocida con un método no enrutado).
* Los nombres de método distinguen mayúsculas y minúsculas: `get` no es `GET`, y se rechaza.

> **Consejo:** el evento de seguridad de un método rechazado incluye su nombre. Un pico de `TRACE`, `PROPFIND` o `DEBUG` suele indicar que un escáner está recorriendo su sitio; el [bloqueo automático](/docs/auto-ban), en el mismo shield, cuenta cada método rechazado como una penalización y puede detenerlo.

## Páginas relacionadas

* [Higiene HTTP](/docs/hygiene)
* [Límite de tamaño del cuerpo](/docs/body-limit)
* [Bloqueo automático](/docs/auto-ban)
* [CORS](/docs/cors)
