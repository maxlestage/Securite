---
title: Identificadores de petición
summary: Asigna a cada petición un identificador único y validado que llega a sus handlers, a sus registros, a cada evento de seguridad y a cada respuesta de error.
category: integrity
order: 1
---

Cuando un cliente informa de que «la web le ha respondido Forbidden», hay que encontrar esa petición concreta entre millones de líneas de registro. `RequestId` asigna un identificador a cada petición, lo pasa a sus handlers, lo devuelve en la respuesta y lo adjunta a cada evento de seguridad y a cada cuerpo de error: un único valor enlaza lo que vio el cliente, lo que decidió el escudo y lo que registró su aplicación.

## Por qué es importante

- **A09:2021 Security Logging and Monitoring Failures**: sin un identificador de correlación, no se puede reconstruir un incidente ni relacionar una alerta con los registros de la aplicación.
- **Inyección en registros (CWE-117)**: los identificadores enviados por el cliente solo se reutilizan si son cortos y están formados por caracteres seguros, de modo que nadie puede falsificar líneas de registro ni inyectar marcado en sus paneles a través de esta cabecera.

## Funcionamiento

1. El guard se ejecuta el primero de la cadena, para que todas las decisiones posteriores puedan hacer referencia al identificador.
2. Si la petición ya trae la cabecera (por defecto `X-Request-Id`) con un valor válido, se conserva. Válido significa entre 1 y 128 caracteres de `A-Z`, `a-z`, `0-9`, `-`, `_`, `.` y `:`.
3. Si no, se genera un identificador nuevo con formato UUID v4, por ejemplo `3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44`.
4. La cabecera se (re)escribe en la petición y se inserta un `RequestIdValue` en sus extensiones.
5. El identificador se devuelve en la cabecera de la respuesta, también en los rechazos, y se añade a `SecurityEvent::request_id`, a los registros de tracing del target `securite` y al campo `request_id` de los cuerpos de error problem+json.

## Inicio rápido

`RequestId::new()` forma parte de todos los presets. En un escudo a medida:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::builder().guard(RequestId::new()).build());
app.get("/", |_req: Request| async { "home" });
```

```bash
curl -i https://example.com/
# HTTP/2 200
# x-request-id: 3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `RequestId::new()` | `x-request-id`, reutiliza los identificadores entrantes seguros | Crea el guard (`RequestId::default()` es equivalente). |
| `.header(name)` | `x-request-id` | Nombre de cabecera personalizado, como `x-correlation-id`; provoca un pánico si el nombre no es válido. |
| `.always_generate()` | desactivado | Ignora los identificadores entrantes y genera siempre uno nuevo. |
| `RequestId::generate()` | — | Devuelve un identificador nuevo con formato UUID v4 (`String`). |

## Leer el identificador en los handlers

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn create_order(req: Request) -> String {
    let id = req.get::<RequestIdValue>().map(|id| id.as_str().to_owned()).unwrap_or_default();
    tracing::info!(request_id = %id, "creating order");
    format!("order accepted, reference {id}")
}

let mut app = App::new();
app.middleware(Shield::builder().guard(RequestId::new()).build());
app.post("/orders", create_order);
```

`RequestIdValue` envuelve el `HeaderValue` (`id.0`), que puede copiar tal cual en las cabeceras de sus peticiones salientes para propagar el identificador a los servicios posteriores.

## Añadir el identificador a cada línea de registro

Con `tower-http`, abra por cada petición un span que lleve el identificador. La capa de trazas debe quedar por debajo del escudo para que la extensión ya esté presente:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Añadido primero, así que se ejecuta primero: el identificador existe para los middlewares siguientes.
app.middleware(Shield::recommended());
app.middleware(|req: Request, next: Next| async move {
    let id = req.get::<RequestIdValue>().map(|id| id.as_str().to_owned()).unwrap_or_default();
    let line = format!("{} {} request_id={id}", req.method(), req.path());
    let res = next.run(req).await;
    tracing::info!(status = res.status_code().as_u16(), "{line}");
    res
});
app.get("/", |_req: Request| async { "home" });
```

## Detrás de un proxy o de una plataforma

El router de Heroku, muchos balanceadores de carga y Nginx (`proxy_set_header X-Request-Id $request_id;`) ya establecen un identificador de petición. `RequestId::new()` lo reutiliza cuando es válido, de modo que el mismo valor aparece en los registros de la plataforma y en los de su aplicación. Si su organización sigue otra convención, cambie el nombre de la cabecera:

```rust
use securite::prelude::*;

let request_id = RequestId::new().header("x-correlation-id");
```

Si los clientes pueden acceder directamente a la aplicación, pueden elegir su propio identificador. La validación lo hace inofensivo para sus registros, pero un cliente podría reutilizar el identificador de otra petición para enturbiar una investigación. Use `.always_generate()` cuando ningún proxy de confianza establezca la cabecera:

```rust
use securite::prelude::*;

let request_id = RequestId::new().always_generate();
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(RequestId::new()));
app.get("/", |_req: Request| async { "home" });
```

> **Atención:** una capa `RequestId` independiente tiene su propio escudo interno. Otro `Shield` de la misma pila no conocerá el identificador: sus eventos y sus cuerpos problem+json no lo incluirán. Registre `RequestId` en el mismo escudo que sus demás guards, como hacen los presets.

## Errores comunes y consejos

- Los identificadores son aleatorios, pero los produce un generador rápido y no criptográfico. Son identificadores de correlación, no secretos: no los use nunca como tokens de sesión, nonces ni claves de autorización.
- El identificador también se devuelve en las peticiones bloqueadas. Muéstrelo en sus páginas de error para que los usuarios puedan facilitarlo a su equipo de soporte.
- Mantenga el mismo nombre de cabecera en todos sus servicios: una sola búsqueda en su plataforma de registros seguirá una petición de principio a fin.

## Páginas relacionadas

- [Eventos de seguridad y estadísticas](/docs/events-stats)
- [Formato de las respuestas de error](/docs/error-format)
- [IP del cliente](/docs/client-ip)
