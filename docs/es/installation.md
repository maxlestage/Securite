---
title: Instalación
summary: Añade Securite a tu proyecto, elige las features adecuadas para Vitesse, hyper o tonic y dale al shield la dirección IP real del cliente.
category: start
order: 2
---

Securite es un crate normal de crates.io sin dependencias nativas: ni OpenSSL, ni toolchain de C, ni scripts de build que configurar.

## Añadir el crate

```bash
cargo add securite --git https://github.com/maxlestage/Securite
```

O decláralo a mano en `Cargo.toml`:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite" }
```

Una aplicación Vitesse típica necesita:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite" }
vitesse = { git = "https://github.com/maxlestage/Vitesse" }
```

## Requisitos

| Elemento | Valor |
|---|---|
| Versión actual | 0.1.0 |
| Versión mínima de Rust soportada | 1.85 (edición 2024) |
| Licencia | Propietaria (© Maxime Nathan Lestage, todos los derechos reservados): uso libre como dependencia, ver [LICENSE](https://maxlestage.github.io/Securite/LICENSE.txt) |
| Código unsafe | Ninguno, el crate usa `#![forbid(unsafe_code)]` |
| Dependencias nativas | Ninguna (Rust puro) |
| Repositorio | `https://maxlestage.github.io/Securite/` |

## Features de Cargo

| Feature | Por defecto | Efecto |
|---|---|---|
| `vitesse` | Activada | El `Shield` y el `SignatureLayer` son middlewares de Vitesse: `app.middleware(Shield::recommended())`. Incorpora `vitesse` con las features mínimas. |

Si usas hyper, tonic u otro stack tower sin Vitesse, desactiva las features por defecto:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite", default-features = false }
```

> **Consejo:** Desactivar la feature `vitesse` solo elimina la dependencia de Vitesse. Todos los guards, presets y capas tower siguen disponibles; la dirección del peer se lee entonces de la extensión de petición `PeerAddr` o `SocketAddr`.

## Exponer la IP del cliente

La limitación de tasa, los límites de concurrencia, el baneo automático y el filtrado de IP indexan su estado por la dirección del cliente, así que el shield necesita saber quién se conecta.

### Vitesse

Nada que configurar: Vitesse entrega al shield la dirección de cada conexión.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    // El shield lee la dirección de cada conexión: no hay nada más que hacer.
    app.middleware(Shield::recommended());
    app.get("/", |_req: Request| async { "Hello, secure world!" });
    app.run(3000)
}
```

> **Atención:** En un servicio tower sin `PeerAddr` (ver más abajo) no se conoce ninguna dirección de cliente: el limitador por IP recurre a un único cubo compartido por todos los clientes, y el baneo automático y el límite de concurrencia se omiten. El shield lo señala con una advertencia que registra una sola vez, bajo el target `securite`.

### hyper

Con un servidor hyper 1 sin framework, inserta `PeerAddr` en cada petición antes de que llegue al shield. Dependencias de este ejemplo:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite", default-features = false }
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "service"] }
http = "1"
http-body-util = "0.1"
bytes = "1"
tower = { version = "0.5", features = ["util"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

```rust
use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use securite::prelude::*;
use tower::{ServiceBuilder, service_fn};

async fn hello(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(b"Hello, secure world!"))))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shield = Shield::recommended();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let svc = ServiceBuilder::new()
            // Tell the shield who the client is.
            .map_request(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(PeerAddr(peer));
                req
            })
            .layer(shield.clone())
            .service(service_fn(hello));

        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(svc))
                .await;
        });
    }
}
```

### tonic

tonic guarda la dirección del peer en su propia extensión `TcpConnectInfo`, que securite no lee. Añade delante del shield un paso `map_request` que copie `remote_addr()` en `PeerAddr`, exactamente igual que en el ejemplo de hyper, y luego añade el shield con `Server::builder().layer(...)`.

### Detrás de un proxy inverso

Detrás de Heroku, Cloudflare, Fly.io, un balanceador de carga o Nginx, el peer TCP es el proxy, no el cliente. Indica al shield de qué cabecera debe fiarse:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();
```

Configura la fuente en el shield más externo: los shields interiores y los guards independientes reutilizan la dirección que este resolvió. La página [IP del cliente](/docs/client-ip) explica cada fuente y sus riesgos de suplantación.

## Comprobar la configuración

Este handler devuelve la dirección que ha resuelto el shield. Detrás de un proxy debe mostrar la IP del visitante, no la del proxy:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn whoami(req: Request) -> String {
    match req.get::<ClientIp>() {
        Some(ClientIp(ip)) => ip.to_string(),
        None => "unknown".to_owned(),
    }
}
```

El valor `ClientIp` solo existe cuando se ha podido resolver una dirección: si el handler muestra `unknown`, corrige la configuración antes de pasar a producción. Siguiente paso: el [inicio rápido](/docs/quick-start).
