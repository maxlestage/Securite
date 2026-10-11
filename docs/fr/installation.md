---
title: Installation
summary: Ajoutez securite à votre projet, choisissez les bonnes features pour axum, hyper ou tonic, et donnez au shield la véritable adresse IP du client.
category: start
order: 2
---

Securite est une crate classique de crates.io, sans aucune dépendance native : ni OpenSSL, ni chaîne de compilation C, ni script de build à configurer.

## Ajouter la crate

```bash
cargo add securite
```

Ou déclarez-la à la main dans `Cargo.toml` :

```toml
[dependencies]
securite = "0.1"
```

Une application axum typique a besoin de :

```toml
[dependencies]
securite = "0.1"
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

## Prérequis

| Élément | Valeur |
|---|---|
| Version actuelle | 0.1.0 |
| Version minimale de Rust prise en charge | 1.85 (édition 2024) |
| Licence | Propriétaire (© Maxime Nathan Lestage, tous droits réservés) : utilisation libre comme dépendance, voir [LICENSE](https://maxlestage.github.io/Securite/LICENSE.txt) |
| Code unsafe | Aucun, la crate est en `#![forbid(unsafe_code)]` |
| Dépendances natives | Aucune (100 % Rust) |
| Dépôt | `https://maxlestage.github.io/Securite/` |

## Features Cargo

| Feature | Par défaut | Effet |
|---|---|---|
| `axum` | Activée | Lit l'adresse du pair TCP dans l'extension `ConnectInfo<SocketAddr>` d'axum. Ajoute la dépendance `axum` 0.8, avec un minimum de features. |

Si vous utilisez hyper, tonic ou une autre pile tower sans axum, désactivez les features par défaut :

```toml
[dependencies]
securite = { version = "0.1", default-features = false }
```

> **Astuce :** Désactiver la feature `axum` retire uniquement la dépendance à axum. Tous les guards, préréglages et couches restent disponibles ; l'adresse du pair est alors lue dans l'extension de requête `PeerAddr` ou `SocketAddr`.

## Exposer l'IP du client

La limitation de débit, les limites de concurrence, le bannissement automatique et le filtrage IP indexent leur état sur l'adresse du client : le shield doit donc savoir qui se connecte.

### axum

Servez le routeur avec `into_make_service_with_connect_info::<SocketAddr>()` :

```rust
use std::net::SocketAddr;

use axum::{Router, routing::get};
use securite::prelude::*;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .layer(Shield::recommended());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(
        listener,
        // Without this, the shield cannot see the client address.
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

> **Attention :** Avec un simple `axum::serve(listener, app)`, aucune adresse client n'est connue : le limiteur par IP se rabat sur un seau unique partagé par tous les clients, tandis que le bannissement automatique et la limite de concurrence sont ignorés. Le shield le signale par un avertissement journalisé une seule fois, sous la cible `securite`.

> **Attention :** securite lit le type `ConnectInfo` d'axum 0.8. Si votre application dépend d'une autre version majeure d'axum, insérez vous-même `PeerAddr`, comme dans l'exemple hyper ci-dessous.

### hyper

Avec un serveur hyper 1 brut, insérez `PeerAddr` dans chaque requête avant qu'elle n'atteigne le shield. Dépendances de cet exemple :

```toml
[dependencies]
securite = { version = "0.1", default-features = false }
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

tonic enregistre l'adresse du pair dans sa propre extension `TcpConnectInfo`, que securite ne lit pas. Ajoutez devant le shield une étape `map_request` qui copie `remote_addr()` dans `PeerAddr`, exactement comme dans l'exemple hyper, puis ajoutez le shield avec `Server::builder().layer(...)`.

### Derrière un proxy inverse

Derrière Heroku, Cloudflare, Fly.io, un répartiteur de charge ou Nginx, le pair TCP est le proxy, pas le client. Indiquez au shield quel en-tête croire :

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();
```

Définissez la source sur le shield le plus externe : les shields intérieurs et les couches autonomes réutilisent l'adresse qu'il a résolue. La page [IP du client](/docs/client-ip) détaille chaque source et ses risques d'usurpation.

## Vérifier l'installation

Ce handler renvoie l'adresse résolue par le shield. Derrière un proxy, il doit afficher l'IP du visiteur, et non celle du proxy :

```rust
use axum::Extension;
use securite::prelude::*;

async fn whoami(Extension(ClientIp(ip)): Extension<ClientIp>) -> String {
    ip.to_string()
}
```

L'extension `ClientIp` n'existe que si une adresse a pu être résolue ; dans le cas contraire, cet extracteur répond `500`, ce qui rend toute erreur de configuration évidente dès la mise en place. Étape suivante : le [démarrage rapide](/docs/quick-start).
