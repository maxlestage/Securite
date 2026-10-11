---
title: Installation
summary: Ajoutez Securite à votre projet, choisissez les bonnes features pour Vitesse, hyper ou tonic, et donnez au shield la véritable adresse IP du client.
category: start
order: 2
---

Securite est une crate classique de crates.io, sans aucune dépendance native : ni OpenSSL, ni chaîne de compilation C, ni script de build à configurer.

## Ajouter la crate

```bash
cargo add securite --git https://github.com/maxlestage/Securite
```

Ou déclarez-la à la main dans `Cargo.toml` :

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite" }
```

Une application Vitesse typique a besoin de :

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite" }
vitesse = { git = "https://github.com/maxlestage/Vitesse" }
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
| `vitesse` | Activée | Le `Shield` et le `SignatureLayer` sont des middlewares Vitesse : `app.middleware(Shield::recommended())`. Ajoute la dépendance `vitesse`, avec un minimum de features. |

Si vous utilisez hyper, tonic ou une autre pile tower sans Vitesse, désactivez les features par défaut :

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite", default-features = false }
```

> **Astuce :** Désactiver la feature `vitesse` retire uniquement la dépendance à Vitesse. Tous les guards, préréglages et couches tower restent disponibles ; l'adresse du pair est alors lue dans l'extension de requête `PeerAddr` ou `SocketAddr`.

## Exposer l'IP du client

La limitation de débit, les limites de concurrence, le bannissement automatique et le filtrage IP indexent leur état sur l'adresse du client : le shield doit donc savoir qui se connecte.

### Vitesse

Rien à configurer : Vitesse transmet au shield l'adresse de chaque connexion.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    // Le shield lit l'adresse de chaque connexion : rien d'autre à faire.
    app.middleware(Shield::recommended());
    app.get("/", |_req: Request| async { "Hello, secure world!" });
    app.run(3000)
}
```

> **Attention :** Dans un service tower sans `PeerAddr` (voir ci-dessous), aucune adresse client n'est connue : le limiteur par IP se rabat sur un seau unique partagé par tous les clients, tandis que le bannissement automatique et la limite de concurrence sont ignorés. Le shield le signale par un avertissement journalisé une seule fois, sous la cible `securite`.

### hyper

Avec un serveur hyper 1 brut, insérez `PeerAddr` dans chaque requête avant qu'elle n'atteigne le shield. Dépendances de cet exemple :

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

tonic enregistre l'adresse du pair dans sa propre extension `TcpConnectInfo`, que securite ne lit pas. Ajoutez devant le shield une étape `map_request` qui copie `remote_addr()` dans `PeerAddr`, exactement comme dans l'exemple hyper, puis ajoutez le shield avec `Server::builder().layer(...)`.

### Derrière un proxy inverse

Derrière Heroku, Cloudflare, Fly.io, un répartiteur de charge ou Nginx, le pair TCP est le proxy, pas le client. Indiquez au shield quel en-tête croire :

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();
```

Définissez la source sur le shield le plus externe : les shields intérieurs et les guards autonomes réutilisent l'adresse qu'il a résolue. La page [IP du client](/docs/client-ip) détaille chaque source et ses risques d'usurpation.

## Vérifier l'installation

Ce handler renvoie l'adresse résolue par le shield. Derrière un proxy, il doit afficher l'IP du visiteur, et non celle du proxy :

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

La valeur `ClientIp` n'existe que si une adresse a pu être résolue : si le handler affiche `unknown`, corrigez la configuration avant la mise en production. Étape suivante : le [démarrage rapide](/docs/quick-start).
