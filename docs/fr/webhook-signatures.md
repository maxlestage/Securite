---
title: Signatures de webhooks
summary: Vérifie en temps constant les signatures HMAC-SHA256 de GitHub, Stripe, Slack, Shopify ou de vos propres émetteurs, avec une protection contre le rejeu fondée sur l'horodatage.
category: integrity
order: 2
---

Un point d'accès de webhook est une URL publique qui déclenche des actions métier : marquer une facture comme payée, déployer un commit, provisionner un compte. Quiconque découvre l'URL peut y poster un événement falsifié ; c'est pourquoi tout fournisseur sérieux signe ses charges utiles avec un secret partagé. `SignatureLayer` vérifie ces signatures avant l'exécution de votre handler et lui transmet exactement le corps qui a été signé.

## Menaces couvertes

- **A08:2021 Software and Data Integrity Failures** : charges de webhook falsifiées ou altérées acceptées comme authentiques (CWE-345, vérification insuffisante de l'authenticité des données).
- **A07:2021 Identification and Authentication Failures** : la signature prouve que l'émetteur connaît le secret partagé.
- **Attaques par rejeu (CWE-294)** : avec les schémas horodatés, une requête capturée est rejetée dès qu'elle dépasse la fenêtre de tolérance.

## Fonctionnement

Contrairement aux autres guards, la vérification de signature a besoin du corps de la requête : c'est donc une couche tower dédiée plutôt qu'un guard du shield. Pour chaque requête dont le chemin correspond :

1. Le corps est mis en mémoire tampon, jusqu'à `max_body` (1 Mio par défaut). Les corps plus volumineux sont rejetés avec `413`, code `body_too_large`.
2. Le HMAC-SHA256 du contenu signé est calculé puis comparé en temps constant à la signature reçue.
3. Pour les schémas horodatés, l'horodatage doit se situer dans la tolérance (5 minutes par défaut, dans les deux sens).
4. Tout échec répond `401` avec le code `invalid_signature` et le message `Invalid webhook signature.` La raison précise (absente, mal formée, expirée, non concordante) est journalisée sous la cible tracing `securite` avec `guard="signature"`, jamais envoyée au client.
5. En cas de succès, la requête est reconstruite avec un corps identique et transmise à votre handler.

## Fournisseurs pris en charge

| Constructeur | En-têtes | Contenu signé | Protection contre le rejeu |
|---|---|---|---|
| `SignatureVerifier::github(secret)` | `X-Hub-Signature-256: sha256=<hex>` | corps | non |
| `SignatureVerifier::stripe(secret)` | `Stripe-Signature: t=<ts>,v1=<hex>` | `<ts>.<body>` | oui |
| `SignatureVerifier::slack(secret)` | `X-Slack-Signature: v0=<hex>` et `X-Slack-Request-Timestamp` | `v0:<ts>:<body>` | oui |
| `SignatureVerifier::shopify(secret)` | `X-Shopify-Hmac-Sha256: <base64>` | corps | non |
| `SignatureVerifier::hmac_hex(secret, header, prefix)` | `<header>: <prefix><hex>` | corps | non |
| `SignatureVerifier::hmac_base64(secret, header, prefix)` | `<header>: <prefix><base64>` | corps | non |
| `SignatureVerifier::hmac_hex_timestamped(secret, header, ts_header, prefix)` | `<header>: <prefix><hex>` et `<ts_header>: <secondes Unix>` | `<ts>.<body>` | oui |

Pour Stripe, chaque entrée `v1` de l'en-tête est essayée, ce qui continue de fonctionner pendant la rotation du secret de votre point d'accès. Les secrets acceptent tout ce qui implémente `AsRef<[u8]>` (`String`, `&str`, `Vec<u8>`…).

## Démarrage rapide

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let secret = std::env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET must be set");

let mut app = App::new();
app.middleware(Shield::recommended());
app.middleware(SignatureLayer::new(SignatureVerifier::github(secret)).paths(["/webhooks/github"]));
app.post("/webhooks/github", |req: Request| async move {
    // Only reached when the signature is valid.
    let body = req.text().await?;
    Ok::<_, Error>(format!("received {} bytes", body.len()))
});
```

Le shield est ajouté en dernier, il s'exécute donc en premier : limitation de débit, filtrage IP et contrôles des en-têtes ont lieu avant toute mise en tampon du corps.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `SignatureLayer::new(verifier)` | tous les chemins | Crée la couche. |
| `.paths(prefixes)` | toutes les requêtes | Ne vérifie que ces préfixes de chemins (comparés par segments) ; les autres requêtes passent sans modification. |
| `SignatureVerifier::tolerance(Duration)` | 5 minutes | Âge maximal ou décalage d'horloge toléré pour les schémas horodatés. |
| `SignatureVerifier::max_body(usize)` | 1 Mio | Taille maximale du corps mis en tampon pour la vérification. |
| `SignatureVerifier::sign(&[u8])` | — | HMAC-SHA256 hexadécimal d'une charge, pour les tests et les webhooks sortants. |
| `SignatureVerifier::verify(&HeaderMap, &[u8])` | — | Vérification manuelle ; renvoie `Result<(), SignatureError>`. |

`SignatureError` (dans `securite::signature`) compte quatre variantes : `Missing`, `Malformed`, `Expired` et `Mismatch`.

## Plusieurs fournisseurs

Empilez une couche par fournisseur, chacune limitée à son propre chemin :

```rust
use std::time::Duration;

use securite::prelude::*;
use vitesse::prelude::*;

let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));

async fn size(req: Request) -> Result<String, Error> {
    Ok(req.text().await?.len().to_string())
}

let mut app = App::new();
app.middleware(Shield::recommended());
app.middleware(
    SignatureLayer::new(SignatureVerifier::github(env("GITHUB_WEBHOOK_SECRET")))
        .paths(["/webhooks/github"]),
);
app.middleware(
    SignatureLayer::new(
        SignatureVerifier::stripe(env("STRIPE_WEBHOOK_SECRET"))
            .tolerance(Duration::from_secs(120))
            .max_body(256 * 1024),
    )
    .paths(["/webhooks/stripe"]),
);
app.middleware(
    SignatureLayer::new(SignatureVerifier::slack(env("SLACK_SIGNING_SECRET")))
        .paths(["/webhooks/slack"]),
);
app.post("/webhooks/github", size);
app.post("/webhooks/stripe", size);
app.post("/webhooks/slack", size);
```

## Exigence sur le corps

Avec Vitesse, le middleware lit le corps, le vérifie et le rend à la requête : les handlers le lisent comme d'habitude. Dans un service tower, la couche reconstruit la requête à partir des octets mis en tampon : le type du corps de requête doit donc implémenter `http_body::Body` et `From<Bytes>` ; `Incoming` de hyper ne l'implémente pas, convertissez-le d'abord en un type de corps qui le fait (un corps boxé, par exemple).

## Tester avec `sign()`

`sign()` calcule le HMAC hexadécimal exactement des octets fournis, ce qui facilite la construction de requêtes de test signées :

```rust
use securite::prelude::*;
use vitesse::prelude::*;
use vitesse::test::TestClient;

#[tokio::test]
async fn accepts_signed_github_payload() {
    let verifier = SignatureVerifier::github("test-secret");
    let payload = r#"{"action":"opened"}"#;
    let signature = format!("sha256={}", verifier.sign(payload.as_bytes()));

    let mut app = App::new();
    app.middleware(SignatureLayer::new(verifier).paths(["/webhooks/github"]));
    app.post("/webhooks/github", |req: Request| async move { req.text().await });

    let client = TestClient::new(app);
    let response = client
        .post("/webhooks/github")
        .header("x-hub-signature-256", &signature)
        .body(payload)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text(), payload);
}
```

Pour les schémas horodatés, signez vous-même le contenu composé :

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use securite::prelude::*;

let verifier = SignatureVerifier::stripe("whsec_test");
let payload = r#"{"type":"invoice.paid"}"#;
let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

let v1 = verifier.sign(format!("{ts}.{payload}").as_bytes());
let stripe_signature = format!("t={ts},v1={v1}");
// Slack: sign format!("v0:{ts}:{payload}") and send "v0=<hex>".
```

## Signer vos propres webhooks sortants

Le même type signe les webhooks que vous envoyez. Partagez le secret avec vos clients et indiquez-leur le constructeur correspondant :

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use securite::prelude::*;

let secret = std::env::var("OUTGOING_WEBHOOK_SECRET").expect("OUTGOING_WEBHOOK_SECRET must be set");
let signer = SignatureVerifier::hmac_hex_timestamped(secret, "x-acme-signature", "x-acme-timestamp", "sha256=");

let body = r#"{"event":"order.shipped","order_id":"ord_8812"}"#;
let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
let signature = format!("sha256={}", signer.sign(format!("{ts}.{body}").as_bytes()));
// Send `body` with the headers x-acme-timestamp: <ts> and x-acme-signature: <signature>.
```

## Protection contre le rejeu

- Stripe, Slack et `hmac_hex_timestamped` rejettent les horodatages hors de la fenêtre de tolérance, dans le passé comme dans le futur. Une requête capturée ne peut pas être rejouée des heures plus tard.
- À l'intérieur de la fenêtre, un rejeu reste possible. Rendez vos handlers idempotents et dédoublonnez sur l'identifiant d'événement du fournisseur : l'`id` de l'événement Stripe, `X-GitHub-Delivery`, `X-Shopify-Webhook-Id`.
- GitHub, Shopify, `hmac_hex` et `hmac_base64` ne transportent aucun horodatage : seul le dédoublonnage vous protège contre le rejeu.
- Synchronisez vos serveurs avec NTP. Une forte dérive d'horloge transforme chaque livraison légitime en erreur `Expired`.

## Pièges et conseils

- Ne placez pas de couche qui réécrit le corps (décompression, transcodage) entre le fournisseur et `SignatureLayer` : la signature porte sur les octets exacts qui ont été envoyés.
- Un mauvais secret transforme chaque livraison en `401`, qu'`AutoBan` compte comme une pénalité contre les adresses IP du fournisseur. Excluez les chemins de webhooks avec `AutoBan::new().ignore_paths(["/webhooks"])`.
- `ContentTypeGuard::json()`, utilisé par le préréglage `api`, rejette les charges encodées en formulaire des commandes slash de Slack : ajoutez `.skip("/webhooks/slack")`. En mode jeton, `Csrf` doit exempter les chemins de webhooks avec `.exempt("/webhooks")`.
- Les rejets de signature ne passent ni par le hook `on_event` ni par les statistiques du shield, et sont toujours rendus en problem+json. Surveillez la cible tracing `securite` pour repérer les erreurs de configuration.
- Un vérificateur ne contient qu'un seul secret. Pour faire tourner vos propres secrets, acceptez les deux pendant la transition, par exemple en appelant `verify` manuellement avec deux vérificateurs.
- `sign()` renvoie de l'hexadécimal. Pour tester Shopify ou `hmac_base64`, encodez vous-même en base64 les octets bruts du MAC.

## Pages associées

- [Authentification](/docs/auth)
- [Bannissement automatique](/docs/auto-ban)
- [Liste des Content-Type autorisés](/docs/content-type)
- [Protection CSRF](/docs/csrf)
- [Limite de taille du corps](/docs/body-limit)
- [Identifiants de requête](/docs/request-id)
