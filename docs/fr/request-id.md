---
title: Identifiants de requête
summary: Attribue à chaque requête un identifiant unique et validé, transmis à vos handlers, à vos journaux, à chaque événement de sécurité et à chaque réponse d'erreur.
category: integrity
order: 1
---

Quand un client signale « le site m'a répondu Forbidden », il faut retrouver cette requête précise parmi des millions de lignes de journal. `RequestId` attribue un identifiant à chaque requête, le transmet à vos handlers, le renvoie dans la réponse et l'attache à chaque événement de sécurité et à chaque corps d'erreur : une seule valeur relie ce que le client a vu, ce que le shield a décidé et ce que votre application a journalisé.

## Pourquoi c'est important

- **A09:2021 Security Logging and Monitoring Failures** : sans identifiant de corrélation, impossible de reconstituer un incident ni de relier une alerte aux journaux applicatifs.
- **Injection dans les journaux (CWE-117)** : un identifiant fourni par le client n'est réutilisé que s'il est court et composé de caractères sûrs ; personne ne peut ainsi forger de fausses lignes de journal ni injecter de balisage dans vos tableaux de bord via cet en-tête.

## Fonctionnement

1. Le guard s'exécute en premier dans la chaîne, afin que toutes les décisions suivantes puissent faire référence à l'identifiant.
2. Si la requête porte déjà l'en-tête (par défaut `X-Request-Id`) avec une valeur valide, celle-ci est conservée. Valide signifie de 1 à 128 caractères parmi `A-Z`, `a-z`, `0-9`, `-`, `_`, `.` et `:`.
3. Sinon, un nouvel identifiant est généré au format UUID v4, par exemple `3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44`.
4. L'en-tête est (ré)écrit dans la requête, et un `RequestIdValue` est inséré dans ses extensions.
5. L'identifiant est renvoyé dans l'en-tête de la réponse, y compris en cas de rejet, et ajouté à `SecurityEvent::request_id`, aux journaux tracing de la cible `securite` et au champ `request_id` des corps d'erreur problem+json.

## Démarrage rapide

`RequestId::new()` fait partie de tous les préréglages. Dans un shield sur mesure :

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

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `RequestId::new()` | `x-request-id`, identifiants entrants sûrs réutilisés | Crée le guard (`RequestId::default()` est équivalent). |
| `.header(name)` | `x-request-id` | Nom d'en-tête personnalisé, comme `x-correlation-id` ; panique si le nom est invalide. |
| `.always_generate()` | désactivé | Ignore les identifiants entrants et en génère toujours un nouveau. |
| `RequestId::generate()` | — | Renvoie un nouvel identifiant au format UUID v4 (`String`). |

## Lire l'identifiant dans les handlers

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

`RequestIdValue` enveloppe la `HeaderValue` (`id.0`), que vous pouvez recopier telle quelle dans les en-têtes de vos requêtes sortantes pour propager l'identifiant aux services en aval.

## Ajouter l'identifiant à chaque ligne de journal

Avec `tower-http`, ouvrez par requête un span qui porte l'identifiant. La couche de trace doit se trouver sous le shield pour que l'extension soit déjà présente :

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// Ajouté en premier, donc exécuté en premier : l'identifiant existe pour les middlewares suivants.
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

## Derrière un proxy ou une plateforme

Le routeur de Heroku, de nombreux répartiteurs de charge et Nginx (`proxy_set_header X-Request-Id $request_id;`) définissent déjà un identifiant de requête. `RequestId::new()` le réutilise lorsqu'il est valide : la même valeur apparaît ainsi dans les journaux de la plateforme et dans ceux de votre application. Si votre organisation suit une autre convention, changez le nom de l'en-tête :

```rust
use securite::prelude::*;

let request_id = RequestId::new().header("x-correlation-id");
```

Si l'application est directement accessible aux clients, ceux-ci peuvent choisir leur propre identifiant. La validation rend la chose inoffensive pour vos journaux, mais un client pourrait réutiliser l'identifiant d'une autre requête pour brouiller une enquête. Utilisez `.always_generate()` lorsqu'aucun proxy de confiance ne définit l'en-tête :

```rust
use securite::prelude::*;

let request_id = RequestId::new().always_generate();
```

## Utilisation comme guard autonome

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(RequestId::new()));
app.get("/", |_req: Request| async { "home" });
```

> **Attention :** une couche `RequestId` autonome possède son propre shield interne. Un autre `Shield` de la même pile ne connaîtra pas l'identifiant : ses événements et ses corps problem+json ne le contiendront pas. Enregistrez `RequestId` dans le même shield que vos autres guards, comme le font les préréglages.

## Pièges et conseils

- Les identifiants sont aléatoires, mais produits par un générateur rapide et non cryptographique. Ce sont des identifiants de corrélation, pas des secrets : ne les utilisez jamais comme jetons de session, nonces ou clés d'autorisation.
- L'identifiant est aussi renvoyé sur les requêtes bloquées. Affichez-le sur vos pages d'erreur afin que les utilisateurs puissent le communiquer à votre support.
- Gardez le même nom d'en-tête d'un service à l'autre : une seule recherche dans votre plateforme de journaux suit alors une requête de bout en bout.

## Pages associées

- [Événements de sécurité et statistiques](/docs/events-stats)
- [Format des réponses d'erreur](/docs/error-format)
- [IP du client](/docs/client-ip)
