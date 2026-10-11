---
title: Protection CSRF
summary: Une protection Fetch Metadata sans état, fondée sur l'algorithme de CrossOriginProtection de Go 1.25, avec un jeton double-submit signé par HMAC en option.
category: access
order: 4
---

`Csrf` rejette les requêtes modifiant l'état qu'un navigateur envoie pour le compte d'un autre site. Son mode par défaut ne demande ni configuration, ni session, ni modification des templates ; un mode optionnel à jeton signé ajoute une seconde barrière, indépendante de la première.

## La menace

Lors d'une falsification de requête intersite (CSRF), une page malveillante pousse le navigateur de la victime à envoyer une requête à votre application (formulaire caché, balise `<img>`, appel `fetch`). Le navigateur y joint les identifiants ambiants (cookies, authentification HTTP, certificats client) : votre serveur voit donc une requête parfaitement authentifiée, qu'il s'agisse d'un virement, d'un changement de mot de passe ou d'une suppression de compte.

Le CSRF (CWE-352) relève de la catégorie A01 Broken Access Control de l'OWASP Top 10 2021 ; voir la Cross-Site Request Forgery Prevention Cheat Sheet de l'OWASP et le test WSTG-SESS-05. Les cookies `SameSite` aident, mais ils ne couvrent pas les attaques venant de sous-domaines voisins, et `Lax` autorise toujours les navigations `GET` de premier niveau.

## Fonctionnement

### Fetch Metadata et vérification de l'origine

Les navigateurs modernes étiquettent chaque requête avec `Sec-Fetch-Site`, qu'une page malveillante ne peut pas falsifier. Le guard (priorité 130) applique la même procédure de décision que `http.CrossOriginProtection` de Go 1.25 :

1. `GET`, `HEAD` et `OPTIONS`, ainsi que les chemins situés sous un préfixe `exempt`, ne sont jamais vérifiés. Toutes les autres méthodes le sont, `TRACE` compris.
2. Si `Sec-Fetch-Site` est présent : `same-origin` et `none` (l'utilisateur a saisi l'URL ou utilisé un favori) passent ; `same-site` ne passe qu'avec `allow_same_site(true)` ; toute autre valeur ne passe que si `Origin` est une origine de confiance.
3. Sans `Sec-Fetch-Site` (anciens navigateurs) : l'absence d'en-tête `Origin` signale un client non navigateur, qui passe ; une `Origin` de confiance passe ; sinon, l'hôte de `Origin` doit être identique à l'en-tête `Host`.
4. Les rejets reçoivent un `403` avec le code `csrf_rejected`.

### Jeton double-submit signé

Avec `with_token(secret)`, chaque client reçoit aussi un jeton : 24 octets aléatoires suivis de leur signature HMAC-SHA256, encodés en base64url. Il est stocké dans le cookie `__Host-csrf` (`Path=/; HttpOnly; SameSite=Strict; Secure`) et exposé aux handlers via l'extension de requête `CsrfToken`. Chaque requête non sûre doit réussir la vérification d'origine **et** renvoyer le même jeton dans l'en-tête `X-CSRF-Token`. La comparaison s'effectue en temps constant, et la signature empêche un attaquant d'imposer un jeton de son choix. Un jeton absent ou erroné donne un `403` avec le code `csrf_token_invalid`.

Le cookie est `HttpOnly` : les scripts ne le lisent jamais. Injectez plutôt le jeton issu de `CsrfToken` dans vos pages.

## Démarrage rapide

`Shield::recommended()` et `Shield::strict()` incluent déjà `Csrf::new()`. Utilisé seul :

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::builder().guard(Csrf::new()).build());
    app.get("/", |_req: Request| async { "form" });
    app.post("/transfer", |_req: Request| async { "done" });
    app
}
```

Le guard s'appelle `csrf` ; `ShieldBuilder::recommended().without("csrf")` le retire.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Csrf::new()` | Fetch Metadata seul | Protection sans état. |
| `trusted_origin(&str)` | aucune | Accepte les requêtes non sûres venant de cette origine (`https://admin.example.com`). Peut être appelée plusieurs fois. |
| `exempt(prefix)` | aucun | Préfixe de chemin qui échappe aux vérifications (webhooks, API authentifiées par jeton). |
| `allow_same_site(bool)` | `false` | Accepte `Sec-Fetch-Site: same-site`, c'est-à-dire tous les sous-domaines de votre site. |
| `with_token(secret)` | inactif | Active le jeton double-submit signé. Panique si le secret fait moins de 32 octets. |
| `cookie_name(&str)` | `__Host-csrf` | Nom du cookie du jeton. Mode jeton uniquement. |
| `header_name(&str)` | `x-csrf-token` | En-tête qui transporte le jeton. Mode jeton uniquement. |
| `insecure_dev_cookie()` | cookie `Secure` | Retire `Secure` et renomme `__Host-csrf` en `csrf`, pour le développement en HTTP simple. Mode jeton uniquement. |
| `monitor()` | blocage | Signale les violations sans bloquer. |

> **Astuce :** `cookie_name`, `header_name` et `insecure_dev_cookie` peuvent être appelées avant ou après `with_token` : l'ordre est indifférent. Sans `with_token`, elles n'ont aucun effet.

## Exemples

### Application rendue côté serveur avec htmx

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn page(req: Request) -> Html<String> {
    let token = req.get::<CsrfToken>().map(|t| t.0.clone()).unwrap_or_default();
    // htmx adds this header to every request it sends.
    Html(format!(
        r#"<body hx-headers='{{"X-CSRF-Token": "{token}"}}'>
  <button hx-post="/transfer">Send</button>
</body>"#
    ))
}

pub fn app(secret: String) -> App {
    let shield = ShieldBuilder::recommended()
        .guard(Csrf::new().with_token(secret).exempt("/webhooks"))
        .build();

    let mut app = App::new();
    app.middleware(shield);
    app.get("/", page);
    app.post("/transfer", |_req: Request| async { "sent" });
    app.post("/webhooks/payments", |_req: Request| async { "ok" });
    app
}
```

Chargez le secret depuis votre coffre à secrets, par exemple avec `std::env::var("CSRF_SECRET")`, et partagez-le entre toutes les instances.

### Envoyer le jeton avec fetch

Si la page génère `<meta name="csrf-token" content="…">` à partir de `CsrfToken` :

```text
const token = document.querySelector('meta[name="csrf-token"]').content;
await fetch("/transfer", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
  body: JSON.stringify({ amount: 10 }),
});
```

### Front-end d'administration, webhooks et API à jeton bearer

```rust
use securite::prelude::*;

pub fn csrf() -> Csrf {
    Csrf::new()
        .trusted_origin("https://admin.example.com")
        .exempt("/webhooks") // verified by signature instead
        .exempt("/api/v1") // bearer tokens, no cookies
}
```

### Développement local

```rust
use securite::prelude::*;

pub fn csrf(secret: &str, dev: bool) -> Csrf {
    let csrf = Csrf::new().with_token(secret);
    if dev { csrf.insecure_dev_cookie() } else { csrf }
}
```

### À quoi ressemble un rejet

```json
{"type":"about:blank","title":"Forbidden","status":403,"code":"csrf_rejected","detail":"Cross-site request rejected."}
```

## Utilisation comme guard autonome

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(Csrf::new()));
    app.post("/settings", |_req: Request| async { "saved" });
    app
}
```

## Pièges et conseils

- **Les méthodes sûres ne sont jamais vérifiées** : un handler `GET` qui modifie l'état n'est, par construction, pas protégé. Gardez `GET`, `HEAD` et `OPTIONS` exempts d'effets de bord.
- **Les formulaires HTML classiques ne peuvent pas envoyer d'en-têtes** : le mode jeton nécessite JavaScript (`fetch`, htmx…). Les formulaires classiques sont couverts par le mode Fetch Metadata dans tous les navigateurs modernes.
- **`allow_same_site(true)`** fait confiance à tous les sous-domaines, y compris ceux qui hébergent du contenu utilisateur ou un sous-domaine détourné via un enregistrement DNS orphelin. Préférez `trusted_origin` pour chaque front-end.
- **Les chemins exemptés** doivent être protégés autrement, par exemple par des signatures de webhook ou des jetons bearer. Les préfixes respectent les limites de segment.
- **Proxys** : la solution de repli pour les anciens navigateurs compare `Origin` à `Host` ; votre reverse proxy doit transmettre le `Host` d'origine.
- **La rotation du secret** invalide tous les jetons. Les clients reçoivent un nouveau cookie à leur requête suivante, mais une requête déjà en cours échoue une fois.
- **Nom du cookie** : renommer le cookie sans le préfixe `__Host-` permet à un sous-domaine voisin de l'écraser.
- **API** : `Shield::api()` ne contient pas de guard CSRF, car les API s'authentifient normalement par jeton. Rajoutez `Csrf::new()` si votre API repose sur des cookies.
- **Jeton absent** : sans `with_token`, `req.get::<CsrfToken>()` vaut `None`.

> **Astuce :** toute faille XSS met en échec n'importe quelle défense CSRF, puisque le script s'exécute sur votre propre origine. Associez ce guard à une [Content-Security-Policy](/docs/security-headers) stricte.

## Pages associées

- [Durcissement des cookies](/docs/cookies)
- [CORS](/docs/cors)
- [Liste d'autorisation Content-Type](/docs/content-type)
- [Filtre d'hôtes](/docs/host-filter)
- [Signatures de webhooks](/docs/webhook-signatures)
- [Mode monitor](/docs/monitor-mode)
