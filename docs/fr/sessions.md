---
title: Sessions
summary: Des sessions côté serveur avec un nouvel identifiant à la connexion, des délais d'inactivité et absolu, des identifiants hachés dans le stockage, une déconnexion avec Clear-Site-Data et des liens de vérification d'e-mail.
category: access
order: 11
---

`SessionManager` garde les sessions sur le serveur et ne donne au navigateur qu'un identifiant aléatoire dans un cookie durci. Il suit l'aide-mémoire OWASP sur la gestion des sessions : nouvel identifiant à la connexion, délais appliqués côté serveur, déconnexion complète. Le guard `Sessions` charge la session de chaque requête.

## Menaces couvertes

- **Fixation de session** (CWE-384) : `login` et `regenerate` donnent un nouvel identifiant à la session ; un identifiant planté par un attaquant meurt aussitôt.
- **Vol de session** : identifiants de 256 bits issus du générateur du système, cookie `__Host-` avec `Secure`, `HttpOnly`, `SameSite=Lax` et `Path=/`.
- **Sessions qui traînent** (CWE-613) : délai d'inactivité (30 min) et délai absolu (12 h), vérifiés sur le serveur quoi que dise le cookie.
- **Fuite du stockage** : le stockage ne voit que le SHA-256 de chaque identifiant ; une copie de Redis ne livre aucune session vivante.
- **Données laissées après la déconnexion** : `logout` supprime la session, fait expirer le cookie et envoie `Clear-Site-Data`.

## Démarrage rapide

```rust
use std::sync::Arc;
use securite::session::{MemorySessionStore, Session, SessionManager, Sessions};
use securite::prelude::*;

let sessions = SessionManager::new(Arc::new(MemorySessionStore::new(100_000)));
let shield = Shield::builder().guard(Sessions::new(sessions.clone())).build();

// POST /login, après la vérification du mot de passe :
let mut session = req.extensions().get::<Session>().cloned().unwrap_or_else(|| sessions.start());
sessions.login(&mut session, &user.id);      // nouvel identifiant + utilisateur
let set_cookie = sessions.commit(&session);  // à ajouter en `Set-Cookie`

// N'importe quel handler :
if let Some(session) = req.extensions().get::<Session>() {
    let user = session.user();
}

// POST /logout :
for (name, value) in sessions.logout(session) { /* à ajouter à la réponse */ }
```

Avec `Sessions` dans le shield, une session connectée dépose aussi un `Principal` (schéma `session`) dans la requête : le [contrôle d'accès](/docs/access-control) fonctionne avec.

## Configuration

| Méthode | Description |
|---|---|
| `SessionManager::new(stockage)` | Cookie `__Host-session`, 30 min d'inactivité, 12 h au total. |
| `.idle_timeout(d)` / `.absolute_timeout(d)` | Délais. |
| `.cookie_name(nom)` / `.same_site(s)` | Réglages du cookie. |
| `.insecure_dev()` | `http://localhost` uniquement : sans `Secure` ni préfixe `__Host-`. |
| `.start()` / `.load(en-têtes)` / `.commit(&session)` | Cycle de vie. |
| `.regenerate(&mut s)` / `.login(&mut s, utilisateur)` | Nouvel identifiant (à chaque changement de privilèges). |
| `.logout(s)` / `.destroy(s)` | Termine une session, avec ou sans `Clear-Site-Data`. |

`Session` offre `get`, `insert`, `remove`, `user` et `created_at`. Sa sortie `Debug` ne montre jamais l'identifiant.

## Stockage partagé

`MemorySessionStore` est borné et convient à une instance. Pour plusieurs, implémentez `SessionStore` (`load`, `save` avec une durée de vie, `delete`) sur Redis ou votre base. Les clés font 64 caractères hexadécimaux ; traitez une erreur du stockage comme une session absente : l'utilisateur est déconnecté plutôt que connecté.

## Clear-Site-Data à la déconnexion

`logout` l'envoie déjà. Pour l'ajouter à n'importe quelle route, utilisez le guard `ClearSiteData` :

```rust
use securite::clear_site_data::{ClearSiteData, Directive};

Shield::builder().guard(ClearSiteData::on(["/logout", "/account/delete"]));
// ou au choix : .directives([Directive::Cookies, Directive::Storage])
```

Il ne décore que les réponses réussies (`2xx` / `3xx`) ; les navigateurs ne l'appliquent qu'en HTTPS.

## Liens de vérification d'e-mail

`Signer` fabrique des liens qui prouvent qu'un utilisateur lit une boîte aux lettres, comme le `MustVerifyEmail` de Laravel :

```rust
use std::time::Duration;
use securite::signing::Signer;

let signer = Signer::new(secret).purpose("verify-email");
let link = signer.email_verification_url("/email/verify", &user.id, &user.email, Duration::from_secs(3600));
// → /email/verify/42/<empreinte de l'adresse>?expires=…&signature=…

// GET /email/verify/... :
let user_id = signer.verify_email_url(req.uri().path_and_query().unwrap().as_str(), &current_email)?;
```

Le lien ne vaut que pour le même utilisateur **et** la même adresse : après un changement d'e-mail, les anciens liens ne marchent plus.

## Pièges et conseils

- Appelez `login` (ou `regenerate`) à chaque changement de privilèges : connexion, mode sudo, changement de rôle.
- Combinez avec la [protection CSRF](/docs/csrf) : le navigateur envoie un cookie de session sur les requêtes intersites.
- Gardez `SameSite=Lax` ou `Strict` ; `None` doit avoir une raison.

## Pages liées

- [Cookies](/docs/cookies)
- [CSRF](/docs/csrf)
- [Contrôle d'accès](/docs/access-control)
- [URL et jetons signés](/docs/signed-urls)
