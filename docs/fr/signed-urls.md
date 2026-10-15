---
title: URL et jetons signés
summary: Jetons et URL infalsifiables, à durée de vie limitée et liés à un usage, avec HMAC-SHA256 et rotation de clés, plus un guard qui vérifie les liens signés avant votre handler.
category: integrity
order: 5
---

`Signer` rend des valeurs infalsifiables : liens de réinitialisation de mot de passe et de vérification d'e-mail, liens de désinscription, invitations, liens de téléchargement temporaires, ou tout identifiant confié au client et qui doit revenir intact. Le guard `SignedUrls` vérifie les liens signés avant votre handler, comme le middleware `signed` de Laravel.

## Menaces couvertes

- **A01:2021 Contrôle d'accès défaillant** : liens dont les paramètres se modifient (`/unsubscribe?user=42` → `user=43`), liens de téléchargement qui n'expirent jamais.
- **A08:2021 Défaillances d'intégrité des logiciels et des données** : valeurs qui transitent par le client et sont crues sans vérification (CWE-345, CWE-565).
- **Confusion de jetons** : un jeton émis pour une fonctionnalité rejoué dans une autre ; chaque jeton est lié à un *usage* (purpose).

## URL signées

```rust
use std::time::Duration;
use securite::prelude::*;

let signer = Signer::new(std::env::var("LINK_SECRET").expect("LINK_SECRET must be set"));

// Dans l'e-mail :
let link = signer.sign_url("/downloads/report.pdf?user=42", Some(Duration::from_secs(15 * 60)));
// /downloads/report.pdf?user=42&expires=1767225600&signature=Qm9...
let absolute = format!("https://example.com{link}");

// Dans l'application :
let mut app = App::new();
app.middleware(
    ShieldBuilder::recommended()
        .guard(SignedUrls::new(signer).protect(["/downloads", "/unsubscribe"]))
        .build(),
);
```

Sur les préfixes protégés, une requête dont l'URL n'a pas été signée, a été modifiée ou a expiré reçoit `403 Forbidden` avec le code `invalid_signature` ou `expired_signature`.

La signature couvre le chemin et tous les paramètres qui la précèdent, `expires` compris. Le paramètre `signature` doit être le dernier : un paramètre ajouté après lui (`&admin=1`) invalide le lien. Un `#fragment` est conservé à la fin et n'est pas signé, puisque les navigateurs ne l'envoient jamais.

## Jetons

```rust
use std::time::Duration;
use securite::signing::{Signer, TokenError};

let resets = Signer::new(secret).purpose("password-reset");
let token = resets.sign_with_ttl(&user.id.to_string(), Duration::from_secs(3600));

// Plus tard, à l'ouverture du lien :
match resets.unsign(&token) {
    Ok(user_id) => { /* afficher le formulaire de réinitialisation pour user_id */ }
    Err(TokenError::Expired) => { /* proposer un nouveau lien */ }
    Err(_) => { /* 400 */ }
}
```

Un jeton s'écrit `base64url(contenu).expiration.base64url(hmac)`. Il est **signé, pas chiffré** : n'importe qui peut lire son contenu, n'y mettez donc jamais de secret. Pour un usage unique (réinitialisation de mot de passe), incluez aussi une valeur qui change une fois le jeton utilisé, par exemple les derniers caractères de l'empreinte du mot de passe actuel ou un compteur stocké avec l'utilisateur.

## Fonctionnement

- HMAC-SHA256 sur un séparateur de domaine (jetons et URL ne sont jamais interchangeables), l'usage (préfixé par sa longueur) et le texte signé.
- Les signatures sont comparées en temps constant à chaque clé configurée, sans sortie anticipée.
- L'expiration n'est vérifiée qu'après la signature : un lien forgé n'apprend rien.
- Les secrets de moins de 32 octets sont refusés au démarrage.

## Rotation des clés

```rust
use securite::signing::Signer;

let signer = Signer::new(new_secret)    // signe tout ce qui est nouveau
    .fallback_key(old_secret);          // encore accepté jusqu'à l'expiration des anciens liens
```

## Configuration

| Méthode | Description |
|---|---|
| `Signer::new(secret)` | 32 octets minimum (`openssl rand -base64 48`). |
| `.purpose(name)` | Lie jetons et URL à un usage (`"default"` par défaut). |
| `.fallback_key(secret)` | Vérifie aussi avec un ancien secret. |
| `.sign(value)` / `.sign_with_ttl(value, ttl)` / `.sign_bytes(bytes, ttl)` | Jetons. |
| `.unsign(token)` / `.unsign_bytes(token)` | `Result<_, TokenError>` (`Malformed`, `Invalid`, `Expired`). |
| `.sign_url(url, ttl)` | URL relative déjà encodée ; panique sur `//hôte` ou sur des paramètres `signature` / `expires` existants. |
| `.verify_url(path_and_query)` | `Result<(), TokenError>`. |
| `SignedUrls::new(signer)` | Guard ; tous les chemins tant que `.protect(prefixes)` ne le restreint pas. |
| `.monitor()` | Signale les liens invalides sans bloquer. |

## Pièges et conseils

- Signez l'URL exactement telle que le navigateur la demandera : même chemin, même encodage, même ordre des paramètres. Construisez-la, signez-la, puis n'y touchez plus.
- Les clients mail et les traqueurs ajoutent parfois des paramètres `utm_` : tenez les liens signés à l'écart des campagnes suivies, ou retirez ces paramètres en frontal.
- Un usage par fonctionnalité, et des durées de vie courtes pour tout ce qui donne un accès.
- `SignedUrls` vérifie l'intégrité, pas l'identité : un lien de téléchargement signé fonctionne pour quiconque le possède. Combinez avec l'[authentification](/docs/auth) quand l'utilisateur doit aussi être connecté.

## Pages associées

- [Signatures de webhooks](/docs/webhook-signatures)
- [Autorisations](/docs/authorization)
- [Protection CSRF](/docs/csrf)
