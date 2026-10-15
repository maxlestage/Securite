---
title: security.txt
summary: Publie un security.txt conforme à la RFC 9116 pour que les chercheurs puissent signaler des vulnérabilités, et refuse les contacts manquants, les expirations incorrectes, les liens http et l'injection de champs.
category: integrity
order: 7
---

`/.well-known/security.txt` (RFC 9116) indique aux chercheurs en sécurité comment signaler une vulnérabilité. `SecurityTxt` construit un fichier valide et refuse les erreurs habituelles.

## Menaces couvertes

- **Vulnérabilités non signalées** : un chercheur qui ne trouve pas de contact publie, ou vend la faille.
- **Fichiers périmés** : `Expires` est obligatoire, doit être dans le futur et à moins d'un an (régénérez-le à chaque déploiement avec `expires_in`).
- **Contacts usurpés** : les liens `http://` sont refusés, et les valeurs ne peuvent pas contenir de sauts de ligne qui injecteraient des champs.

## Démarrage rapide

```rust
use std::time::Duration;
use securite::security_txt::{SecurityTxt, CONTENT_TYPE, PATH};

let txt = SecurityTxt::new()
    .contact("mailto:security@example.com")
    .contact("https://example.com/security")
    .expires_in(Duration::from_secs(180 * 24 * 3600))
    .encryption("https://example.com/pgp-key.txt")
    .preferred_languages(["fr", "en", "es"])
    .canonical("https://example.com/.well-known/security.txt")
    .policy("https://example.com/disclosure-policy")
    .render()?; // Err(MissingContact / MissingExpires / BadExpires / InvalidValue)

app.get(PATH, move |_req: Request| {
    let body = txt.clone();
    async move { ([("content-type", CONTENT_TYPE)], body) }
});
```

## Champs

| Méthode | Champ | Valeurs permises |
|---|---|---|
| `.contact(uri)` | `Contact` (obligatoire, répétable) | `mailto:`, `tel:`, `https://` |
| `.expires_in(d)` / `.expires_at(t)` | `Expires` (obligatoire) | futur, un an au plus |
| `.encryption(uri)` | `Encryption` | `https://`, `openpgp4fpr:`, `dns:` |
| `.acknowledgments(uri)` | `Acknowledgments` | `https://` |
| `.preferred_languages([...])` | `Preferred-Languages` | étiquettes de langue |
| `.canonical(uri)` | `Canonical` | `https://` |
| `.policy(uri)` | `Policy` | `https://` |
| `.hiring(uri)` | `Hiring` | `https://` |
| `.csaf(uri)` | `CSAF` | `https://` |

## Pièges et conseils

- Surveillez l'adresse de contact : un signalement sans réponse est pire que pas de signalement.
- Signer le fichier avec OpenPGP (signature en clair) est facultatif ; faites-le hors de l'application si besoin.
- Pensez au [filtre Host](/docs/host-filter) : le fichier doit être accessible sur chaque nom d'hôte public.

## Pages liées

- [En-têtes de sécurité](/docs/security-headers)
- [URL et jetons signés](/docs/signed-urls)
