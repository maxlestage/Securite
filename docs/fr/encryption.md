---
title: Chiffrement
summary: Le Crypt de Laravel avec XChaCha20-Poly1305, des clés versionnées et leur rotation, des usages et contextes, des jetons qui expirent et des cookies chiffrés liés à leur nom.
category: integrity
order: 6
---

`Encrypter` transforme des octets en un jeton opaque, sûr dans une URL ou un cookie, que seul votre serveur peut lire et qui ne peut pas être modifié sans que cela se voie. C'est le `Crypt` de Laravel pour Rust, bâti sur la crate auditée RustCrypto `chacha20poly1305` (feature `crypt`, active par défaut).

## Menaces couvertes

- **A02:2021 Défaillances cryptographiques** : des valeurs que le client doit détenir sans les lire (CWE-311) ni les modifier (CWE-345).
- **Falsification** : XChaCha20-Poly1305 est un chiffrement authentifié ; un seul bit modifié fait échouer le déchiffrement.
- **Réutilisation de nonce** : le nonce de 192 bits est tiré du générateur aléatoire du système pour chaque message ; deux nonces aléatoires ne se rencontrent jamais en pratique.
- **Échange de cookies** : un cookie chiffré ne se déchiffre que sous son propre nom ; la valeur de `prefs` ne peut pas être rejouée comme `role`.

## Démarrage rapide

```rust
use securite::crypt::Encrypter;

// Une fois : `Encrypter::generate_key()` → gardez-la dans un secret (APP_KEY).
let crypt = Encrypter::from_base64(&std::env::var("APP_KEY")?)?;

let token = crypt.encrypt_str("4111 1111 1111 1111");
let card = crypt.decrypt_str(&token)?;
```

## Usages, contextes et expiration

```rust
use std::time::Duration;

// Un jeton prévu pour un usage ne s'ouvre nulle part ailleurs.
let remember = crypt.clone().purpose("remember-me");
let t = remember.encrypt_with_ttl(b"user:42", Duration::from_secs(30 * 24 * 3600));

// Liez une valeur à sa ligne : copiée dans la ligne d'un autre utilisateur, elle ne s'ouvre plus.
let iban = crypt.encrypt_in("user:42:iban", b"FR76...", None);
assert!(crypt.decrypt_in("user:43:iban", &iban).is_err());
```

## Cookies chiffrés

```rust
let value = crypt.encrypt_cookie("prefs", "theme=dark", None);
// Set-Cookie: prefs=<value>; Path=/; HttpOnly; Secure; SameSite=Lax
// (ou laissez CookieHardening ajouter les attributs)

let prefs = crypt.read_cookie(req.headers(), "prefs"); // None si forgé, expiré ou déplacé
```

Quand le client peut lire la valeur mais ne doit pas la modifier, signez-la plutôt : `Signer::sign_cookie(nom, valeur)` et `unsign_cookie` (voir [URL et jetons signés](/docs/signed-urls)).

## Rotation des clés

Chaque jeton porte une version de format et l'identifiant de la clé qui l'a scellé (une empreinte de 4 octets, jamais la clé). Changez de clé sans déconnecter personne :

```rust
let crypt = Encrypter::from_base64(&new_key)?
    .fallback_key_base64(&old_key)?; // déchiffre encore les anciens jetons
```

Les nouveaux jetons sont scellés avec la nouvelle clé ; retirez l'ancienne une fois expiré le jeton le plus durable. `crypt.key_id()` affiche l'identifiant de la clé courante, pratique pour vérifier un déploiement.

## Configuration

| Méthode | Description |
|---|---|
| `Encrypter::new(&[u8; 32])` / `try_new` / `from_base64` | La clé (32 octets aléatoires ; préfixe `base64:` accepté). |
| `Encrypter::generate_key()` | Une nouvelle clé aléatoire, en base64. |
| `.purpose(p)` | Lie les jetons à un usage. |
| `.fallback_key(ancienne)` | Rotation des clés. |
| `.encrypt` / `.encrypt_str` / `.encrypt_with_ttl` | Scelle. |
| `.decrypt` / `.decrypt_str` | `Err(Malformed / Invalid / Expired)`. |
| `.encrypt_in(contexte, …)` / `.decrypt_in` | Valeurs liées à un contexte. |
| `.encrypt_cookie` / `.decrypt_cookie` / `.read_cookie` | Cookies chiffrés. |

## Pièges et conseils

- La clé est tout : gardez-la hors du dépôt, et ne la réutilisez jamais pour autre chose (comme secret de signature par exemple).
- Le chiffrement cache le contenu, pas la taille : complétez les valeurs si leur longueur est sensible.
- Ne chiffrez pas les mots de passe : [hachez-les](/docs/passwords).

## Pages liées

- [URL et jetons signés](/docs/signed-urls)
- [Cookies](/docs/cookies)
- [Sessions](/docs/sessions)
