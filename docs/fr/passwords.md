---
title: Hachage des mots de passe
summary: Hachage Argon2id avec les paramètres de l'OWASP, mise à niveau transparente à la connexion, poivre optionnel et protection contre l'énumération de comptes.
category: access
order: 6
---

`PasswordHasher` stocke les mots de passe comme le recommandent l'OWASP et la RFC 9106 : avec **Argon2id**, une fonction coûteuse en mémoire qui rend le cassage sur GPU ou ASIC onéreux, et un sel aléatoire neuf pour chaque mot de passe. Il s'appuie sur la crate `argon2` auditée de RustCrypto et ajoute ce dont un parcours de connexion a besoin : re-hachage à la connexion quand vous augmentez le coût, vérification factice pour les comptes inconnus, poivre et limites raisonnables.

## Menaces couvertes

- **A02:2021 Défaillances cryptographiques** / **A07:2021 Identification et authentification de mauvaise qualité** : des mots de passe stockés en clair, avec un hachage rapide (MD5, SHA-256) ou sans sel se cassent en quelques heures dès que la base fuite (CWE-916, CWE-759).
- **Énumération de comptes** (CWE-204) : une connexion qui répond plus vite quand l'adresse e-mail est inconnue révèle aux attaquants quels comptes existent.
- **Déni de service par le hachage** : mots de passe gigantesques, ou ligne de hachage falsifiée qui réclame des gigaoctets de mémoire.

## Démarrage rapide

Le module dépend de la feature `password`, activée par défaut.

```rust
use securite::password::PasswordHasher;

let hasher = PasswordHasher::new(); // Argon2id, m = 19 Mio, t = 2, p = 1

// Inscription : stockez cette chaîne telle quelle (elle contient le sel et les paramètres).
let stored = hasher.hash("correct horse battery staple")?;
// $argon2id$v=19$m=19456,t=2,p=1$<sel>$<hash>

// Connexion.
assert!(hasher.verify("correct horse battery staple", &stored));
```

Le hachage est volontairement lent (quelques dizaines de millisecondes, 19 Mio de mémoire). Dans un serveur asynchrone, exécutez-le sur un thread bloquant pour ne pas retarder les autres requêtes :

```rust
let hasher = hasher.clone(); // peu coûteux : le hasher est partagé
let ok = tokio::task::spawn_blocking(move || hasher.verify(&password, &stored)).await?;
```

## Une connexion complète

```rust
use securite::password::{PasswordCheck, PasswordHasher};

fn login(hasher: &PasswordHasher, db: &Db, email: &str, password: &str) -> Result<User, LoginError> {
    let Some(user) = db.find_user_by_email(email) else {
        // Autant de travail qu'une vraie vérification : le temps de réponse ne
        // révèle pas si l'adresse est inscrite.
        hasher.verify_dummy(password);
        return Err(LoginError::InvalidCredentials);
    };
    match hasher.check(password, &user.password_hash) {
        PasswordCheck::Valid => Ok(user),
        PasswordCheck::ValidNeedsRehash(new_hash) => {
            // Le hachage stocké utilisait des paramètres plus faibles (ou Argon2i) :
            // on le met à niveau maintenant, seul moment où le mot de passe est connu.
            db.update_password_hash(user.id, &new_hash);
            Ok(user)
        }
        PasswordCheck::Invalid => Err(LoginError::InvalidCredentials),
    }
}
```

Renvoyez la même erreur et le même message pour un compte inconnu et un mauvais mot de passe. Combinez avec la [limitation des tentatives de connexion](/docs/login-throttle) pour qu'aucun compte ne puisse être deviné.

## Fonctionnement

1. **Hachage.** Un sel de 16 octets est tiré du générateur cryptographique du système, puis Argon2id (version 0x13) calcule un hachage de 32 octets. Le résultat est une chaîne PHC qui enregistre l'algorithme, la version, les coûts et le sel : chaque hachage reste vérifiable même si les valeurs par défaut changent.
2. **Vérification.** La chaîne PHC est analysée et le mot de passe est haché de nouveau avec *les paramètres stockés* ; les sorties sont comparées en temps constant. Les chaînes malformées, les hachages bcrypt ou PBKDF2, les mots de passe vides et ceux qui dépassent la limite de longueur ne correspondent jamais.
3. **Plafond de coût.** Avant tout calcul, les coûts stockés sont comparés à ceux configurés : une ligne qui demande plus de quatre fois la mémoire ou le temps configurés est refusée, une base falsifiée ne peut donc pas faire allouer des gigaoctets au serveur.
4. **Mises à niveau.** `check` renvoie `ValidNeedsRehash` quand le hachage stocké est plus faible que les paramètres actuels ou n'est pas un Argon2id, avec un nouveau hachage fait avec les paramètres actuels.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `PasswordHasher::new()` | — | Argon2id, `m = 19456 Kio, t = 2, p = 1` (OWASP). |
| `PasswordHasher::with_params(m_kib, t, p)` | — | Coûts personnalisés ; panique sous le minimum OWASP (`m ≥ 7168 Kio`, `m × t ≥ 35840`). |
| `.pepper(secret)` | aucun | Secret mêlé à chaque hachage (entrée secrète d'Argon2) ; 16 octets minimum. |
| `.max_password_bytes(n)` | `1024` | Les mots de passe plus longs sont refusés, jamais tronqués. |
| `.hash(password)` | — | `Result<String, PasswordError>` (`Empty`, `TooLong`, `Hashing`). |
| `.verify(password, hash)` | — | `bool`. |
| `.check(password, hash)` | — | `Invalid`, `Valid` ou `ValidNeedsRehash(new_hash)`. |
| `.needs_rehash(hash)` | — | Le hachage est-il plus faible que les paramètres actuels ? |
| `.verify_dummy(password)` | — | Consomme une vérification et renvoie `false`. |

L'OWASP liste des réglages équivalents qui échangent mémoire contre itérations, par exemple `with_params(47104, 1, 1)`, `with_params(12288, 3, 1)` ou `with_params(9216, 4, 1)`. Augmentez-les selon votre matériel : les utilisateurs existants sont mis à niveau à leur prochaine connexion.

## Poivre

Un poivre est un secret qui vit hors de la base (variable d'environnement, gestionnaire de secrets). Avec lui, une base qui fuite ne suffit pas à un attaquant :

```rust
use securite::password::PasswordHasher;

let pepper = std::env::var("PASSWORD_PEPPER").expect("PASSWORD_PEPPER must be set");
let hasher = PasswordHasher::new().pepper(pepper);
```

Perdre le poivre oblige chaque utilisateur à réinitialiser son mot de passe, et un hachage fait avec lui ne se vérifie qu'avec lui : sauvegardez-le comme une clé de chiffrement.

## Pièges et conseils

- Ne hachez jamais un mot de passe avec SHA-256, MD5 ou HMAC : ils sont conçus pour être rapides. `Auth::token_sha256` convient à des jetons d'API aléatoires, pas à des mots de passe humains.
- Ne tronquez ni ne normalisez les mots de passe en silence. Laissez les utilisateurs saisir de longues phrases de passe ; `1024` octets, c'est large.
- Appliquez une politique de mots de passe à part : longueur minimale (8 à 15 caractères selon le NIST SP 800-63B), vérification contre les mots de passe ayant fuité, pas de règles de composition.
- Le `Debug` de `PasswordCheck` n'affiche jamais le hachage, mais gardez les hachages eux-mêmes hors de vos journaux.

## Pages associées

- [Limitation des tentatives de connexion](/docs/login-throttle)
- [Authentification à deux facteurs](/docs/two-factor)
- [Authentification](/docs/auth)
- [Autorisations](/docs/authorization)
