---
title: Limitation des tentatives de connexion
summary: Verrouille un compte, une adresse ou les deux après des échecs répétés, contre la devinette de mots de passe, le credential stuffing et la force brute sur la 2FA.
category: traffic
order: 7
---

`LoginThrottle` compte les **tentatives échouées** par clé, une clé que vous choisissez, et verrouille la clé une fois la limite atteinte, jusqu'à la fin de sa fenêtre. C'est le `RateLimiter` / `ThrottlesLogins` de Laravel pour Rust. Là où la [limitation de débit](/docs/rate-limit) compte les requêtes par IP avant votre handler, `LoginThrottle` est appelé depuis le handler, une fois que vous savez quel compte est visé et si la tentative a échoué.

## Menaces couvertes

- **A07:2021 Identification et authentification de mauvaise qualité** : devinette de mot de passe en ligne contre un compte (CWE-307).
- **Credential stuffing et password spraying** : des identifiants ayant fuité essayés depuis des milliers d'IP, ou un mot de passe courant essayé sur tous les comptes.
- **Force brute sur la 2FA** : un code à 6 chiffres n'a qu'un million de valeurs ; sans limite, il tombe en quelques heures.

## Démarrage rapide

```rust
use std::time::Duration;
use securite::prelude::*;

// 5 échecs par compte et par IP ; puis verrouillé jusqu'à la fin des 15 minutes.
let throttle = LoginThrottle::new(5, Duration::from_secs(15 * 60));

// Dans le handler de connexion :
let key = LoginThrottle::key(&form.email, client_ip); // "alice@example.com|203.0.113.7"
match throttle.attempt(&key, || hasher.verify(&form.password, &user.password_hash)) {
    Ok(true) => { /* connecté : les échecs de cette clé sont oubliés */ }
    Ok(false) => { /* 401 : identifiants incorrects */ }
    Err(retry_after) => { /* 429 avec `Retry-After: retry_after.as_secs()` */ }
}
```

`attempt` refuse une clé verrouillée **sans exécuter** la vérification : même le bon mot de passe est refusé jusqu'à la fin de la fenêtre, un attaquant n'apprend donc rien d'un essai chanceux.

## Fonctionnement

1. Le premier échec d'une clé ouvre une fenêtre de durée `decay`.
2. Chaque échec dans la fenêtre incrémente le compteur ; `check` échoue dès qu'il atteint `max_attempts`, avec le temps restant comme `Retry-After`.
3. À la fin de la fenêtre, le compteur repart de zéro ; un succès (`clear`) l'oublie immédiatement.
4. Les clés sont stockées sous forme d'empreintes SHA-256 dans une table partitionnée, bornée (100 000 clés par défaut) et qui se nettoie seule. Quand elle est pleine d'entrées vivantes, les nouvelles clés sont refusées (échec fermé) au lieu d'échapper silencieusement au comptage.

## Choisir les clés

Un throttle par question à laquelle vous voulez répondre :

| Clé | Arrête | Exemple |
|---|---|---|
| compte + IP | un attaquant sur un compte, sans bloquer le vrai utilisateur ailleurs | `LoginThrottle::key(email, Some(ip))` |
| compte | le credential stuffing depuis de nombreuses IP | `LoginThrottle::key(email, None)`, avec une limite plus haute |
| IP | le password spraying sur tous les comptes | `ip.to_string()` |

```rust
use std::time::Duration;
use securite::prelude::*;

let per_account_ip = LoginThrottle::new(5, Duration::from_secs(15 * 60));
let per_account = LoginThrottle::new(50, Duration::from_secs(60 * 60));

let k1 = LoginThrottle::key(&email, Some(ip));
let k2 = LoginThrottle::key(&email, None);
per_account_ip.check(&k1).and(per_account.check(&k2))?; // Err(retry_after) : 429
if hasher.verify(&password, &hash) {
    per_account_ip.clear(&k1);
    per_account.clear(&k2);
} else {
    per_account_ip.hit(&k1);
    per_account.hit(&k2);
}
```

`key` supprime les espaces autour de l'identifiant et le met en minuscules : `Alice@Example.com` et `alice@example.com` partagent un compteur.

## Configuration

| Méthode | Description |
|---|---|
| `LoginThrottle::new(max_attempts, decay)` | Limite et fenêtre ; suit jusqu'à 100 000 clés. |
| `LoginThrottle::default()` | 5 échecs par 15 minutes. |
| `LoginThrottle::with_capacity(max, decay, keys)` | Borne personnalisée sur le nombre de clés suivies. |
| `LoginThrottle::key(identifier, ip)` | `"identifiant\|ip"`, normalisé. |
| `.attempt(key, verify)` | `Ok(bool)` ou `Err(retry_after)` ; efface en cas de succès, compte les échecs. |
| `.check(key)` / `.too_many_attempts(key)` | La clé est-elle verrouillée ? |
| `.check_all(keys)` | Plusieurs clés d'un même throttle ; l'attente la plus longue l'emporte. |
| `.hit(key)` | Enregistre un échec, renvoie le compte. |
| `.clear(key)` | Oublie les échecs (après un succès). |
| `.attempts(key)` / `.remaining(key)` | Compteurs actuels. |

## Pièges et conseils

- Un verrouillage par compte seul permet à un attaquant de bloquer volontairement n'importe quel utilisateur : préférez compte + IP pour la limite stricte et gardez une limite par compte élevée.
- Utilisez le même outil pour les codes 2FA, les demandes de réinitialisation de mot de passe et les renvois d'e-mail de vérification, chacun avec ses propres clés.
- L'état est en mémoire, par processus. Avec plusieurs instances, chacune compte de son côté : partagez les compteurs avec `LoginThrottle::with_store` (voir [compteurs partagés](/docs/shared-counters)), ou divisez vos limites en conséquence.
- Derrière un proxy, configurez l'[IP client](/docs/client-ip) (et les proxies de confiance), sinon tous les utilisateurs partagent l'adresse du proxy.
- Le [bannissement automatique](/docs/auto-ban) le complète : des réponses `401` et `429` répétées bannissent l'adresse dans toute l'application.

## Pages associées

- [Hachage des mots de passe](/docs/passwords)
- [Authentification à deux facteurs](/docs/two-factor)
- [Limitation de débit](/docs/rate-limit)
- [Bannissement automatique](/docs/auto-ban)
