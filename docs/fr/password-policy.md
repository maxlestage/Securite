---
title: Politique de mots de passe
summary: Les règles de mots de passe du NIST SP 800-63B (longueur, listes de refus, mots du contexte, pas de règles de composition) et la vérification des mots de passe ayant fuité avec l'API k-anonyme de Have I Been Pwned.
category: access
order: 12
---

`PasswordPolicy` vérifie les nouveaux mots de passe comme le demandent le NIST SP 800-63B et l'OWASP ASVS : assez longs, pas trop courants, pas tirés du nom ou de l'e-mail de l'utilisateur, ni trivialement répétitifs ou séquentiels, et absents des fuites de données. Elle n'impose **pas** « une majuscule, un chiffre, un symbole » : ces règles produisent `Password1!` et le NIST les déconseille.

## Menaces couvertes

- **A07:2021 Identification et authentification de mauvaise qualité** : mots de passe faibles (CWE-521).
- **Credential stuffing** : mots de passe déjà fuités ailleurs, refusés grâce à Have I Been Pwned.
- **Devinette ciblée** : mots de passe construits à partir du nom d'utilisateur, de l'e-mail ou du nom du site.

## Démarrage rapide

```rust
use securite::password_policy::PasswordPolicy;

let policy = PasswordPolicy::new().context([&form.username, &form.email, "Acme"]);

if let Err(e) = policy.check(&form.password) {
    // e.violations() : TooShort, TooLong, Common, Context, Repetitive, Sequential …
    return Err(format!("Choisissez un autre mot de passe : {e}"));
}
let hash = hasher.hash(&form.password)?;
```

Toutes les règles enfreintes sont renvoyées, chacune avec un message lisible (`Display`).

## Mots de passe ayant fuité (Have I Been Pwned)

Avec la k-anonymité, seuls les 5 premiers caractères hexadécimaux du SHA-1 du mot de passe quittent votre serveur. `securite` construit la requête et lit la réponse ; l'appel HTTP est le vôtre, avec n'importe quel client :

```rust
use securite::password_policy::hibp::RangeQuery;

let query = RangeQuery::new(&form.password);
let body = http_get(&query.url(), [("Add-Padding", "true")]).await?; // votre client HTTP
let count = query.count(&body);
policy.check_with_breaches(&form.password, count)?; // Violation::Breached { count }
```

Si l'API est injoignable, décidez explicitement : refuser le changement, ou l'accepter et vérifier de nouveau à la prochaine connexion.

## Règles

| Règle | Par défaut |
|---|---|
| Longueur minimale | 12 caractères (`min_length`, au moins 8) |
| Longueur maximale | 128 caractères (`max_length`, au moins 64), borne le coût du hachage |
| Mots de passe courants | ~200 parmi les plus courants, y compris entourés de chiffres et de symboles |
| Mots du contexte | `context([...])` : mots de 4 caractères ou plus, sans tenir compte de la casse ; la partie locale des e-mails aussi |
| Répétitifs | Trop peu de caractères distincts (`aaaaaaaaaaaa`, `abababababab`) |
| Séquentiels | Surtout une suite de l'alphabet, des chiffres ou du clavier (`abcdefgh`, `12345678`, `qwertyui`, `azertyui`) |
| Liste de refus maison | `blocklist([...])` |

La longueur se compte en caractères, pas en octets : tous les caractères Unicode et les espaces sont permis, les phrases de passe fonctionnent.

## Pièges et conseils

- Appliquez la politique à l'inscription et au changement de mot de passe, jamais à la connexion (les anciens mots de passe doivent encore permettre de se connecter, puis d'être changés).
- Montrez toutes les infractions d'un coup, avec une indication de robustesse, plutôt qu'une erreur à la fois.
- Ne journalisez jamais le mot de passe ni le suffixe de `RangeQuery` (son `Debug` le cache).

## Pages liées

- [Hachage des mots de passe](/docs/passwords)
- [Limitation des tentatives de connexion](/docs/login-throttle)
- [Double authentification](/docs/two-factor)
