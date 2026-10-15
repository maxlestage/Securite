---
title: Authentification à deux facteurs
summary: Mots de passe à usage unique basés sur le temps (RFC 6238) compatibles avec toutes les applications d'authentification, avec protection contre le rejeu, QR code et codes de secours.
category: access
order: 8
---

`Totp` implémente les mots de passe à usage unique basés sur le temps (RFC 6238), les codes à 6 chiffres de Google Authenticator, Authy, 1Password, Bitwarden ou FreeOTP. Un second facteur arrête la plupart des prises de contrôle de compte qui commencent par un mot de passe ayant fuité, hameçonné ou réutilisé.

## Menaces couvertes

- **A07:2021 Identification et authentification de mauvaise qualité** : comptes protégés par un simple mot de passe (CWE-308) ; le niveau 2 de l'OWASP ASVS exige l'authentification multifacteur.
- **Rejeu de code** : un code vu par-dessus une épaule, dans un journal ou par un proxy d'hameçonnage est refusé une fois utilisé (RFC 6238 §5.2).
- **Fuites temporelles** : les codes sont comparés en temps constant, chaque pas de temps accepté est vérifié sans sortie anticipée.

## Enrôlement

```rust
use securite::totp::{Totp, recovery_codes};

let totp = Totp::generate(); // secret aléatoire de 160 bits
let uri = totp.provisioning_uri("Example Inc", &user.email);
// otpauth://totp/Example%20Inc:alice%40example.com?secret=JBSWY3DP...&issuer=Example%20Inc
// Affichez `uri` en QR code ; montrez `totp.secret_base32()` pour la saisie manuelle.

// Stockez le secret (chiffré) avec l'utilisateur seulement après qu'il a saisi un code valide :
assert!(totp.verify(&code_typed_by_user));
db.save_totp_secret(user.id, &totp.secret_base32());

// Codes de secours : affichez-les une fois, ne stockez que leurs empreintes.
let codes = recovery_codes(10); // ["k3m7q-2vx9t", ...]
```

## Connexion

```rust
use securite::totp::Totp;

let totp = Totp::from_base32(&user.totp_secret)?;
match totp.verify_once(&form.code, user.totp_last_step) {
    Some(step) => {
        db.set_totp_last_step(user.id, step); // le même code ne pourra pas resservir
        // second facteur OK
    }
    None => { /* code faux, expiré ou rejoué */ }
}
```

`verify_once` refuse tous les pas de temps jusqu'à celui enregistré lors de la connexion réussie précédente : un code ne sert qu'une fois, même pendant sa période de validité. Protégez cet endpoint avec la [limitation des tentatives de connexion](/docs/login-throttle) : sans limite, un million de combinaisons tombent vite.

## Fonctionnement

- Le secret et le pas de temps courant (`temps unix / 30`) passent dans HMAC-SHA1 (ou SHA-256 / SHA-512), et la troncature dynamique de la RFC 4226 transforme le résultat en 6 à 8 chiffres. L'implémentation passe tous les vecteurs de test de la RFC 6238.
- Un pas de dérive d'horloge est accepté de chaque côté par défaut : un code est valable environ 90 secondes.
- Les espaces du code saisi sont ignorés (`123 456`) ; tout ce qui n'est pas une suite de chiffres ASCII de la bonne longueur est refusé.
- Les secrets de moins de 128 bits sont refusés ; le `Debug` n'affiche jamais le secret, qui est effacé quand la valeur est libérée.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Totp::generate()` | — | Secret de 160 bits tiré du générateur cryptographique du système. |
| `Totp::new(bytes)` | — | Secret brut ; panique sous 16 octets. |
| `Totp::from_base32(s)` | — | Secret stocké ; casse, espaces, tirets et remplissage ignorés. |
| `.algorithm(a)` | `Sha1` | `Sha1`, `Sha256` ou `Sha512` (vérifiez que les applications de vos utilisateurs les gèrent). |
| `.digits(n)` | `6` | 6 à 8. |
| `.period(d)` | 30 s | Durée d'un pas de temps. |
| `.skew(n)` | `1` | Pas acceptés de chaque côté (10 au plus). |
| `.verify(code)` / `.verify_at(code, t)` | — | Vérification sans protection contre le rejeu. |
| `.verify_once(code, last_step)` | — | Vérification avec protection contre le rejeu ; renvoie le pas à stocker. |
| `.provisioning_uri(issuer, account)` | — | URI `otpauth://` pour les QR codes. |
| `recovery_codes(n)` | — | `n` codes à usage unique de 50 bits aléatoires. |

## Pièges et conseils

- Chiffrez les secrets TOTP au repos : contrairement à une empreinte de mot de passe, le secret doit rester lisible pour vérifier les codes.
- Demandez un code valide avant d'activer la 2FA, pour qu'un secret mal saisi ne bloque pas l'utilisateur.
- Hachez les codes de secours comme des mots de passe (par exemple avec [`PasswordHasher`](/docs/passwords)) et supprimez chacun dès qu'il sert.
- Synchronisez les horloges des serveurs avec NTP ; n'élargissez `skew` que si des utilisateurs signalent des codes refusés.
- TOTP n'arrête pas les proxies d'hameçonnage en temps réel ; WebAuthn / les passkeys, si. Proposez-les aussi quand c'est possible.

## Pages associées

- [Limitation des tentatives de connexion](/docs/login-throttle)
- [Hachage des mots de passe](/docs/passwords)
- [Authentification](/docs/auth)
