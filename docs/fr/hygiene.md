---
title: Hygiène HTTP
summary: Rejetez les requêtes malformées ou ambiguës utilisées pour la contrebande de requêtes, la traversée de répertoires, l'injection d'en-têtes et l'épuisement des parseurs.
category: traffic
order: 5
---

`Hygiene` regroupe des contrôles de cohérence protocolaire peu coûteux, exécutés sur l'en-tête de chaque requête. Les navigateurs et clients HTTP légitimes ne les déclenchent jamais ; les outils d'attaque, les charges de contrebande et les scanners mal écrits, si. Ce garde fait partie de tous les préréglages.

## Menaces couvertes

* **Contrebande de requêtes HTTP** (CL.TE, TE.CL, TE.TE) : un découpage ambigu des messages qui amène un proxy et votre serveur à ne pas s'accorder sur la fin d'une requête.
* **Traversée de répertoires** (OWASP A01:2021) : séquences `../`, brutes, encodées en pourcent, voire doublement encodées, pour sortir d'un répertoire.
* **Injection d'en-têtes et fractionnement de réponse** : `NUL`, `CR` et `LF` glissés dans le chemin.
* **Épuisement des ressources et HashDoS** : URI démesurées, centaines d'en-têtes ou milliers de paramètres de requête qui malmènent parseurs et tables de hachage.
* **Confusion sur l'hôte** : plusieurs en-têtes `Host`, utilisés pour empoisonner les caches et contourner le routage.

## La contrebande de requêtes en bref

HTTP/1.1 offre deux façons de délimiter un corps : `Content-Length` (CL) et `Transfer-Encoding: chunked` (TE). Quand une requête porte les deux, ou une variante obscurcie, le proxy frontal et le serveur applicatif peuvent chacun retenir une méthode différente. Les octets que l'un considère comme « la fin du corps » sont lus par l'autre comme le **début de la requête suivante**, qui se retrouve alors greffée sur la connexion d'un autre utilisateur.

```text
CL.TE: the front-end trusts Content-Length, the back-end trusts Transfer-Encoding

POST / HTTP/1.1
Host: shop.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

front-end: forwards the 13 body bytes "0\r\n\r\nSMUGGLED"
back-end : chunk "0" ends the body; "SMUGGLED" is prefixed to the next request
```

TE.CL est le cas symétrique : le frontal suit les chunks tandis que le serveur applicatif s'arrête après un petit `Content-Length`, et le reste des données devient une requête. Les variantes TE.TE dissimulent l'en-tête à l'un des deux avec des valeurs comme `Transfer-Encoding: xchunked`, `chunked, identity` ou un en-tête dupliqué.

`Hygiene` n'essaie pas de deviner la bonne interprétation : une requête ambiguë est purement et simplement refusée, il ne reste donc aucun désaccord à exploiter.

## Contrôles et valeurs par défaut

Les contrôles s'exécutent dans cet ordre ; le premier échec détermine la réponse.

| Contrôle | Défaut | Statut | Code |
|---|---|---|---|
| Longueur de l'URI (chemin et query) | 8 Kio | `414` | `uri_too_long` |
| Nombre d'en-têtes | 100 | `431` | `too_many_headers` |
| Taille totale des noms et valeurs d'en-têtes | 32 Kio | `431` | `headers_too_large` |
| `Content-Length` et `Transfer-Encoding` à la fois | rejeté | `400` | `ambiguous_framing` |
| `Transfer-Encoding` autre qu'un unique `chunked` | rejeté | `400` | `bad_transfer_encoding` |
| `Content-Length` invalide (signe, lettres, valeur vide) | rejeté | `400` | `bad_content_length` |
| Valeurs de `Content-Length` contradictoires | rejeté | `400` | `bad_content_length` |
| Plusieurs en-têtes `Host` | rejeté | `400` | `duplicate_host` |
| Caractères de contrôle dans le chemin brut | rejeté | `400` | `bad_path` |
| Encodage pourcent malformé dans le chemin | rejeté | `400` | `bad_path_encoding` |
| `NUL`, `CR`, `LF` dans le chemin décodé | rejeté | `400` | `bad_path` |
| Segments `..` ou `.` (bruts, encodés, doublement encodés, séparateurs `\`) | rejeté | `400` | `path_traversal` |
| Nombre de paramètres de requête | 256 | `400` | `too_many_params` |
| `%00` dans la query string | rejeté | `400` | `bad_query` |

Les longueurs identiques répétées (`Content-Length: 5, 5`) sont acceptées, comme le permet la RFC 9110. Les segments de points sont comparés en entier : `/files/report..pdf` passe, `/a/%252e%252e/etc` non (le chemin est décodé deux fois pour détecter le double encodage).

## Démarrage rapide

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(Shield::builder().guard(Hygiene::new()).build());
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Hygiene::new()` | – | Tous les contrôles actifs avec les valeurs ci-dessus. |
| `.max_uri_length(bytes)` | `8192` | Longueur maximale de l'URI (`414 URI Too Long`). |
| `.max_headers(n)` | `100` | Nombre maximal d'en-têtes de requête (`431`). |
| `.max_header_bytes(bytes)` | `32768` | Taille cumulée maximale des noms et valeurs d'en-têtes (`431`). |
| `.max_query_params(n)` | `256` | Nombre maximal de paramètres de requête. |
| `.allow_dot_segments()` | rejeté | Accepte les segments `..` et `.` dans les chemins (déconseillé). |
| `.allow_bad_encoding()` | rejeté | Accepte un encodage pourcent malformé dans les chemins. |

Les contrôles de découpage, de `Host`, de caractères de contrôle et de `NUL` ne peuvent pas être désactivés.

## Exemples

### Des limites plus strictes pour une API JSON

```rust
use securite::prelude::*;

let hygiene = Hygiene::new()
    .max_uri_length(2 * 1024)
    .max_headers(50)
    .max_header_bytes(16 * 1024)
    .max_query_params(32);

let shield = ShieldBuilder::api()
    .guard(hygiene) // replaces the preset's Hygiene
    .build();
```

### Clients historiques

Certains vieux clients envoient des signes `%` non échappés dans les chemins. N'assouplissez que ce contrôle, et seulement si c'est indispensable :

```rust
use securite::prelude::*;

let hygiene = Hygiene::new().allow_bad_encoding();
```

## Utilisation en couche autonome

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(Hygiene::new());
```

## En-têtes de réponse

`Hygiene` n'ajoute aucun en-tête particulier. Les rejets utilisent le format d'erreur du bouclier :

```text
HTTP/1.1 400 Bad Request
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Bad Request","status":400,"code":"path_traversal","detail":"Dot segments are not allowed."}
```

## Pièges et conseils

* **Cookies ou jetons volumineux** : de gros JWT et de nombreux cookies peuvent dépasser 32 Kio d'en-têtes. Augmentez `max_header_bytes` plutôt que de désactiver des contrôles.
* **Formulaires de recherche et filtres** comportant de nombreux champs peuvent dépasser `max_query_params` ; dimensionnez-le d'après votre plus grand formulaire légitime.
* `Hygiene` voit la requête après son analyse par votre serveur HTTP. C'est une défense en profondeur : maintenez aussi votre proxy et votre serveur à jour, et configurés pour rejeter les découpages ambigus.
* Avec `AutoBan` dans le même shield, chaque rejet de l'hygiène compte comme une pénalité : les récidivistes finissent bannis. Entre couches autonomes séparées, `AutoBan` ne voit que le statut `400` : ajoutez alors `count_status(400)`.

> **Astuce :** `Hygiene` s'exécute en priorité 50, avant la limitation de débit et le WAF. Les requêtes aberrantes sont écartées avant tout contrôle coûteux.

## Pages associées

* [Limite de taille du corps](/docs/body-limit)
* [Filtrage des méthodes](/docs/method-filter)
* [Pare-feu applicatif (WAF)](/docs/waf)
* [Bannissement automatique](/docs/auto-ban)
