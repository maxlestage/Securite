---
title: Filtrage des méthodes
summary: N'autorisez que les méthodes HTTP réellement utilisées, refusez TRACE, CONNECT et les verbes WebDAV, et bloquez les en-têtes de surcharge de méthode.
category: traffic
order: 6
---

`MethodFilter` est une liste blanche globale de méthodes HTTP. Les requêtes utilisant une autre méthode sont refusées avec `405 Method Not Allowed` et un en-tête `Allow`, avant que le routage, la limitation de débit ou le WAF ne leur consacrent le moindre temps. Par défaut, il rejette aussi les en-têtes de surcharge de méthode.

## Menaces couvertes

* **Cross-Site Tracing (XST)** : `TRACE` renvoie la requête telle quelle, cookies et en-têtes d'autorisation compris, ce qui peut neutraliser la protection `HttpOnly` lorsqu'un proxy ou un framework l'implémente.
* **Détournement de proxy** : `CONNECT` transforme un serveur ou un proxy mal configuré en tunnel ouvert.
* **Surface d'attaque inattendue** : les verbes WebDAV (`PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK` …) et les méthodes personnalisées atteignent du code que personne n'a testé, et sont très prisés des scanners.
* **Contournement du contrôle d'accès par surcharge de méthode** : des en-têtes comme `X-HTTP-Method-Override: DELETE` font traiter un `POST` comme une autre méthode par les frameworks ou proxys qui les honorent, et passer outre les règles écrites pour la méthode réelle (OWASP A01:2021, Broken Access Control).

## Fonctionnement

```text
request ----> method in allow-list?
                no  -> 405 method_not_allowed + Allow: GET, HEAD, POST, ...
                yes -> override header present and not allowed?
                         yes -> 400 method_override
                         no  -> next guard
```

* La liste blanche par défaut est `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`.
* La valeur de l'en-tête `Allow` est calculée une seule fois, à la construction du filtre.
* Les en-têtes de surcharge bloqués sont `X-HTTP-Method-Override`, `X-HTTP-Method` et `X-Method-Override`, quelle que soit leur valeur.
* Le garde s'exécute en priorité 60, après `Hygiene` et avant `HostFilter`, `BodyLimit`, CORS et la limitation de débit.

## Démarrage rapide

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::builder().guard(MethodFilter::new()).build());
app.get("/", |_req: Request| async { "hello" });
```

`MethodFilter::new()` fait déjà partie des préréglages `recommended`, `strict` et `api`.

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `MethodFilter::new()` | – | `GET HEAD POST PUT PATCH DELETE OPTIONS`, en-têtes de surcharge bloqués. |
| `MethodFilter::only(methods)` | – | Exactement ces méthodes (remplace la liste par défaut). Panique sur une liste vide. |
| `MethodFilter::read_only()` | – | `GET HEAD OPTIONS` uniquement. |
| `.allow_method_override()` | bloqués | Accepte les en-têtes de surcharge de méthode (clients historiques). |

## Exemples

### Un site en lecture seule

Un site de documentation, une page de statut ou un miroir public n'ont jamais besoin d'écritures :

```rust
use securite::prelude::*;

let shield = Shield::builder()
    .guard(MethodFilter::read_only())
    .build();
```

### Une liste exacte avec une méthode personnalisée

`only` remplace la liste par défaut : énumérez tout ce dont vous avez besoin, y compris des verbes personnalisés comme un `PURGE` de cache :

```rust
use securite::http::Method;
use securite::prelude::*;

let purge = Method::from_bytes(b"PURGE").expect("valid method");
let filter = MethodFilter::only([
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::OPTIONS,
    purge,
]);
```

### Clients historiques qui ont besoin de la surcharge de méthode

Certains vieux formulaires HTML et clients de l'ère SOAP ne savent envoyer que `GET` et `POST`. Si votre framework s'appuie sur les en-têtes de surcharge, réactivez-les explicitement :

```rust
use securite::prelude::*;

let filter = MethodFilter::new().allow_method_override();
```

## Utilisation en guard autonome

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(MethodFilter::read_only()));
app.get("/", |_req: Request| async { "hello" });
```

## En-têtes de réponse

Une méthode refusée reçoit un en-tête `Allow` listant les méthodes acceptées, comme l'exige la RFC 9110 :

```text
HTTP/1.1 405 Method Not Allowed
allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Method Not Allowed","status":405,"code":"method_not_allowed","detail":"Method not allowed."}
```

Un en-tête de surcharge reçoit `400 Bad Request` avec le code `method_override`. La méthode refusée est inscrite dans les détails d'audit de l'événement de sécurité (`method=TRACE`), jamais dans la réponse au client.

## Pièges et conseils

* **Gardez `OPTIONS` si vous utilisez CORS** : les navigateurs envoient les requêtes de pré-vérification avec `OPTIONS`, et le filtrage des méthodes s'exécute avant le garde CORS. Sans elle, chaque pré-vérification cross-origin échoue en `405`.
* **Gardez `HEAD` à côté de `GET`** : sondes de disponibilité, robots d'indexation et vérificateurs de liens s'en servent, et Vitesse répond à `HEAD` pour chaque route `GET`.
* `MethodFilter` est global. Les restrictions de méthode par route restent l'affaire de votre routeur (Vitesse répond `405` pour un chemin connu avec une méthode non routée).
* Les noms de méthode sont sensibles à la casse : `get` n'est pas `GET`, et il est refusé.

> **Astuce :** l'événement de sécurité d'une méthode refusée contient son nom. Un pic de `TRACE`, `PROPFIND` ou `DEBUG` signale généralement un scanner qui explore votre site ; le [bannissement automatique](/docs/auto-ban), dans le même shield, compte chaque méthode refusée comme une pénalité et peut l'arrêter.

## Pages associées

* [Hygiène HTTP](/docs/hygiene)
* [Limite de taille du corps](/docs/body-limit)
* [Bannissement automatique](/docs/auto-ban)
* [CORS](/docs/cors)
