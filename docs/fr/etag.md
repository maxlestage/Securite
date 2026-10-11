---
title: ETag et 304 Not Modified
summary: Attribue à chaque réponse GET un ETag calculé à partir de son corps et répond 304 Not Modified, sans corps, lorsque le client l'a déjà.
category: everyday
order: 2
---

Un navigateur ou un client d'API qui a déjà téléchargé une page peut demander « a-t-elle changé ? » en renvoyant, dans un en-tête `If-None-Match`, l'`ETag` qu'il a reçu. `ETag` calcule cette étiquette pour vous à partir du corps de chaque réponse `GET` et `HEAD`, et répond `304 Not Modified` avec un corps vide si rien n'a changé : les octets ne voyagent jamais deux fois.

## Fonctionnement

1. Seules les requêtes `GET` et `HEAD`, et les réponses `200 OK`, sont concernées.
2. Si la réponse possède déjà un `ETag` (fichiers statiques servis par Vitesse), il est conservé.
3. Sinon, lorsque le corps est complet, de taille connue (texte, HTML, JSON…) et ne dépasse pas la limite (4 Mio par défaut), il est haché et la réponse reçoit `ETag: "<length>-<hash>"`. Les flux et les corps plus volumineux passent sans modification.
4. Si l'`If-None-Match` de la requête contient cette étiquette (ou `*`), le statut devient `304 Not Modified` et le corps est supprimé. Les autres en-têtes (`ETag`, `Cache-Control`, `Vary`…) sont conservés.

Le hachage (FNV-1a sur 64 bits) est stable d'un redémarrage et d'un serveur à l'autre : chaque instance derrière un répartiteur de charge produit la même étiquette pour le même corps.

## Démarrage rapide

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ETag::new());
app.get("/api/products", |_req: Request| async { Json(json!([{ "id": 1 }])) });
```

```bash
curl -i https://example.com/api/products
# HTTP/1.1 200 OK
# etag: "a-1f3c9b2e8d7a6c54"

curl -i https://example.com/api/products -H 'If-None-Match: "a-1f3c9b2e8d7a6c54"'
# HTTP/1.1 304 Not Modified
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `ETag::new()` | étiquettes fortes, 4 Mio | Crée le middleware (`ETag::default()` est équivalent). |
| `.max_size(bytes)` | `4 * 1024 * 1024` | Taille maximale d'un corps haché. Les corps plus gros ne reçoivent pas d'étiquette. |
| `.weak(true)` | `false` | Étiquettes faibles (`W/"…"`), lorsqu'un middleware ultérieur peut modifier les octets sans en changer le sens. |

## Avec Cache-Control

`ETag` décide si les octets doivent être renvoyés ; `Cache-Control` décide si le client pose seulement la question. `Cache-Control: no-cache` signifie « toujours demander, puis réutiliser si rien n'a changé » : c'est le partenaire idéal d'`ETag`.

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(ETag::new());
app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
```

## Pièges et conseils

- Le corps doit être calculé pour être haché : un `304` économise de la bande passante et du temps côté client, pas du travail côté serveur. Pour épargner aussi le serveur, ajoutez un [cache de réponses](/docs/response-cache).
- La comparaison est faible, comme l'exige la RFC 9110 pour `If-None-Match` : `W/"x"` correspond à `"x"`.
- Placez `ETag` avant un middleware de compression (pour qu'il s'exécute à l'intérieur) afin de hacher les octets d'origine, ou utilisez `.weak(true)`.

## Pages associées

- [Cache-Control](/docs/cache-control)
- [Cache de réponses](/docs/response-cache)
