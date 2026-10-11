---
title: Blocage des robots
summary: Rejette les requêtes des scanners de vulnérabilités et outils d'attaque connus d'après leur User-Agent, un filtre peu coûteux qui élimine l'essentiel du bruit automatisé.
category: threats
order: 2
---

Un point d'accès public reçoit un flux constant de reconnaissance automatisée : sqlmap, nikto, nuclei, wpscan, gobuster et consorts, à la recherche de vulnérabilités connues et de fichiers oubliés. La plupart de ces outils s'annoncent dans l'en-tête `User-Agent`. `BotBlocker` les rejette avec `403 Forbidden` avant qu'ils n'atteignent le WAF et vos handlers, ce qui garde vos journaux lisibles et réserve vos serveurs aux vrais utilisateurs.

## Menaces couvertes

- Le balayage automatisé de vulnérabilités et la collecte d'informations (OWASP Automated Threats OAT-014 et OAT-018), cette reconnaissance qui précède l'exploitation de A05:2021 Security Misconfiguration et A06:2021 Vulnerable and Outdated Components.
- Les outils de force brute prêts à l'emploi comme hydra (OAT-007 Credential Cracking, A07:2021 Identification and Authentication Failures).
- En option, les scripts qui n'envoient aucun `User-Agent`.

> **Attention :** l'en-tête `User-Agent` est entièrement contrôlé par le client. N'importe quel attaquant peut se faire passer pour Firefox en une ligne de code. Le blocage des robots est un filtre anti-bruit qui écarte le trafic automatisé et négligent ; ce n'est pas une frontière de sécurité. La véritable protection vient du WAF, de la limitation de débit, du bannissement automatique et de l'authentification.

## Fonctionnement

1. Le guard lit l'en-tête `User-Agent`.
2. La liste d'autorisation est consultée en premier : une correspondance laisse passer la requête.
3. La liste de refus est comparée sous forme de sous-chaînes insensibles à la casse, tous les motifs à la fois, avec un unique automate Aho-Corasick. Le coût ne dépend pas du nombre de motifs.
4. En cas de correspondance, la requête est rejetée avec `403`, le code `bot_blocked` et le message `Automated clients are not allowed.` Le motif reconnu n'est consigné que dans les détails d'audit, par exemple `user-agent matched "sqlmap"`.
5. Une requête sans en-tête `User-Agent` passe, sauf si `block_empty(true)` est activé.

Le guard s'exécute après la limitation de débit et avant le WAF.

## La liste de refus par défaut

`BotBlocker::new()` bloque les fragments listés dans `securite::user_agent::DEFAULT_DENY` :

```text
sqlmap, nikto, nmap, masscan, zgrab, nuclei, acunetix, netsparker,
wpscan, joomscan, dirbuster, gobuster, dirb/, feroxbuster, ffuf, wfuzz,
hydra, havij, w3af, openvas, arachni, skipfish, commix, xsstrike,
jaeles, whatweb, zmeu, morfeus, fimap, nessus, qualys, burpcollaborator,
interactsh, censysinspect, "httpx - open-source",
"go-http-client/1.1 (scanner"
```

## Démarrage rapide

`BotBlocker::new()` fait partie des préréglages `recommended`, `strict` et `api`. Pour l'utiliser dans votre propre shield :

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::builder().guard(BotBlocker::new()).build());
app.get("/", |_req: Request| async { "home" });
```

## Configuration

| Méthode | Défaut | Description |
|---|---|---|
| `BotBlocker::new()` | `DEFAULT_DENY` | Bloque les outils connus listés ci-dessus. |
| `BotBlocker::empty()` | liste de refus vide | Part de zéro : seuls vos motifs s'appliquent. |
| `.deny(patterns)` | aucun | Ajoute des motifs de refus (sous-chaînes insensibles à la casse). |
| `.allow(patterns)` | aucun | Motifs toujours autorisés, vérifiés avant la liste de refus. |
| `.block_empty(bool)` | `false` | Rejette les requêtes sans en-tête `User-Agent`. |
| `.monitor()` | blocage | Signale les correspondances sans bloquer. |
| `.check(&str)` | — | Renvoie le motif de refus reconnu, s'il y en a un (`Option<&str>`). |

## Exemples

### Site réservé aux navigateurs

Un site vitrine ou une application rendue côté serveur n'a aucune raison de servir des bibliothèques HTTP génériques :

```rust
use securite::prelude::*;

let bots = BotBlocker::new()
    // Generic HTTP clients: fine for a browser-only site, not for a public API.
    .deny(["python-requests", "curl/", "go-http-client", "libwww-perl"])
    .block_empty(true);
```

### Votre propre scanner de sécurité

```rust
use securite::prelude::*;

let bots = BotBlocker::new()
    // Our weekly authenticated scan announces itself with this marker.
    .allow(["acme-security-audit/"]);
```

### Uniquement vos propres motifs

```rust
use securite::prelude::*;

let bots = BotBlocker::empty().deny(["badbot", "evil-crawler"]);
```

### Tester un User-Agent

```rust
use securite::prelude::*;

let bots = BotBlocker::new();
assert_eq!(bots.check("sqlmap/1.7.2#stable (https://sqlmap.org)"), Some("sqlmap"));
assert_eq!(bots.check("Mozilla/5.0 (compatible; Nmap Scripting Engine)"), Some("nmap"));
assert!(bots.check("Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0").is_none());
```

### Observer d'abord

Avant de refuser les clients génériques sur un service existant, découvrez qui les utilise réellement :

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(BotBlocker::new().deny(["python-requests"]).monitor())
    .build();
```

## Utilisation comme guard autonome

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(BotBlocker::new().block_empty(true)));
app.get("/", |_req: Request| async { "home" });
```

## Pièges et conseils

- La comparaison se fait par sous-chaîne : un motif court attrape plus de choses qu'on ne le croit. `curl` reconnaîtrait aussi `curling-club-app/2.0` ; préférez `curl/`.
- Les entrées de la liste d'autorisation peuvent être recopiées par quiconque les connaît. Elles ne contournent que le blocage des robots, pas le WAF ni la limitation de débit ; restreignez aussi vos propres scanners par adresse IP.
- `block_empty(true)` ne rejette que les requêtes dépourvues d'en-tête `User-Agent`. Vérifiez que les sondes de santé de votre répartiteur de charge, vos outils de supervision et vos fournisseurs de webhooks en envoient un avant de l'activer.
- Certaines organisations font tourner Qualys ou Nessus pour leurs audits de conformité. Ajoutez `.allow(["qualys"])` ou `.allow(["nessus"])` si vos propres scans doivent passer.
- Avec `AutoBan` dans le même shield, chaque blocage compte comme une pénalité : un scanner qui insiste finit banni par adresse IP, y compris pour ses requêtes munies d'un `User-Agent` de navigateur falsifié.

## Pages associées

- [Pare-feu applicatif (WAF)](/docs/waf)
- [Limitation de débit](/docs/rate-limit)
- [Bannissement automatique](/docs/auto-ban)
- [Événements de sécurité et statistiques](/docs/events-stats)
