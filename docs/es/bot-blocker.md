---
title: Bloqueo de bots
summary: Rechaza las peticiones de escáneres de vulnerabilidades y herramientas de ataque conocidas por su User-Agent, un filtro barato que elimina la mayor parte del ruido automatizado.
category: threats
order: 2
---

Un endpoint público recibe un flujo constante de reconocimiento automatizado: sqlmap, nikto, nuclei, wpscan, gobuster y compañía, en busca de vulnerabilidades conocidas y archivos olvidados. La mayoría de estas herramientas se identifican en la cabecera `User-Agent`. `BotBlocker` las rechaza con `403 Forbidden` antes de que lleguen al WAF y a sus handlers, lo que mantiene legibles sus registros y deja sus servidores para los usuarios reales.

## Amenazas que mitiga

- El escaneo automatizado de vulnerabilidades y la recopilación de información (OWASP Automated Threats OAT-014 y OAT-018), el reconocimiento que precede a la explotación de A05:2021 Security Misconfiguration y A06:2021 Vulnerable and Outdated Components.
- Herramientas de fuerza bruta listas para usar como hydra (OAT-007 Credential Cracking, A07:2021 Identification and Authentication Failures).
- Opcionalmente, scripts que no envían ningún `User-Agent`.

> **Atención:** la cabecera `User-Agent` la controla por completo el cliente. Cualquier atacante puede hacerse pasar por Firefox con una línea de código. El bloqueador de bots es un filtro de ruido que descarta el tráfico automatizado y descuidado; no es una frontera de seguridad. La protección real la aportan el WAF, la limitación de peticiones, el bloqueo automático y la autenticación.

## Funcionamiento

1. El guard lee la cabecera `User-Agent`.
2. Primero se consulta la lista de permitidos: una coincidencia deja pasar la petición.
3. La lista de denegados se compara como subcadenas sin distinguir mayúsculas, todos los patrones a la vez, con un único autómata Aho-Corasick. El coste no depende del número de patrones.
4. Si hay coincidencia, la petición se rechaza con `403`, el código `bot_blocked` y el mensaje `Automated clients are not allowed.` El patrón detectado solo se registra en los detalles de auditoría, por ejemplo `user-agent matched "sqlmap"`.
5. Una petición sin cabecera `User-Agent` pasa, salvo que se active `block_empty(true)`.

El guard se ejecuta después de la limitación de peticiones y antes del WAF.

## La lista de denegados por defecto

`BotBlocker::new()` bloquea los fragmentos de `securite::user_agent::DEFAULT_DENY`:

```text
sqlmap, nikto, nmap, masscan, zgrab, nuclei, acunetix, netsparker,
wpscan, joomscan, dirbuster, gobuster, dirb/, feroxbuster, ffuf, wfuzz,
hydra, havij, w3af, openvas, arachni, skipfish, commix, xsstrike,
jaeles, whatweb, zmeu, morfeus, fimap, nessus, qualys, burpcollaborator,
interactsh, censysinspect, "httpx - open-source",
"go-http-client/1.1 (scanner"
```

## Inicio rápido

`BotBlocker::new()` forma parte de los presets `recommended`, `strict` y `api`. Para usarlo en su propio escudo:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::builder().guard(BotBlocker::new()).build());
app.get("/", |_req: Request| async { "home" });
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `BotBlocker::new()` | `DEFAULT_DENY` | Bloquea las herramientas conocidas de la lista anterior. |
| `BotBlocker::empty()` | lista de denegados vacía | Empieza sin ningún patrón: solo se aplican los suyos. |
| `.deny(patterns)` | ninguno | Añade patrones de denegación (subcadenas sin distinguir mayúsculas). |
| `.allow(patterns)` | ninguno | Patrones siempre permitidos, comprobados antes de la lista de denegados. |
| `.block_empty(bool)` | `false` | Rechaza las peticiones sin cabecera `User-Agent`. |
| `.monitor()` | bloqueo | Informa de las coincidencias sin bloquear. |
| `.check(&str)` | — | Devuelve el patrón de denegación detectado, si lo hay (`Option<&str>`). |

## Ejemplos

### Sitio solo para navegadores

Un sitio corporativo o una aplicación renderizada en el servidor no tiene por qué atender a bibliotecas HTTP genéricas:

```rust
use securite::prelude::*;

let bots = BotBlocker::new()
    // Generic HTTP clients: fine for a browser-only site, not for a public API.
    .deny(["python-requests", "curl/", "go-http-client", "libwww-perl"])
    .block_empty(true);
```

### Su propio escáner de seguridad

```rust
use securite::prelude::*;

let bots = BotBlocker::new()
    // Our weekly authenticated scan announces itself with this marker.
    .allow(["acme-security-audit/"]);
```

### Solo sus propios patrones

```rust
use securite::prelude::*;

let bots = BotBlocker::empty().deny(["badbot", "evil-crawler"]);
```

### Probar un User-Agent

```rust
use securite::prelude::*;

let bots = BotBlocker::new();
assert_eq!(bots.check("sqlmap/1.7.2#stable (https://sqlmap.org)"), Some("sqlmap"));
assert_eq!(bots.check("Mozilla/5.0 (compatible; Nmap Scripting Engine)"), Some("nmap"));
assert!(bots.check("Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0").is_none());
```

### Observar primero

Antes de denegar clientes genéricos en un servicio existente, averigüe quién los usa realmente:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(BotBlocker::new().deny(["python-requests"]).monitor())
    .build();
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(BotBlocker::new().block_empty(true)));
app.get("/", |_req: Request| async { "home" });
```

## Errores comunes y consejos

- La comparación es por subcadena: un patrón corto captura más de lo que parece. `curl` también coincidiría con `curling-club-app/2.0`; es preferible `curl/`.
- Cualquiera que conozca las entradas de la lista de permitidos puede copiarlas. Solo eluden el bloqueador de bots, no el WAF ni la limitación de peticiones; restrinja también sus propios escáneres por dirección IP.
- `block_empty(true)` solo rechaza las peticiones que no tienen cabecera `User-Agent`. Antes de activarlo, compruebe que los health checks de su balanceador de carga, sus herramientas de monitorización y sus proveedores de webhooks envían una.
- Algunas organizaciones usan Qualys o Nessus para sus auditorías de cumplimiento. Añada `.allow(["qualys"])` o `.allow(["nessus"])` si sus propios escaneos deben pasar.
- Con `AutoBan` en el mismo escudo, cada bloqueo cuenta como una penalización: un escáner que insiste acaba bloqueado por dirección IP, incluso en sus peticiones con un `User-Agent` de navegador falsificado.

## Páginas relacionadas

- [Firewall de aplicaciones web (WAF)](/docs/waf)
- [Limitación de peticiones](/docs/rate-limit)
- [Bloqueo automático](/docs/auto-ban)
- [Eventos de seguridad y estadísticas](/docs/events-stats)
