---
title: Modo observación
summary: Ejecuta los guards solo para informar, mide los falsos positivos y pasa al bloqueo con confianza; la forma segura de desplegar un WAF o una CSP estricta.
category: start
order: 7
---

Activar un WAF o una Content-Security-Policy estricta delante de una aplicación existente entraña riesgos: un solo falso positivo puede bloquear una página de pago o una integración con un socio. El modo observación (`Mode::Monitor`) permite que un guard informe de lo que *habría* bloqueado mientras deja pasar el tráfico, para que lo ajustes con tráfico real antes de aplicarlo.

## Bloqueo y observación

Cada guard tiene un `Mode`:

| Modo | Cuando el guard detecta una infracción |
|---|---|
| `Mode::Enforce` (por defecto) | La petición se rechaza, se registra un evento `WARN` `request blocked` y se incrementa `blocked` |
| `Mode::Monitor` | La petición continúa hacia los guards siguientes y tu handler, se registra un evento `INFO` `violation (monitor mode)` y se incrementa `monitored` |

En ambos casos el shield emite un `SecurityEvent` con el mismo guard, código, estado y detalles; solo cambia su campo `enforced`. Una infracción observada no desactiva el resto de guards: un limitador de tasa en modo bloqueo sigue frenando las avalanchas de peticiones mientras el WAF está en observación.

## Guards compatibles

| Guard | `.monitor()` | Comportamiento en modo observación |
|---|---|---|
| `Waf` | Sí | Los ataques se notifican con su puntuación, los identificadores de regla y las categorías, y llegan al handler |
| `RateLimit` | Sí | Las peticiones que superan el límite pasan; las respuestas siguen mostrando `RateLimit-Remaining: 0` |
| `ConcurrencyLimit` | Sí | Las peticiones simultáneas que exceden el límite pasan y se notifican |
| `AutoBan` | Sí | Las infracciones y los baneos se calculan y se registran, pero los clientes baneados no se bloquean |
| `IpFilter` | Sí | Las direcciones denegadas pasan y se notifican |
| `HostFilter` | Sí | Los valores de `Host` desconocidos pasan y se notifican |
| `BotBlocker` | Sí | Los user agents reconocidos pasan y se notifican |
| `Csrf` | Sí | Las peticiones entre sitios que modifican estado pasan y se notifican |
| `SecurityHeaders` | No | Usa en su lugar una CSP en modo report-only (ver más abajo) |
| Otros guards integrados | No | `Auth`, `Hygiene`, `MethodFilter`, `BodyLimit`, `ContentTypeGuard`, `HttpsRedirect`, `Cors`, `RequestId` y `CookieHardening` siempre aplican sus reglas |

`.monitor()` es un método de builder, así que se encadena con el resto de la configuración: `Waf::new().paranoia(Paranoia::Medium).monitor()`. Tus propios guards adoptan este modo devolviendo `Mode::Monitor` desde `mode()`; consulta [Guards personalizados](/docs/custom-guards).

## CSP en modo report-only

`ContentSecurityPolicy::report_only()` envía `Content-Security-Policy-Report-Only` en lugar de la cabecera que bloquea. Los navegadores informan entonces de las infracciones sin bloquear nada:

```rust
use securite::headers::src;
use securite::prelude::*;

let csp = ContentSecurityPolicy::strict()
    .img_src([src::SELF, src::DATA, "https://images.example.com"])
    .report_uri(["/csp-reports"])
    .report_only();

let shield = ShieldBuilder::recommended()
    .guard(SecurityHeaders::new().csp(csp))
    .guard(Csrf::new().exempt("/csp-reports"))
    .build();
```

Los navegadores envían los informes como `application/csp-report` o `application/reports+json`. Exime el endpoint de la protección CSRF como en el ejemplo y, si tu shield incluye un `ContentTypeGuard`, permite esos tipos de medios u omite la ruta con `.skip("/csp-reports")`.

## Un despliegue progresivo

1. **Observar.** Despliega el WAF con `.monitor()` y la CSP con `.report_only()`. Todavía no se bloquea nada.
2. **Esperar a tener tráfico representativo.** Un ciclo de actividad completo, normalmente una o dos semanas, incluidos procesos por lotes, clientes móviles e integraciones con socios.
3. **Clasificar.** Cada evento del WAF observado incluye `details` del tipo `score=… rules=[…] categories=…`. Para cada falso positivo, corrige la aplicación, omite la ruta o la cabecera (`skip_paths`, `skip_headers`), desactiva la regla (`disable_rules`) o sube el umbral (`threshold`).
4. **Aplicar.** Quita `.monitor()`, o pasa a la CSP que bloquea, y mantén las alertas sobre los eventos. Activar primero el bloqueo en una sola instancia sirve como despliegue canario.
5. **Endurecer.** Sube el nivel de paranoia o restringe la CSP, y repite el ciclo.

Una variable de entorno permite cambiar de modo sin tocar el código:

```rust
use securite::prelude::*;

// WAF_ENFORCE=1 switches from observation to blocking.
let enforce = std::env::var("WAF_ENFORCE").is_ok_and(|v| v == "1");

let waf = Waf::new()
    .paranoia(Paranoia::Medium)
    .disable_rules([119]) // "sleep(" matched legitimate search queries
    .skip_paths(["/webhooks"]);
let waf = if enforce { waf } else { waf.monitor() };

let shield = ShieldBuilder::recommended().guard(waf).build();
```

> **Atención:** Un guard en modo observación no te protege: los ataques llegan a tus handlers. Mantén cortos los periodos de observación, deja el resto de guards en modo bloqueo y asegúrate de que alguien lee de verdad los informes.

## Observar las infracciones

### Callback de eventos

`on_event` recibe todos los eventos; `enforced` vale `false` en los observados:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .guard(Waf::new().monitor())
    .on_event(|e| {
        if !e.enforced {
            eprintln!(
                "[monitor] {} {} {} {} would return {} ({})",
                e.guard,
                e.code,
                e.method,
                e.path,
                e.status,
                e.details.unwrap_or("-"),
            );
        }
    })
    .build();
```

### tracing

Con `log_events` activado (el valor por defecto), los eventos se escriben bajo el target `securite`, con los campos `guard`, `code`, `status`, `ip`, `method`, `path`, `request_id` y `details`. Las infracciones observadas se registran con nivel `INFO` y los bloqueos con nivel `WARN`; un filtro como `RUST_LOG=securite=info` muestra ambos.

### Estadísticas

`shield.stats()` cuenta las infracciones observadas por separado de los bloqueos:

```rust
let stats = shield.stats();
println!(
    "{} requests, {} blocked, {} would have been blocked",
    stats.total, stats.blocked, stats.monitored,
);
println!("{}", stats.to_json());
// {"total":1200,"allowed":1198,"blocked":2,"monitored":37,"by_guard":{"request_id":0,
//  "hygiene":0,"method":0,"body_limit":0,"rate_limit":2,"bot_blocker":0,"waf":37,
//  "csrf":0,"security_headers":0,"cookies":0}}
```

`by_guard` suma, para cada guard, las infracciones bloqueadas y las observadas. Los contadores viven en memoria y vuelven a cero cuando se reinicia el proceso: expórtalos con regularidad (consulta [Eventos y estadísticas](/docs/events-stats)).

> **Consejo:** Las peticiones observadas cuentan como `allowed`, ya que efectivamente pasaron. `monitored` es exactamente el número de peticiones que el bloqueo habría rechazado, legítimas o no: compáralo con los ataques que hayas identificado realmente antes de dar el paso.
