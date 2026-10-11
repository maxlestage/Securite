---
title: Introducción
summary: Securite protege aplicaciones Vitesse, y cualquier servicio tower o hyper, con un solo middleware, el Shield, que ejecuta guards de seguridad rápidos en cada petición y refuerza cada respuesta.
category: start
order: 1
---

`securite` es un conjunto de herramientas de seguridad para servicios web en Rust, escrito para Vitesse y para el ecosistema tower. Reúne las protecciones que necesita cualquier aplicación expuesta a Internet (cabeceras de seguridad, limitación de tasa, cortafuegos de aplicaciones web, CSRF y CORS, filtrado de IP, baneo automático, autenticación, firmas de webhooks) tras una única capa que se añade con una sola línea.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::recommended());
app.get("/", |_req: Request| async { "Hello, secure world!" });
```

## Por qué securite

Ningún control detiene por sí solo todos los ataques. Securite aplica la **defensa en profundidad**: varias comprobaciones independientes y baratas, cada una de las cuales cierra un tipo distinto de debilidad, de modo que un hueco en una capa quede cubierto por la siguiente. Una petición que se mantiene por debajo del límite de tasa se topa igualmente con el WAF; un script inyectado a pesar del WAF sigue neutralizado por la Content-Security-Policy.

Los valores por defecto siguen las recomendaciones de OWASP (Secure Headers Project, Core Rule Set, cheat sheets de CSRF y de gestión de sesiones) y están pensados para usarse en producción tal cual. Desactivar una protección es una decisión explícita; nunca tienes que acordarte de activarla.

| OWASP Top 10 (2021) | Controles en securite |
|---|---|
| A01 Broken Access Control | Filtro de IP, filtro de host, autenticación, CSRF, CORS |
| A03 Injection | WAF, higiene HTTP, lista de tipos de contenido permitidos, CSP |
| A05 Security Misconfiguration | Cabeceras de seguridad, refuerzo de cookies, filtro de métodos, redirección HTTPS |
| A07 Identification and Authentication Failures | Límites de tasa por ruta, baneo automático, verificación de credenciales en tiempo constante |
| A08 Software and Data Integrity Failures | Verificación de firmas de webhooks |
| A09 Security Logging and Monitoring Failures | Eventos de seguridad, estadísticas en vivo, identificadores de petición |
| A10 Server-Side Request Forgery | Firmas SSRF del WAF |

## El concepto de Shield

`Shield` es el corazón del crate: una única capa tower que ejecuta un pipeline de **guards**.

```text
request ─► request_id ─► hygiene ─► … ─► rate_limit ─► waf ─► csrf ─► handler
                 │ first rejection stops the pipeline             │
                 ▼                                                ▼
        rejection (problem+json)                         handler response
                 └───────────────────────┬────────────────────────┘
                                         ▼
           on_response: security headers, rate-limit headers, CORS,
                        hardened cookies, x-request-id …
```

### Un pipeline de guards síncronos

Cada guard examina la petición sin su cuerpo (método, URI, cabeceras, extensiones) y la deja pasar o la rechaza. Los guards son síncronos y nunca cargan el cuerpo en un búfer, lo que los hace extremadamente rápidos. Se ejecutan por orden de prioridad ascendente, de modo que las comprobaciones baratas, como los baneos o la higiene del protocolo, ocurren antes que el WAF. El primer rechazo gana: tu handler nunca llega a ejecutarse y el cliente recibe un error estructurado.

### Decoración de respuestas

En cuanto existe una respuesta, venga de tu handler o de un rechazo, cada guard puede completar sus cabeceras. Por eso las respuestas de error también llevan las cabeceras de seguridad, las de limitación de tasa y el identificador de petición.

### Contexto compartido y eventos

Los guards comparten un contexto por petición (IP del cliente, identificador de petición, nonce de CSP…). Cada infracción genera un evento de seguridad, que se escribe con `tracing` y se pasa a tu propio callback. La página [Shield y presets](/docs/shield-presets) detalla el orden de ejecución.

## Middlewares

### Refuerzo del navegador

| Middleware | Qué hace |
|---|---|
| [Cabeceras de seguridad](/docs/security-headers) | CSP con nonces, HSTS, COOP, CORP, COEP, Permissions-Policy; elimina las cabeceras que delatan tu stack |
| [CORS](/docs/cors) | Intercambio de recursos entre orígenes estricto, basado en una lista de orígenes permitidos |
| [Cookies](/docs/cookies) | Añade `Secure`, `HttpOnly` y `SameSite` a cada `Set-Cookie` |
| [Redirección HTTPS](/docs/https-redirect) | Redirección de HTTP a HTTPS compatible con proxies |

### Control del tráfico

| Middleware | Qué hace |
|---|---|
| [Limitación de tasa](/docs/rate-limit) | Limitador GCRA por IP, cabecera, ruta o global |
| [Límite de concurrencia](/docs/concurrency-limit) | Limita las peticiones simultáneas por cliente |
| [Baneo automático](/docs/auto-ban) | Baneo al estilo fail2ban de los clientes que acumulan fallos |
| [Límite de cuerpo](/docs/body-limit) | Rechaza los cuerpos demasiado grandes antes de que tu handler los lea |
| [Higiene HTTP](/docs/hygiene) | Comprobaciones contra request smuggling, path traversal y anomalías de protocolo |
| [Filtro de métodos](/docs/method-filter) | Métodos HTTP permitidos; bloquea las cabeceras de sobrescritura de método |

### Control de acceso

| Middleware | Qué hace |
|---|---|
| [Filtro de IP](/docs/ip-filter) | Listas CIDR de direcciones permitidas y denegadas, actualizables en caliente |
| [Filtro de host](/docs/host-filter) | Lista de valores de `Host` permitidos contra el DNS rebinding y los ataques a la cabecera Host |
| [Autenticación](/docs/auth) | Token Bearer, clave de API y Basic, con comparaciones en tiempo constante |
| [CSRF](/docs/csrf) | Verificación Fetch Metadata y, opcionalmente, tokens double-submit firmados |
| [Tipo de contenido](/docs/content-type) | Lista de tipos de medios permitidos en las peticiones |

### Detección de amenazas

| Middleware | Qué hace |
|---|---|
| [WAF](/docs/waf) | Cortafuegos con puntuación de anomalías: SQLi, XSS, path traversal, RCE, Log4Shell, SSRF … |
| [Bloqueo de bots](/docs/bot-blocker) | Bloquea escáneres y herramientas de ataque conocidos |

### Integridad y trazabilidad

| Middleware | Qué hace |
|---|---|
| [ID de petición](/docs/request-id) | Identificadores de petición validados para logs, handlers y respuestas |
| [Firmas de webhooks](/docs/webhook-signatures) | Verificación HMAC para GitHub, Stripe, Slack, Shopify … |
| [Eventos y estadísticas](/docs/events-stats) | Registro de auditoría, integración con `tracing` y contadores en vivo |
| [Formato de errores](/docs/error-format) | Cuerpos de error problem+json (RFC 9457), texto plano, vacíos o personalizados |

## Rendimiento

La seguridad que ralentiza una aplicación acaba desactivada, así que Securite está diseñado para la velocidad. Mediciones realizadas con criterion (`cargo bench -p securite`):

| Benchmark | Tiempo |
|---|---|
| Pipeline recomendado completo, petición realista de navegador | ~6 µs |
| Inspección de una petición por el WAF | ~2 µs |
| Búsqueda en un conjunto de 10 000 rangos de IP | ~3,4 ns |

Todas las firmas del WAF se compilan en un único autómata Aho-Corasick, por lo que el coste no crece con el número de reglas. El crate usa `#![forbid(unsafe_code)]`, y los guards con estado guardan sus datos en mapas fragmentados y acotados, con hashing de clave aleatoria: las claves controladas por un atacante no pueden agotar la memoria ni provocar ataques de inundación de hash (HashDoS).

## Compatibilidad

`Shield` es un middleware de Vitesse e implementa `tower::Layer`, así que encaja en cualquier stack que acepte capas tower:

| Stack | Integración |
|---|---|
| Vitesse | `app.middleware(shield)`; el shield lee por sí mismo la dirección de cada conexión |
| hyper 1 | Envuelve tu servicio con `tower::ServiceBuilder` e inserta `PeerAddr` |
| tonic | `Server::builder().layer(shield)` |
| tower | `ServiceBuilder::new().layer(shield)` |

Cada guard es también un middleware independiente, por ejemplo `app.middleware(Shield::from(Waf::new()))`. Continúa con la [instalación](/docs/installation) y, después, con el [inicio rápido](/docs/quick-start).
