---
title: IP del cliente
summary: Cómo encuentra el shield la dirección real del cliente detrás de proxies y CDN, por qué lee X-Forwarded-For desde la derecha y cómo usar esa dirección en tus handlers.
category: start
order: 5
---

La limitación de tasa, los límites de concurrencia, el baneo automático, el filtrado de IP y el registro de auditoría dependen de saber quién es el cliente. Equivocarse sale caro en ambos sentidos: si confías en la cabecera equivocada, un atacante elige su propia IP para esquivar los baneos; si ignoras el proxy, todos tus visitantes comparten su dirección y, con ella, su límite de tasa.

## Fuentes

El shield resuelve la dirección una vez por petición, según la `ClientIpSource` configurada con `ShieldBuilder::client_ip`:

| Variante | Lee | Úsala cuando |
|---|---|---|
| `Peer` (por defecto) | La dirección del peer TCP | La aplicación está expuesta directamente, sin proxy |
| `XForwardedFor { trusted_hops }` | La entrada más a la derecha de `X-Forwarded-For`, saltando `trusted_hops` proxies adicionales | Tus proxies añaden entradas a `X-Forwarded-For` |
| `Forwarded { trusted_hops }` | El `for=` más a la derecha de la cabecera `Forwarded` (RFC 7239) | Tus proxies emiten la cabecera estándar |
| `Header(name)` | Una cabecera con una sola IP, fijada por tu frontal | CDN como Cloudflare o Akamai |

### Atajos

| Atajo | Equivalente | Plataforma |
|---|---|---|
| `ClientIpSource::heroku()` | `XForwardedFor { trusted_hops: 0 }` | Heroku, Render, AWS ALB, un único Nginx |
| `ClientIpSource::cloudflare()` | `Header("cf-connecting-ip")` | Cloudflare |
| `ClientIpSource::fly()` | `Header("fly-client-ip")` | Fly.io |
| `ClientIpSource::x_real_ip()` | `Header("x-real-ip")` | Nginx con `proxy_set_header X-Real-IP $remote_addr;` |

```rust
use securite::prelude::*;

// Heroku router, or any single proxy appending to X-Forwarded-For.
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();

// A CDN and a load balancer, both appending to X-Forwarded-For.
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::XForwardedFor { trusted_hops: 1 })
    .build();

// Akamai, or any edge that sets a single-IP header.
// (securite::http reexporta la crate http.)
let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::Header(
        securite::http::HeaderName::from_static("true-client-ip"),
    ))
    .build();
```

## Por qué la entrada más a la derecha de X-Forwarded-For

Cada proxy *añade* la dirección desde la que ha recibido la conexión. Todo lo que queda a la izquierda ya estaba en la petición cuando llegó a tu proxy y, por tanto, puede haberlo escrito el cliente. Supongamos que un visitante con la dirección `203.0.113.50` envía una cabecera falsificada:

```text
X-Forwarded-For: 6.6.6.6                  ← sent by the client (forged)
X-Forwarded-For: 6.6.6.6, 203.0.113.50    ← after your proxy appended the peer
```

El valor más a la izquierda, `6.6.6.6`, lo controla el atacante; el más a la derecha, `203.0.113.50`, lo ha escrito una infraestructura de confianza. Por eso `ClientIpSource::heroku()` resuelve `203.0.113.50`. Las bibliotecas que toman el valor más a la izquierda permiten a cualquiera esquivar baneos y límites de tasa con una simple cabecera.

### trusted_hops

En una cadena de varios proxies, cada uno añade una entrada. `trusted_hops` es el número de proxies de confianza *adicionales* que hay que saltar empezando por la derecha:

| `X-Forwarded-For` | `trusted_hops` | Dirección resuelta |
|---|---|---|
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `0` | `5.6.7.8` |
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `1` | `1.2.3.4` |
| `6.6.6.6, 1.2.3.4, 5.6.7.8` | `5` | Demasiado pocas entradas: peer TCP |

Varias líneas de cabecera cuentan como una única lista separada por comas. Las entradas pueden incluir un puerto (`1.2.3.4:5678`, `[2001:db8::1]:443`), y las direcciones IPv6 mapeadas a IPv4, como `::ffff:1.2.3.4`, se normalizan a IPv4. `Forwarded` funciona igual: a partir de `for=192.0.2.43, for="[2001:db8:cafe::17]:4711"`, `Forwarded { trusted_hops: 0 }` resuelve `2001:db8:cafe::17`.

## Riesgos de suplantación

> **Atención:** Confía en una cabecera de reenvío solo si tu aplicación es accesible **exclusivamente** a través del proxy que la fija. Si también se puede llegar al origen directamente (una IP pública, una URL `*.herokuapp.com` que se salta tu CDN), un atacante puede enviar la cabecera él mismo y elegir cualquier dirección. Blinda el origen con un cortafuegos, una red privada o la autenticación de origen que ofrezca tu CDN.

Las cabeceras de una sola IP, como `CF-Connecting-IP`, son las más expuestas: su valor se toma tal cual, así que solo son seguras si todas las peticiones pasan por el frontal que las sobrescribe.

### Proxies de confianza

Cuando el origen no puede blindarse por completo, indica al shield en qué redes viven tus proxies. Una cabecera de reenvío solo se cree entonces si el par TCP pertenece a una de ellas, como el `trust proxy` de Express, el `TrustProxies` de Laravel o las recomendaciones de Django sobre `X-Forwarded-For`:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::XForwardedFor { trusted_hops: 0 })
    // Tu balanceador de carga, tu ingress o los rangos de tu CDN.
    .trusted_proxies(["10.0.0.0/8", "fd00::/8"])
    .build();
```

Con un conjunto de confianza:

- una petición desde una dirección **fuera** del conjunto se resuelve a su par TCP, lleve las cabeceras que lleve: un cliente que llega directamente al origen no puede suplantar su dirección;
- `X-Forwarded-For` y `Forwarded` se leen desde la derecha **saltando cada proxy de confianza**, y la primera dirección no fiable es el cliente (`trusted_hops` se ignora entonces: el conjunto describe la cadena). Si todos los saltos son de confianza, se usa el de más a la izquierda; una entrada ilegible detiene el recorrido en el último salto de confianza;
- una cabecera de una sola IP (`CF-Connecting-IP`, `X-Real-IP` …) solo se usa si el par es de confianza;
- sin una dirección de par conocida, no se cree ninguna cabecera.

| Par | `X-Forwarded-For` | Confianza | Resultado |
|---|---|---|---|
| `10.0.0.1` | `6.6.6.6, 203.0.113.9, 10.1.2.3` | `10.0.0.0/8` | `203.0.113.9` |
| `198.51.100.7` | `1.2.3.4` | `10.0.0.0/8` | `198.51.100.7` (cabecera ignorada) |
| `10.0.0.1` | `10.1.1.1, 10.2.2.2` | `10.0.0.0/8` | `10.1.1.1` |

`try_trusted_proxies` devuelve un error en lugar de entrar en pánico, para redes leídas de la configuración, y `ClientIpSource::resolve_trusted` expone la misma lógica a tu propio código.

## Agrupación IPv6

Los proveedores de Internet suelen asignar a cada cliente un `/64` IPv6 completo, es decir, 2^64 direcciones. Contar cada dirección por separado permitiría a un solo atacante rotar entre miles de millones de identidades. Por eso el limitador de tasa, el límite de concurrencia y el baneo automático agrupan a los clientes IPv6 por `/64`; las direcciones IPv4 se usan tal cual. El limitador de tasa permite cambiar el prefijo:

```rust
use securite::prelude::*;

// Some ISPs delegate a /56 per customer.
let limiter = RateLimit::per_second(20).burst(100).ipv6_prefix(56);
```

La función `securite::ip::mask` aplica la misma agrupación en tu propio código.

## Usar la dirección en los handlers

El shield inserta una extensión `ClientIp` en cada petición cuya dirección ha resuelto. Contiene la dirección completa, no el grupo `/64`:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn whoami(req: Request) -> String {
    match req.get::<ClientIp>() {
        Some(ClientIp(ip)) => format!("your address: {ip}"),
        None => "unknown address".to_owned(),
    }
}

let mut app = App::new();
app.middleware(Shield::recommended());
app.get("/whoami", whoami);
```

En un [guard personalizado](/docs/custom-guards), léela con `ctx.client_ip()`.

## Shields anidados y guards independientes

Cuando una petición ya lleva una extensión `ClientIp`, puesta por un shield exterior, el shield reutiliza esa dirección en lugar de resolverla de nuevo. Así, los shields interiores y los guards independientes coinciden con el más externo. Para usar guards independientes detrás de un proxy, añade como primer middleware un shield sin guards que solo resuelva la dirección:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
// El más externo (primer middleware añadido): resuelve la IP del cliente una vez,
// y los middlewares añadidos después reutilizan su `ClientIp`.
app.middleware(Shield::builder().client_ip(ClientIpSource::heroku()).build());
app.middleware(Shield::from(AutoBan::new()));
app.middleware(Shield::from(RateLimit::per_minute(120)));
app.get("/", |_req: Request| async { "hello" });
```

> **Atención:** solo cuenta el ajuste `client_ip` del shield más externo. Si conserva la fuente por defecto `Peer`, todos los shields interiores reutilizan la dirección del proxy que este resolvió, sea cual sea su propio ajuste: configura la fuente en el shield más externo.

## Alternativas de respaldo

Cuando la cabecera configurada falta, está mal formada o tiene muy pocas entradas, el shield recurre a la dirección del peer TCP. Esta es la dirección de la conexión, que Vitesse entrega al shield; en un servicio tower se busca en una extensión `PeerAddr` y después en una extensión `SocketAddr` sin envolver.

Cuando no se encuentra ninguna dirección (un servicio tower sin `PeerAddr`), el shield registra una única advertencia (target `securite`) que recomienda una extensión `PeerAddr`, y los guards se degradan así:

| Guard | Comportamiento sin IP de cliente |
|---|---|
| `RateLimit` (por IP) | Todas esas peticiones comparten un único cubo global |
| `AutoBan`, `ConcurrencyLimit` | Se omiten |
| `IpFilter` | Deniega si hay una lista de permitidos configurada; si no, deja pasar |
| Eventos de seguridad | `client_ip` vale `None` |

> **Consejo:** Añade el handler `whoami` anterior durante el despliegue y llámalo a través de tu infraestructura real. Si muestra la dirección de un proxy o `unknown address`, corrige la fuente antes de pasar a producción.
