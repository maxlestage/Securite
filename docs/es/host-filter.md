---
title: Filtro de hosts
summary: Una lista de permitidos para la cabecera Host que detiene el envenenamiento de la cabecera Host y los ataques de DNS rebinding.
category: access
order: 2
---

`HostFilter` solo deja pasar las peticiones dirigidas a sus propios nombres de dominio. Todo lo demás (un `Host` falsificado, una dirección IP sin más, un dominio que simplemente apunta a su servidor) se rechaza antes de llegar a su código.

## La amenaza

La cabecera `Host` la elige el cliente y, aun así, muchas aplicaciones confían en ella:

- **Envenenamiento de enlaces de restablecimiento**: una aplicación que construye URL absolutas a partir de `Host` («haga clic aquí para restablecer su contraseña») envía a sus víctimas un enlace al dominio del atacante, junto con un token de restablecimiento válido.
- **Envenenamiento de caché web**: una caché que no incluye `Host` en su clave puede almacenar una respuesta generada para un host falsificado y servírsela a todo el mundo.
- **DNS rebinding**: una página maliciosa hace que su propio dominio apunte a `127.0.0.1` o a una dirección interna. El navegador de la víctima habla entonces con su servicio local o interno como si fuera del mismo origen que la página del atacante, enviando `Host: attacker.example`.
- **Escáneres y enrutamiento erróneo**: los bots que recorren rangos de direcciones envían la IP directamente como host.

OWASP recoge la inyección en la cabecera Host en su Web Security Testing Guide (WSTG-INPV-17); suele encuadrarse en la categoría A05 Security Misconfiguration.

## Cómo funciona

El guard se ejecuta con prioridad 70, después de las comprobaciones de higiene del protocolo y justo antes de la redirección HTTPS (75). Toma el host de la URI de la petición (peticiones en forma absoluta y `:authority` de HTTP/2) o, en su defecto, de la cabecera `Host`. Antes de comparar, el valor se pasa a minúsculas, se le quita el puerto y un posible punto final. Cada regla es un nombre exacto o un patrón `*.example.com`.

- Host permitido: la petición sigue su curso.
- Host desconocido: `421 Misdirected Request`, código `invalid_host`; el valor rechazado se guarda en los detalles del evento y nunca se devuelve al cliente.
- Sin host: `400 Bad Request`, código `missing_host`.

Las peticiones con varias cabeceras `Host` ya las rechaza el guard `Hygiene` de los presets.

| Regla | Coincide con | No coincide con |
|---|---|---|
| `example.com` | `example.com`, `EXAMPLE.com:443`, `example.com.` | `www.example.com`, `example.com.evil.com` |
| `*.example.com` | `api.example.com`, `a.b.example.com` | `example.com`, `evilexample.com` |
| `localhost` (con `allow_localhost`) | `localhost:3000` | `localhost.example.com` |

## Inicio rápido

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let shield = Shield::builder()
        .guard(HostFilter::new(["example.com", "*.example.com"]))
        .build();

    let mut app = App::new();
    app.middleware(shield);
    app.get("/", |_req: Request| async { "hello" });
    app
}
```

El guard se llama `host`. Ningún preset lo incluye, porque solo usted conoce sus dominios.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `HostFilter::new(hosts)` | — | Nombres de host permitidos, sin tener en cuenta el puerto. `*.example.com` abarca todos los subdominios, pero no `example.com`. |
| `allow(hosts)` | — | Añade más hosts permitidos. |
| `allow_localhost()` | inactivo | Acepta también `localhost`, `127.0.0.1` y `[::1]`. |
| `monitor()` | bloqueo | Registra y notifica las infracciones sin bloquear. |
| `is_allowed(&str)` | — | Indica si un host, con o sin puerto, está permitido. |

## Ejemplos

### Producción y desarrollo local

```rust
use securite::prelude::*;

pub fn hosts(dev: bool) -> HostFilter {
    let hosts = HostFilter::new(["example.com", "*.example.com"]);
    if dev { hosts.allow_localhost() } else { hosts }
}
```

### Una herramienta local protegida contra DNS rebinding

Los paneles de desarrollo, los back-ends de aplicaciones de escritorio y las herramientas de administración que escuchan en `127.0.0.1` son el objetivo favorito del DNS rebinding:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn local_admin() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(HostFilter::new(["localhost", "127.0.0.1", "[::1]"])));
    app.get("/", |_req: Request| async { "local admin" });
    app
}
```

### Despliegue progresivo en modo monitor

Antes de bloquear, averigüe qué hosts usa realmente su tráfico:

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    Shield::builder()
        .guard(HostFilter::new(["example.com", "*.example.com"]).monitor())
        .on_event(|e| {
            if e.guard == "host" {
                eprintln!("unexpected host on {}: {:?}", e.path, e.details);
            }
        })
        .build()
}
```

### Comprobaciones de salud dirigidas por IP

Los balanceadores de carga y las sondas de Kubernetes suelen usar la IP de la instancia como host. En Vitesse, los middlewares de un router solo se aplican a sus propias rutas: mantenga la sonda fuera del router que lleva el filtro:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    // El sitio, tras el filtro de hosts: los middlewares de un router solo se aplican a sus rutas.
    let mut site = Router::new();
    site.middleware(Shield::builder().guard(HostFilter::new(["example.com"])).build());
    site.get("/", |_req: Request| async { "hello" });

    let mut app = App::new();
    // Not behind the shield: probes using the pod IP as host still succeed.
    app.get("/healthz", |_req: Request| async { "ok" });
    app.mount("/", site);
    app
}
```

## Uso como guard independiente

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(HostFilter::new(["example.com"]))); // outermost: runs first
    app.middleware(Shield::from(SecurityHeaders::strict()));
    app.get("/", |_req: Request| async { "ok" });
    app
}
```

## Errores comunes y consejos

> **Consejo:** dentro de un mismo `Shield`, `HostFilter` se ejecuta antes que [HttpsRedirect](/docs/https-redirect), que construye su `Location` a partir de la cabecera `Host`: añada ambos al mismo shield y solo se redirigirán hosts validados. Con capas independientes, coloque `HostFilter` por fuera de `HttpsRedirect`.

- Un comodín no incluye el dominio raíz: incluya tanto `example.com` como `*.example.com`.
- Las reglas ignoran el puerto; el filtro no distingue `example.com:8080` de `example.com`.
- `X-Forwarded-Host` no se comprueba. Si su framework construye URL a partir de esa cabecera, asegúrese de que su proxy la sobrescribe.
- En cualquier caso, no construya nunca URL absolutas a partir de las cabeceras de la petición; use una URL base configurada. El filtro es una red de seguridad, no un sustituto.
- Las comprobaciones de salud por IP reciben un `421`: déjelas fuera como se muestra arriba o permita la dirección de forma explícita.

> **Consejo:** `421 Misdirected Request` es el estado que esperan los clientes HTTP/2 cuando una conexión se reutiliza para un host que no atiende; los clientes bien implementados reintentan con una conexión nueva.

## Páginas relacionadas

- [Redirección a HTTPS](/docs/https-redirect)
- [Protección CSRF](/docs/csrf)
- [CORS](/docs/cors)
- [Cabeceras de seguridad](/docs/security-headers)
- [Higiene HTTP](/docs/hygiene)
- [Modo monitor](/docs/monitor-mode)
