---
title: Firmas de webhooks
summary: Verifica en tiempo constante las firmas HMAC-SHA256 de GitHub, Stripe, Slack, Shopify o de sus propios emisores, con protección contra ataques de repetición basada en marcas de tiempo.
category: integrity
order: 2
---

Un endpoint de webhook es una URL pública que desencadena acciones de negocio: marcar una factura como pagada, desplegar un commit, aprovisionar una cuenta. Cualquiera que descubra la URL puede enviar un evento falsificado, por eso todo proveedor serio firma sus cargas con un secreto compartido. `SignatureLayer` verifica esas firmas antes de que se ejecute su handler y le entrega exactamente el cuerpo que se firmó.

## Amenazas que mitiga

- **A08:2021 Software and Data Integrity Failures**: cargas de webhook falsificadas o alteradas aceptadas como auténticas (CWE-345, verificación insuficiente de la autenticidad de los datos).
- **A07:2021 Identification and Authentication Failures**: la firma demuestra que el emisor conoce el secreto compartido.
- **Ataques de repetición (CWE-294)**: con los esquemas con marca de tiempo, una petición capturada se rechaza en cuanto supera la ventana de tolerancia.

## Funcionamiento

A diferencia de los demás guards, la verificación de firmas necesita el cuerpo de la petición, así que es una capa de tower dedicada y no un guard del escudo. Para cada petición cuya ruta coincide:

1. El cuerpo se almacena en un búfer, hasta `max_body` (1 MiB por defecto). Los cuerpos más grandes se rechazan con `413`, código `body_too_large`.
2. Se calcula el HMAC-SHA256 del contenido firmado y se compara en tiempo constante con la firma recibida.
3. En los esquemas con marca de tiempo, esta debe estar dentro de la tolerancia (5 minutos por defecto, en ambos sentidos).
4. Cualquier fallo responde `401` con el código `invalid_signature` y el mensaje `Invalid webhook signature.` El motivo concreto (ausente, mal formada, caducada, no coincide) se registra bajo el target de tracing `securite` con `guard="signature"` y nunca se envía al cliente.
5. Si todo es correcto, la petición se reconstruye con un cuerpo idéntico y se pasa a su handler.

## Proveedores compatibles

| Constructor | Cabeceras | Contenido firmado | Protección contra repetición |
|---|---|---|---|
| `SignatureVerifier::github(secret)` | `X-Hub-Signature-256: sha256=<hex>` | cuerpo | no |
| `SignatureVerifier::stripe(secret)` | `Stripe-Signature: t=<ts>,v1=<hex>` | `<ts>.<body>` | sí |
| `SignatureVerifier::slack(secret)` | `X-Slack-Signature: v0=<hex>` y `X-Slack-Request-Timestamp` | `v0:<ts>:<body>` | sí |
| `SignatureVerifier::shopify(secret)` | `X-Shopify-Hmac-Sha256: <base64>` | cuerpo | no |
| `SignatureVerifier::hmac_hex(secret, header, prefix)` | `<header>: <prefix><hex>` | cuerpo | no |
| `SignatureVerifier::hmac_base64(secret, header, prefix)` | `<header>: <prefix><base64>` | cuerpo | no |
| `SignatureVerifier::hmac_hex_timestamped(secret, header, ts_header, prefix)` | `<header>: <prefix><hex>` y `<ts_header>: <segundos Unix>` | `<ts>.<body>` | sí |

Con Stripe se prueba cada entrada `v1` de la cabecera, lo que sigue funcionando mientras rota el secreto de su endpoint. Los secretos aceptan cualquier tipo que implemente `AsRef<[u8]>` (`String`, `&str`, `Vec<u8>`…).

## Inicio rápido

```rust
use axum::{routing::post, Router};
use securite::prelude::*;

let secret = std::env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET must be set");

let app: Router = Router::new()
    .route(
        "/webhooks/github",
        post(|body: String| async move {
            // Only reached when the signature is valid.
            format!("received {} bytes", body.len())
        }),
    )
    .layer(SignatureLayer::new(SignatureVerifier::github(secret)).paths(["/webhooks/github"]))
    .layer(Shield::recommended());
```

El escudo se añade el último, así que se ejecuta el primero: la limitación de peticiones, el filtrado por IP y las comprobaciones de cabeceras ocurren antes de almacenar ningún cuerpo.

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `SignatureLayer::new(verifier)` | todas las rutas | Crea la capa. |
| `.paths(prefixes)` | todas las peticiones | Solo verifica estos prefijos de ruta (comparados por segmentos); las demás peticiones pasan sin cambios. |
| `SignatureVerifier::tolerance(Duration)` | 5 minutos | Antigüedad máxima o desfase de reloj tolerado en los esquemas con marca de tiempo. |
| `SignatureVerifier::max_body(usize)` | 1 MiB | Tamaño máximo del cuerpo almacenado para la verificación. |
| `SignatureVerifier::sign(&[u8])` | — | HMAC-SHA256 en hexadecimal de una carga, para pruebas y webhooks salientes. |
| `SignatureVerifier::verify(&HeaderMap, &[u8])` | — | Verificación manual; devuelve `Result<(), SignatureError>`. |

`SignatureError` (en `securite::signature`) tiene cuatro variantes: `Missing`, `Malformed`, `Expired` y `Mismatch`.

## Varios proveedores

Apile una capa por proveedor, cada una limitada a su propia ruta:

```rust
use std::time::Duration;

use axum::{routing::post, Router};
use securite::prelude::*;

let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));

let app: Router = Router::new()
    .route("/webhooks/github", post(|body: String| async move { body.len().to_string() }))
    .route("/webhooks/stripe", post(|body: String| async move { body.len().to_string() }))
    .route("/webhooks/slack", post(|body: String| async move { body.len().to_string() }))
    .layer(
        SignatureLayer::new(SignatureVerifier::github(env("GITHUB_WEBHOOK_SECRET")))
            .paths(["/webhooks/github"]),
    )
    .layer(
        SignatureLayer::new(
            SignatureVerifier::stripe(env("STRIPE_WEBHOOK_SECRET"))
                .tolerance(Duration::from_secs(120))
                .max_body(256 * 1024),
        )
        .paths(["/webhooks/stripe"]),
    )
    .layer(
        SignatureLayer::new(SignatureVerifier::slack(env("SLACK_SIGNING_SECRET")))
            .paths(["/webhooks/slack"]),
    )
    .layer(Shield::recommended());
```

## Requisito sobre el cuerpo

La capa reconstruye la petición a partir de los bytes almacenados, así que el tipo del cuerpo de la petición debe implementar `http_body::Body` y `From<Bytes>`. `axum::body::Body` lo hace, por lo que la capa funciona directamente con axum. Con un servidor hyper sin más, `Incoming` no lo implementa: conviértalo antes, por ejemplo con `axum::body::Body::new(incoming)`.

## Pruebas con `sign()`

`sign()` calcula el HMAC en hexadecimal exactamente de los bytes que recibe, lo que facilita construir peticiones de prueba firmadas:

```rust
use axum::{body::Body, http::{Request, StatusCode}, routing::post, Router};
use securite::prelude::*;
use tower::ServiceExt;

#[tokio::test]
async fn accepts_signed_github_payload() {
    let verifier = SignatureVerifier::github("test-secret");
    let payload = r#"{"action":"opened"}"#;
    let signature = format!("sha256={}", verifier.sign(payload.as_bytes()));

    let app: Router = Router::new()
        .route("/webhooks/github", post(|body: String| async move { body }))
        .layer(SignatureLayer::new(verifier).paths(["/webhooks/github"]));

    let request = Request::post("/webhooks/github")
        .header("x-hub-signature-256", signature)
        .body(Body::from(payload))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
```

En los esquemas con marca de tiempo, firme usted mismo el contenido compuesto:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use securite::prelude::*;

let verifier = SignatureVerifier::stripe("whsec_test");
let payload = r#"{"type":"invoice.paid"}"#;
let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

let v1 = verifier.sign(format!("{ts}.{payload}").as_bytes());
let stripe_signature = format!("t={ts},v1={v1}");
// Slack: sign format!("v0:{ts}:{payload}") and send "v0=<hex>".
```

## Firmar sus propios webhooks salientes

El mismo tipo firma los webhooks que usted envía. Comparta el secreto con sus clientes e indíqueles el constructor correspondiente:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use securite::prelude::*;

let secret = std::env::var("OUTGOING_WEBHOOK_SECRET").expect("OUTGOING_WEBHOOK_SECRET must be set");
let signer = SignatureVerifier::hmac_hex_timestamped(secret, "x-acme-signature", "x-acme-timestamp", "sha256=");

let body = r#"{"event":"order.shipped","order_id":"ord_8812"}"#;
let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
let signature = format!("sha256={}", signer.sign(format!("{ts}.{body}").as_bytes()));
// Send `body` with the headers x-acme-timestamp: <ts> and x-acme-signature: <signature>.
```

## Protección contra la repetición

- Stripe, Slack y `hmac_hex_timestamped` rechazan las marcas de tiempo fuera de la ventana de tolerancia, tanto en el pasado como en el futuro. Una petición capturada no puede repetirse horas después.
- Dentro de la ventana, la repetición sigue siendo posible. Haga que sus handlers sean idempotentes y elimine duplicados con el identificador de evento del proveedor: el `id` del evento de Stripe, `X-GitHub-Delivery`, `X-Shopify-Webhook-Id`.
- GitHub, Shopify, `hmac_hex` y `hmac_base64` no incluyen marca de tiempo: solo la eliminación de duplicados le protege frente a la repetición.
- Mantenga sus servidores sincronizados con NTP. Un desfase de reloj importante convierte cada entrega legítima en un error `Expired`.

## Errores comunes y consejos

- No coloque una capa que reescriba el cuerpo (descompresión, transcodificación) entre el proveedor y `SignatureLayer`: la firma cubre exactamente los bytes enviados.
- Un secreto incorrecto convierte cada entrega en un `401`, que `AutoBan` cuenta como penalización contra las direcciones IP del proveedor. Excluya las rutas de webhooks con `AutoBan::new().ignore_paths(["/webhooks"])`.
- `ContentTypeGuard::json()`, que usa el preset `api`, rechaza las cargas codificadas como formulario de los comandos de barra de Slack: añada `.skip("/webhooks/slack")`. En modo token, `Csrf` debe eximir las rutas de webhooks con `.exempt("/webhooks")`.
- Los rechazos de firma no pasan por el hook `on_event` ni por las estadísticas del escudo, y siempre se devuelven en formato problem+json. Vigile el target de tracing `securite` para detectar errores de configuración.
- Un verificador contiene un solo secreto. Para rotar sus propios secretos, acepte ambos durante la transición, por ejemplo llamando a `verify` manualmente con dos verificadores.
- `sign()` devuelve hexadecimal. Para probar Shopify o `hmac_base64`, codifique usted mismo en base64 los bytes en bruto del MAC.

## Páginas relacionadas

- [Autenticación](/docs/auth)
- [Bloqueo automático](/docs/auto-ban)
- [Lista de Content-Type permitidos](/docs/content-type)
- [Protección CSRF](/docs/csrf)
- [Límite de tamaño del cuerpo](/docs/body-limit)
- [Identificadores de petición](/docs/request-id)
