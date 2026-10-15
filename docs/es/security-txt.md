---
title: security.txt
summary: Publica un security.txt conforme a la RFC 9116 para que los investigadores puedan notificar vulnerabilidades, y rechaza contactos ausentes, caducidades incorrectas, enlaces http e inyección de campos.
category: integrity
order: 7
---

`/.well-known/security.txt` (RFC 9116) indica a los investigadores de seguridad cómo notificar una vulnerabilidad. `SecurityTxt` construye un archivo válido y rechaza los errores habituales.

## Amenazas mitigadas

- **Vulnerabilidades no notificadas**: un investigador que no encuentra un contacto publica el fallo o lo vende.
- **Archivos caducados**: `Expires` es obligatorio, debe estar en el futuro y a menos de un año (regenérelo en cada despliegue con `expires_in`).
- **Contactos suplantados**: se rechazan los enlaces `http://`, y los valores no pueden contener saltos de línea que inyectarían campos.

## Inicio rápido

```rust
use std::time::Duration;
use securite::security_txt::{SecurityTxt, CONTENT_TYPE, PATH};

let txt = SecurityTxt::new()
    .contact("mailto:security@example.com")
    .contact("https://example.com/security")
    .expires_in(Duration::from_secs(180 * 24 * 3600))
    .encryption("https://example.com/pgp-key.txt")
    .preferred_languages(["es", "en", "fr"])
    .canonical("https://example.com/.well-known/security.txt")
    .policy("https://example.com/disclosure-policy")
    .render()?; // Err(MissingContact / MissingExpires / BadExpires / InvalidValue)

app.get(PATH, move |_req: Request| {
    let body = txt.clone();
    async move { ([("content-type", CONTENT_TYPE)], body) }
});
```

## Campos

| Método | Campo | Valores permitidos |
|---|---|---|
| `.contact(uri)` | `Contact` (obligatorio, repetible) | `mailto:`, `tel:`, `https://` |
| `.expires_in(d)` / `.expires_at(t)` | `Expires` (obligatorio) | futuro, un año como máximo |
| `.encryption(uri)` | `Encryption` | `https://`, `openpgp4fpr:`, `dns:` |
| `.acknowledgments(uri)` | `Acknowledgments` | `https://` |
| `.preferred_languages([...])` | `Preferred-Languages` | etiquetas de idioma |
| `.canonical(uri)` | `Canonical` | `https://` |
| `.policy(uri)` | `Policy` | `https://` |
| `.hiring(uri)` | `Hiring` | `https://` |
| `.csaf(uri)` | `CSAF` | `https://` |

## Trampas y consejos

- Vigile la dirección de contacto: una notificación sin respuesta es peor que ninguna.
- Firmar el archivo con OpenPGP (firma en claro) es opcional; hágalo fuera de la aplicación si lo necesita.
- Tenga en cuenta el [filtro de Host](/docs/host-filter): el archivo debe ser accesible en cada nombre de host público.

## Páginas relacionadas

- [Cabeceras de seguridad](/docs/security-headers)
- [URL y tokens firmados](/docs/signed-urls)
