---
title: Informes CSP
summary: Recoge los informes de violación de la Content-Security-Policy en los dos formatos de los navegadores, con Reporting-Endpoints, límites de tamaño, campos protegidos contra la inyección en logs y filtrado del ruido de las extensiones.
category: browser
order: 5
---

Una Content-Security-Policy solo se despliega con tranquilidad si se ve lo que bloquea. Los navegadores envían un informe por cada violación, al `report-uri` de la política (formato `application/csp-report`) o a un punto `report-to` declarado por `Reporting-Endpoints` (formato `application/reports+json`). `parse_csp_reports` lee ambos (feature `reports`).

```toml
securite = { version = "0.2", features = ["reports"] }
```

## Amenazas mitigadas

- **A05:2021 Configuración de seguridad incorrecta**: una CSP que rompe el sitio acaba desactivada; los informes permiten corregirla primero en modo report-only.
- **Detección de XSS**: los scripts inyectados aparecen como violaciones en producción.
- **Un punto de entrada hostil**: cualquiera puede enviar datos. Se rechazan los cuerpos de más de 64 KiB y más de 100 informes, cada campo se recorta a 1024 caracteres y se le quitan los caracteres de control (sin inyección en los logs).

## Inicio rápido

```rust
use securite::headers::{ContentSecurityPolicy, SecurityHeaders};

let headers = SecurityHeaders::new()
    .reporting_endpoint("csp", "https://example.com/csp-reports")
    .content_security_policy(
        ContentSecurityPolicy::strict()
            .report_to(["csp"])            // API Reporting (Chrome, Edge, Safari)
            .report_uri(["/csp-reports"])  // formato antiguo (Firefox)
            .report_only(),                // observar primero, aplicar después
    );
```

El punto de entrada:

```rust
use securite::report::{parse_csp_reports, ReportError};

app.post("/csp-reports", |req: Request| async move {
    let ct = req.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_owned);
    match parse_csp_reports(ct.as_deref(), &req.body_bytes()) {
        Ok(reports) => {
            for v in reports.iter().filter(|v| !v.is_extension_noise()) {
                v.log(); // aviso tracing, destino `securite::csp`
            }
            StatusCode::NO_CONTENT
        }
        Err(ReportError::TooLarge) => StatusCode::PAYLOAD_TOO_LARGE,
        Err(ReportError::UnsupportedMediaType) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Err(_) => StatusCode::BAD_REQUEST,
    }
});
```

## Qué contiene una violación

`CspViolation` tiene `document_uri`, `blocked_uri`, `effective_directive`, `disposition` (`enforce` / `report`), `source_file`, `line`, `column`, `sample` (con `'report-sample'`), `referrer` y `status_code`, todos opcionales.

`is_extension_noise()` detecta las violaciones causadas por extensiones del navegador (`chrome-extension:`, `moz-extension:` …), que suelen ser la mayoría de los informes.

## Trampas y consejos

- Ponga una [limitación de peticiones](/docs/rate-limit) y un [límite de cuerpo](/docs/body-limit) en el punto de entrada, y exclúyalo de la [protección CSRF](/docs/csrf) (los navegadores envían sin token).
- `reporting_endpoint` solo acepta URL `https://` (y `http://localhost`): los navegadores ignoran las demás.
- Los informes son indicios, no pruebas: pueden falsificarse.

## Páginas relacionadas

- [Cabeceras de seguridad y CSP](/docs/security-headers)
- [Modo observación](/docs/monitor-mode)
