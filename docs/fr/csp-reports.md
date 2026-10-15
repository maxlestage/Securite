---
title: Rapports CSP
summary: Collecte les rapports de violation de la Content-Security-Policy dans les deux formats des navigateurs, avec Reporting-Endpoints, des limites de taille, des champs protégés de l'injection dans les logs et le filtrage du bruit des extensions.
category: browser
order: 5
---

Une Content-Security-Policy ne se déploie sereinement que si l'on voit ce qu'elle bloque. Les navigateurs envoient un rapport pour chaque violation, au `report-uri` de la politique (format `application/csp-report`) ou à un point `report-to` déclaré par `Reporting-Endpoints` (format `application/reports+json`). `parse_csp_reports` lit les deux (feature `reports`).

```toml
securite = { version = "0.2", features = ["reports"] }
```

## Menaces couvertes

- **A05:2021 Mauvaise configuration de sécurité** : une CSP qui casse le site finit désactivée ; les rapports permettent de la corriger d'abord en mode report-only.
- **Détection de XSS** : les scripts injectés apparaissent comme des violations en production.
- **Un point d'entrée hostile** : n'importe qui peut y poster. Les corps de plus de 64 Kio et au-delà de 100 rapports sont refusés, chaque champ est tronqué à 1024 caractères et débarrassé des caractères de contrôle (pas d'injection dans les logs).

## Démarrage rapide

```rust
use securite::headers::{ContentSecurityPolicy, SecurityHeaders};

let headers = SecurityHeaders::new()
    .reporting_endpoint("csp", "https://example.com/csp-reports")
    .content_security_policy(
        ContentSecurityPolicy::strict()
            .report_to(["csp"])            // API Reporting (Chrome, Edge, Safari)
            .report_uri(["/csp-reports"])  // ancien format (Firefox)
            .report_only(),                // observer d'abord, appliquer ensuite
    );
```

Le point d'entrée :

```rust
use securite::report::{parse_csp_reports, ReportError};

app.post("/csp-reports", |req: Request| async move {
    let ct = req.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_owned);
    match parse_csp_reports(ct.as_deref(), &req.body_bytes()) {
        Ok(reports) => {
            for v in reports.iter().filter(|v| !v.is_extension_noise()) {
                v.log(); // avertissement tracing, cible `securite::csp`
            }
            StatusCode::NO_CONTENT
        }
        Err(ReportError::TooLarge) => StatusCode::PAYLOAD_TOO_LARGE,
        Err(ReportError::UnsupportedMediaType) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Err(_) => StatusCode::BAD_REQUEST,
    }
});
```

## Ce que contient une violation

`CspViolation` a `document_uri`, `blocked_uri`, `effective_directive`, `disposition` (`enforce` / `report`), `source_file`, `line`, `column`, `sample` (avec `'report-sample'`), `referrer` et `status_code`, tous optionnels.

`is_extension_noise()` repère les violations dues aux extensions du navigateur (`chrome-extension:`, `moz-extension:` …), qui forment souvent l'essentiel des rapports.

## Pièges et conseils

- Mettez une [limitation de débit](/docs/rate-limit) et une [limite de corps](/docs/body-limit) sur le point d'entrée, et excluez-le de la [protection CSRF](/docs/csrf) (les navigateurs y postent sans jeton).
- `reporting_endpoint` n'accepte que des URL `https://` (et `http://localhost`) : les navigateurs ignorent les autres.
- Les rapports sont des indices, pas des preuves : ils peuvent être forgés.

## Pages liées

- [En-têtes de sécurité et CSP](/docs/security-headers)
- [Mode observation](/docs/monitor-mode)
