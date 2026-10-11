---
title: Desplegar en GitHub Pages
summary: Publique el sitio gratis en GitHub Pages con un workflow de GitHub Actions, configurado una vez desde el móvil y actualizado en cada fusión en master.
category: deploy
order: 2
---

`.github/workflows/pages.yml` construye el sitio y publica una copia estática en GitHub Pages en `https://<propietario>.github.io/<repositorio>/` (para este repositorio: `https://maxlestage.github.io/Securite/`). Es gratis para los repositorios públicos y no necesita ningún secreto.

GitHub Pages es un alojamiento estático. Las páginas son las que el servidor axum renderiza con [active](https://maxlestage.github.io/Active/), escritas en archivos: la página de inicio animada, el hub de documentación y todas las páginas de documentación funcionan exactamente igual que en Heroku, en los tres idiomas, y la copia es una aplicación instalable que funciona sin conexión. El playground de ataques y las estadísticas en directo necesitan el servidor axum: en Pages el playground lo indica y enlaza con la guía de despliegue. Use [Heroku](/docs/heroku-from-phone) o [Docker](/docs/docker) para la demo completa.

## Configuración única desde el móvil

1. Abra el repositorio en un navegador móvil y toque **Settings** (cambie a la vista de escritorio si la pestaña está oculta).
2. Toque **Pages** en el menú lateral.
3. En **Build and deployment**, elija **GitHub Actions** como **Source**.
4. Aplicación de GitHub → repositorio → **Actions** → **Deploy to GitHub Pages** → **Run workflow**.

Unos tres minutos después, el resumen de la ejecución muestra la dirección del sitio. Mientras no haga el paso 3, el workflow sigue construyendo el sitio en cada fusión, para detectar errores, y termina con el aviso *GitHub Pages not enabled* en lugar de fallar.

## Qué hace el workflow

Se ejecuta con cada push a `master`, tras cada ejecución correcta de Auto-merge o de Dependabot auto-merge (vea [CI y fusión automática](/docs/ci-auto-merge)) y bajo demanda. Dos ejecuciones nunca se solapan.

1. **Comprobación**: pregunta a la API de GitHub si Pages está activado con la fuente *GitHub Actions*.
2. **Ruta base**: `/<repositorio>` y la dirección `https://<propietario>.github.io/<repositorio>`, o la raíz de su dominio propio.
3. **Bundle del navegador**: `cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release` y luego `wasm-bindgen --target web` (la herramienta de línea de comandos precompilada, de la versión fijada en `Cargo.lock`).
4. **Exportación**: `BASE_PATH=/Securite SITE_URL=https://maxlestage.github.io/Securite cargo run --release -p securite-server -- export dist`. El servidor renderiza cada página con su propio código (3 idiomas × página de inicio, hub de documentación, 33 páginas de documentación y playground), con todos los enlaces bajo la ruta base, y escribe el manifiesto de la aplicación web, el service worker, `sitemap.xml`, `robots.txt`, `404.html`, `.nojekyll`, la hoja de estilos, los iconos y el bundle WebAssembly.
5. **Despliegue**: `actions/upload-pages-artifact` y luego `actions/deploy-pages`, en el entorno `github-pages`.

## Seguridad en un alojamiento estático

GitHub Pages no permite enviar cabeceras HTTP, así que la exportación escribe en cada página lo que el HTML permite, justo después de `<meta charset>`:

| Protección | Cómo |
|---|---|
| Content-Security-Policy | `<meta http-equiv>` con `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `worker-src 'self'`, `manifest-src 'self'` y los mismos `script-src` y `style-src` estrictos que el servidor |
| Scripts y estilo inline | el cargador WebAssembly, el registro del service worker y el pequeño estilo de active se permiten por sus hashes SHA-256, calculados para cada página durante la exportación, nunca con `'unsafe-inline'` |
| WebAssembly | solo `'wasm-unsafe-eval'`, nunca `'unsafe-eval'` |
| Referrer-Policy | `<meta name="referrer" content="strict-origin-when-cross-origin">` |
| HTTPS | impuesto por GitHub Pages (marque **Enforce HTTPS** en Settings → Pages) |

> **Atención:** algunas protecciones solo existen como cabeceras HTTP: `frame-ancestors` (clickjacking), HSTS, `X-Content-Type-Options`, COOP y CORP. Un navegador las ignora en una etiqueta `<meta>`. Para una aplicación que maneja datos de usuarios, sírvala con el servidor axum y el `Shield` de securite, como en Heroku.

## Direcciones y uso sin conexión

Cada página es un archivo HTML real, por ejemplo `/Securite/es/docs/waf/index.html`: los enlaces a cualquier página responden 200 con etiquetas SEO completas (dirección canónica, versiones en los otros idiomas, Open Graph, JSON-LD), y `sitemap.xml` lista todas las páginas en todos los idiomas. `/Securite/` ofrece los tres idiomas y abre el sitio en inglés (el servidor, en cambio, elige el idioma según el navegador); las direcciones desconocidas reciben `404.html`.

La copia es una Progressive Web App: el navegador ofrece instalarla, y su service worker, limitado a `/Securite/`, guarda para el uso sin conexión las páginas de inicio, los hubs de documentación, la hoja de estilos y el bundle WebAssembly, además de cada página leída. Un nuevo despliegue cambia la versión del worker, que entonces sustituye los archivos antiguos.

## Dominio propio

1. En su DNS, añada un registro `CNAME` que apunte `www.example.com` a `<propietario>.github.io`.
2. Settings → Pages → **Custom domain** → escriba el dominio → **Save**, y marque **Enforce HTTPS** cuando el certificado esté listo.
3. Vuelva a ejecutar el workflow: detecta el dominio propio y exporta el sitio para la raíz del dominio.

## Solución de problemas

| Síntoma | Solución |
|---|---|
| Aviso *GitHub Pages not enabled* | Elija **GitHub Actions** en Settings → Pages → Source y vuelva a ejecutar el workflow |
| `Branch "…" is not allowed to deploy to github-pages` | Settings → Environments → `github-pages` → permita la rama `master` |
| Página sin estilos, 404 en el `.css`, el `.js` o el `.wasm` | La ruta base no coincide con la dirección: revise el dominio propio y vuelva a ejecutar el workflow |
| El playground muestra el aviso de alojamiento estático | Normal en Pages: despliegue el servidor en [Heroku](/docs/heroku-from-phone) para la demo en directo |

## Páginas relacionadas

- [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)
- [Imagen Docker](/docs/docker)
- [CI y fusión automática](/docs/ci-auto-merge)
- [Cabeceras de seguridad](/docs/security-headers)
