---
title: Desplegar en GitHub Pages
summary: Publique el sitio gratis en GitHub Pages con un workflow de GitHub Actions, configurado una vez desde el móvil y actualizado en cada fusión en master.
category: deploy
order: 2
---

`.github/workflows/pages.yml` construye el sitio Yew + WebAssembly y lo publica en GitHub Pages en `https://<propietario>.github.io/<repositorio>/` (para este repositorio: `https://maxlestage.github.io/Securite/`). Es gratis para los repositorios públicos y no necesita ningún secreto.

GitHub Pages es un alojamiento estático. La página de inicio animada, el centro de documentación y todas las páginas de documentación funcionan exactamente igual que en Heroku. El playground de ataques y las estadísticas en directo necesitan el servidor axum: en Pages muestran un breve aviso en su lugar. Use [Heroku](/docs/heroku-from-phone) o [Docker](/docs/docker) para la demo completa.

## Configuración única desde el móvil

1. Abra el repositorio en un navegador móvil y toque **Settings** (cambie a la vista de escritorio si la pestaña está oculta).
2. Toque **Pages** en el menú lateral.
3. En **Build and deployment**, elija **GitHub Actions** como **Source**.
4. Aplicación de GitHub → repositorio → **Actions** → **Deploy to GitHub Pages** → **Run workflow**.

Unos tres minutos después, el resumen de la ejecución muestra la dirección del sitio. Mientras no haga el paso 3, el workflow sigue construyendo el sitio en cada fusión, para detectar errores, y termina con el aviso *GitHub Pages not enabled* en lugar de fallar.

## Qué hace el workflow

Se ejecuta con cada push a `master`, tras cada ejecución correcta de Auto-merge o de Dependabot auto-merge (vea [CI y fusión automática](/docs/ci-auto-merge)) y bajo demanda. Dos ejecuciones nunca se solapan.

1. **Comprobación**: pregunta a la API de GitHub si Pages está activado con la fuente *GitHub Actions*.
2. **Ruta base**: `/<repositorio>/`, o `/` si configuró un dominio propio.
3. **Build**: `SITE_BASE=/Securite/ trunk build --release --public-url /Securite/`. `SITE_BASE` se lee en tiempo de compilación: el router, los archivos de documentación y las llamadas a la API viven todos bajo la subruta.
4. **Refuerzo**: `.github/scripts/pages-postprocess.py` añade las cabeceras de seguridad que un alojamiento estático puede llevar, copia `index.html` a `404.html` y añade `.nojekyll`.
5. **Despliegue**: `actions/upload-pages-artifact` y luego `actions/deploy-pages`, en el entorno `github-pages`.

## Seguridad en un alojamiento estático

GitHub Pages no permite enviar cabeceras HTTP, así que el paso de posprocesado inyecta lo que el HTML permite, justo después de `<meta charset>`:

| Protección | Cómo |
|---|---|
| Content-Security-Policy | `<meta http-equiv>` con `default-src 'self'`, `object-src 'none'`, `base-uri 'self'` y el mismo `script-src` estricto que el servidor |
| Script de arranque inline | permitido por su hash SHA-256, calculado tras `trunk build`, nunca con `'unsafe-inline'` |
| WebAssembly | solo `'wasm-unsafe-eval'`, nunca `'unsafe-eval'` |
| Referrer-Policy | `<meta name="referrer" content="strict-origin-when-cross-origin">` |
| HTTPS | impuesto por GitHub Pages (marque **Enforce HTTPS** en Settings → Pages) |

> **Atención:** algunas protecciones solo existen como cabeceras HTTP: `frame-ancestors` (clickjacking), HSTS, `X-Content-Type-Options`, COOP y CORP. Un navegador las ignora en una etiqueta `<meta>`. Para una aplicación que maneja datos de usuarios, sírvala con el servidor axum y el `Shield` de securite, como en Heroku.

## Enlaces directos

Una aplicación de una sola página tiene un único archivo HTML. Cuando alguien abre directamente `/Securite/docs/waf`, GitHub Pages no encuentra ese archivo y sirve `404.html`, que es una copia de `index.html`: la aplicación arranca y el router muestra la página correcta. Los navegadores muestran la página con normalidad. Solo el estado HTTP es 404, lo que importa a los buscadores, no a los lectores.

## Dominio propio

1. En su DNS, añada un registro `CNAME` que apunte `www.example.com` a `<propietario>.github.io`.
2. Settings → Pages → **Custom domain** → escriba el dominio → **Save**, y marque **Enforce HTTPS** cuando el certificado esté listo.
3. Vuelva a ejecutar el workflow: detecta el dominio propio y construye el sitio para la ruta base `/`.

## Solución de problemas

| Síntoma | Solución |
|---|---|
| Aviso *GitHub Pages not enabled* | Elija **GitHub Actions** en Settings → Pages → Source y vuelva a ejecutar el workflow |
| `Branch "…" is not allowed to deploy to github-pages` | Settings → Environments → `github-pages` → permita la rama `master` |
| Página en blanco, 404 en el `.wasm` o el `.js` | La ruta base no coincide con la dirección: revise el dominio propio y vuelva a ejecutar el workflow |
| El playground muestra el aviso de alojamiento estático | Normal en Pages: despliegue el servidor en [Heroku](/docs/heroku-from-phone) para la demo en directo |

## Páginas relacionadas

- [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)
- [Imagen Docker](/docs/docker)
- [CI y fusión automática](/docs/ci-auto-merge)
- [Cabeceras de seguridad](/docs/security-headers)
