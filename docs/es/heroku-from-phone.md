---
title: Desplegar en Heroku desde el móvil
summary: Ponga en línea el sitio de securite sin ordenador, con el botón Deploy en un toque, GitHub Actions en cada fusión o la integración de Heroku con GitHub.
category: deploy
order: 1
---

El repositorio incluye todo lo que Heroku necesita: un `Dockerfile`, un `heroku.yml` para el stack container y un `app.json` para el botón Deploy. Todos los pasos siguientes se hacen desde un navegador móvil o la aplicación de GitHub. Los nombres de menú citados son los de las interfaces en inglés.

## Antes de empezar

* Una cuenta de Heroku **verificada**, es decir, con un método de pago registrado. Heroku no tiene dynos gratuitos: la aplicación se ejecuta en un dyno de pago (Eco, Basic o superior), así que consulte antes la [página de precios de Heroku](https://www.heroku.com/pricing). Los dynos Eco se suspenden cuando no hay tráfico, por lo que la primera visita tras una pausa es lenta.
* Para los métodos B y C, acceso de escritura al repositorio de GitHub o a su fork.

## Método A, el botón Deploy

1. Abra el [enlace Deploy to Heroku](https://www.heroku.com/deploy?template=https://github.com/maxlestage/Securite), o toque el botón **Deploy to Heroku** del README, e inicie sesión en Heroku.
2. Elija un **App name**: letras minúsculas, cifras y guiones, único en todo Heroku. Elija una región.
3. Conserve las variables de configuración que `app.json` rellena:
   * `SECURITE_ENV=production` activa la redirección a HTTPS, HSTS y `upgrade-insecure-requests`, y lee la IP del cliente de la cabecera `X-Forwarded-For` de Heroku.
   * `RUST_LOG=info` es el filtro de registros; los eventos de seguridad usan el target `securite`.
4. Toque **Deploy app**. Como `app.json` declara `"stack": "container"`, Heroku construye la imagen descrita en `heroku.yml`, es decir, el `Dockerfile` del repositorio. La primera compilación tarda unos 10 a 15 minutos, porque todo el código Rust se compila desde cero.
5. Cuando termine la compilación, toque **View** para abrir el sitio.

Una aplicación creada con el botón es una instantánea: los commits posteriores no se despliegan. Configure el método B con el mismo nombre de aplicación para mantenerla al día.

## Método B, GitHub Actions en cada fusión

Es la opción recomendada para la entrega continua: `.github/workflows/deploy.yml` despliega `master` en Heroku.

### Copiar la clave de API de Heroku

1. En el navegador móvil, abra el panel de Heroku, toque su avatar y luego **Account settings**.
2. Desplácese hasta **API Key**, toque **Reveal** y copie la clave. Si la página aparece cortada, cambie el navegador al modo «versión para ordenador».

> **Consejo:** para mantener privada su clave principal, cree un token dedicado en **Account settings** → **Applications** → **Authorizations** → **Create authorization**.

### Añadir los secretos del repositorio

La aplicación de GitHub no permite editar secretos: use el navegador móvil.

1. Abra el repositorio en github.com y toque **Settings** (en modo «versión para ordenador» si la pestaña está oculta).
2. **Secrets and variables** → **Actions** → **New repository secret**.
3. Cree `HEROKU_API_KEY` con la clave.
4. Cree `HEROKU_APP_NAME` con un nombre único, por ejemplo `securite-sunombre`. Una variable de repositorio con ese nombre también funciona.

### Qué hace cada ejecución

El workflow arranca con cada push a `master`, tras cada ejecución correcta de Auto-merge (vea [CI y fusión automática](/docs/ci-auto-merge)) y bajo demanda. Dos ejecuciones nunca se solapan.

Primero se vuelve a ejecutar toda la CI (tests, lints, build del sitio) sobre `master`; no se despliega nada si no está en verde. Después:

1. **Check configuration**: si falta un secreto, la ejecución termina con el aviso *Heroku deploy skipped*, no con un fallo.
2. **Prepare the Heroku app**: crea la aplicación si no existe, fija su stack en `container` y define `SECURITE_ENV=production` salvo que la variable ya exista.
3. **Push to Heroku**: un `git push --force` de `master` al repositorio Git de Heroku de la aplicación. Heroku construye la imagen con `heroku.yml`.
4. **Smoke test**: consulta `/api/health` cada 10 segundos durante 5 minutos como máximo y luego muestra las cabeceras CSP, HSTS y de identificador de petición.

Para desplegar a mano: aplicación de GitHub → repositorio → **Actions** → **Deploy to Heroku** → **Run workflow**.

## Método C, la integración de Heroku con GitHub

1. Panel de Heroku → su aplicación → **Deploy** → **Deployment method** → **GitHub** → **Connect to GitHub**, y autorice a Heroku.
2. Busque el repositorio y toque **Connect**.
3. En **Automatic deploys**, elija `master` y luego **Enable Automatic Deploys**. **Manual deploy** → **Deploy Branch** lanza una primera compilación.

> **Atención:** el stack de la aplicación debe ser `container`; si no, Heroku ignora `heroku.yml` y busca un buildpack. Los métodos A y B lo configuran por usted; en otro caso hace falta `heroku stack:set container` desde la CLI de Heroku, lo que exige un ordenador. Prefiera A o B, y no combine nunca B y C en la misma aplicación: cada fusión compilaría dos veces.

## Comprobar el despliegue

1. Toque **Open app** en el panel, o abra la URL que muestra el smoke test. Las aplicaciones nuevas reciben una dirección del tipo `https://<name>-<random>.herokuapp.com`.
2. `/api/health` responde `ok`; `/api/stats` devuelve los contadores del escudo en JSON.
3. Revise las cabeceras de respuesta en el registro del paso **Smoke test**, o con un analizador en línea como [securityheaders.com](https://securityheaders.com).
4. Abra la página **Playground** y ataque el sitio: el WAF bloquea las cargas maliciosas y los contadores cambian.

## Registros

Panel de Heroku → su aplicación → **More** → **View logs**. Las peticiones bloqueadas aparecen como líneas `WARN` con el target `securite`:

```text
app[web.1]: 2026-10-10T08:12:44.913245Z  WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(203.0.113.7) method=GET path="/api/demo" request_id="3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44"
```

Para cambiar el nivel de detalle, edite `RUST_LOG` en **Settings** → **Reveal Config Vars**, por ejemplo `warn,securite=info`. Al guardar, la aplicación se reinicia. Vea [Eventos de seguridad](/docs/events-stats).

## Dominio propio

1. **Settings** → **Domains** → **Add domain**, por ejemplo `www.example.com`. Heroku muestra un destino DNS.
2. En su proveedor de DNS, cree un registro `CNAME` de `www` hacia ese destino (`ALIAS` o `ANAME` para un dominio raíz).
3. **Settings** → **SSL Certificates**: active Automated Certificate Management y Heroku emitirá y renovará el certificado. La disponibilidad depende del tipo de dyno.

> **Atención:** el modo producción envía HSTS con `includeSubDomains` durante dos años: el host y sus subdominios deben seguir sirviendo HTTPS. Con un proxy de CDN delante de Heroku, cambie la fuente de IP del cliente en `server/src/main.rs` (vea [IP del cliente](/docs/client-ip)).

## Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| La compilación dura de 10 a 15 minutos | Es normal: cada crate de Rust se compila en modo release. Siga el registro de compilación hasta el final. |
| `H10 App crashed` | El proceso se detuvo al arrancar. Lea las líneas de registro justo anteriores, corrija la causa y luego **More** → **Restart all dynos**. |
| `R10 Boot timeout` | Nada escuchaba en `$PORT`. Heroku define `PORT` en cada arranque y el servidor lo lee: no fije nunca un puerto en `main.rs` ni en el `Dockerfile`. |
| Aviso *Heroku deploy skipped* | Falta `HEROKU_API_KEY` o `HEROKU_APP_NAME`, o su nombre está mal escrito. Use secretos de repositorio, no secretos de entorno. |
| `Name is already taken` | Los nombres de aplicación son globales: elija otro. |
| El smoke test falla | En **Resources**, compruebe que el dyno `web` está activado y luego lea los registros. |
| `401` al preparar la aplicación | La clave de API cambió: actualice el secreto. |

## Páginas relacionadas

* [Imagen Docker](/docs/docker)
* [CI y fusión automática](/docs/ci-auto-merge)
* [Redirección a HTTPS](/docs/https-redirect)
* [IP del cliente](/docs/client-ip)
