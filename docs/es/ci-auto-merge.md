---
title: CI y fusión automática
summary: Qué comprueba el workflow de CI, cómo cada rama en verde se fusiona en master y se despliega automáticamente, y cómo gestionar exclusiones, conflictos y actualizaciones de Dependabot desde el móvil.
category: deploy
order: 4
---

Tres workflows se encadenan para que una rama enviada desde cualquier lugar, móvil incluido, acabe probada, fusionada y desplegada sin un solo clic:

```text
push to feature/x
  -> Auto-merge: CI (crate, MSRV, website)
  -> green: merge --no-ff into master as github-actions[bot]
  -> Deploy to Heroku (workflow_run): build, release, smoke test /api/health
```

## El workflow de CI

`.github/workflows/ci.yml` se ejecuta con cada push a `master`, en las pull requests, cuando Auto-merge lo llama y a mano. Sus tres jobs corren en paralelo:

| Job | Comprobaciones |
|---|---|
| Crate · fmt, clippy, tests, docs, package | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc -p securite --no-deps` con `RUSTDOCFLAGS=-D warnings`, `cargo publish -p securite --dry-run` |
| Crate · MSRV 1.85 | `cargo check -p securite --all-features` con Rust 1.85 |
| Website · Yew + WebAssembly | En `site/`, `cargo fmt -- --check`, `cargo clippy --target wasm32-unknown-unknown -- -D warnings` y `trunk build --release` con Trunk 0.21.14 y wasm-bindgen 0.2.129 |

Los avisos son errores: un lint de clippy o un enlace roto en la documentación hacen fallar la ejecución. Las mismas comprobaciones en un ordenador:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc -p securite --no-deps
cargo publish -p securite --dry-run
```

## El workflow de fusión automática

`.github/workflows/auto-merge.yml` se ejecuta con cada push de rama, salvo en `master`, `main`, `wip/**` y `dependabot/**`:

1. Llama al workflow de CI sobre el commit enviado.
2. Cuando todos los jobs están en verde, el job **Merge into master** obtiene `master` y fusiona ese commit exacto con `git merge --no-ff` como `github-actions[bot]`, con el mensaje `Merge branch '<branch>' into master (auto-merge)`, y después hace push de `master`. Si el commit ya está en `master`, no hace nada.
3. Su éxito lanza **Deploy to Heroku** mediante `workflow_run`. Un push hecho con el token del workflow no dispara otros workflows, de ahí este enlace explícito (vea [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)).

Un nuevo push a la misma rama cancela la ejecución en curso, y las fusiones en `master` se hacen de una en una. Una pull request abierta desde la rama se marca como fusionada automáticamente. La rama, en cambio, se queda: bórrela desde la página **Branches** cuando ya no la necesite.

> **Atención:** el resultado de la fusión no se vuelve a probar antes del propio push. Sin embargo, el workflow de despliegue vuelve a ejecutar toda la CI sobre `master` y solo despliega en Heroku si está en verde: una mala fusión nunca llega a producción. Si dos ramas modifican el mismo código, manténgalas cortas y al día con `master`.

### Desde el móvil

Edite un archivo en github.com, elija **Create a new branch for this commit** y luego **Propose changes**. Ese push basta para lanzar la cadena: no hace falta crear la pull request que propone GitHub y, si la crea, se marcará como fusionada en cuanto la fusión se complete.

### Excluir una rama

Dé a la rama un nombre `wip/...`, por ejemplo `wip/nuevas-reglas-waf`. No se fusiona nada y tampoco se ejecuta la CI, ya que la CI solo se lanza por sí sola para `master` y las pull requests. Abra una pull request para obtener las comprobaciones y fusiónela desde la aplicación de GitHub cuando esté lista.

## Requisitos

* **Settings** → **Actions** → **General** → **Workflow permissions** → **Read and write permissions** → **Save**. El workflow pide `contents: write` para hacer push de `master`; si la opción aparece en gris, una política de la organización la restringe.
* Si `master` está protegida por una regla de protección de rama o un ruleset, esa regla debe permitir que `github-actions` haga push directamente, por ejemplo mediante su lista de omisión. Una regla que exija pull requests o comprobaciones de estado rechaza el push y el job de fusión falla.

## Conflictos de fusión

Cuando `master` ha cambiado las mismas líneas, `git merge` se detiene, el job falla y no se envía nada. Integre `master` en su rama, resuelva y vuelva a hacer push: la fusión automática lo reintenta sola. Desde el móvil, abra una pull request desde la rama; si GitHub ofrece **Resolve conflicts**, corrija los marcadores en el editor web (el modo «versión para ordenador» ayuda) y luego **Mark as resolved** y **Commit merge**. Ese commit llega a su rama y relanza la cadena.

> **Consejo:** para recibir avisos solo en caso de fallo, abra github.com → su avatar → **Settings** → **Notifications** y, en **Actions**, marque **Only notify for failed workflows**.

## Dependabot

`.github/dependabot.yml` busca actualizaciones cada semana en tres lugares: el workspace de Cargo (`/`), el sitio (`/site`) y las versiones de las GitHub Actions. Cada actualización abre una pull request en una rama `dependabot/...`, que **también se fusiona automáticamente en `master`**:

1. La CI se ejecuta sobre la pull request.
2. Cuando está en verde, `.github/workflows/dependabot-auto-merge.yml` fusiona exactamente el commit probado (`gh pr merge --match-head-commit`). Nunca descarga el código de la pull request y solo actúa sobre las pull requests abiertas por `dependabot[bot]`.
3. El despliegue en Heroku viene después, tras una nueva pasada de la CI sobre `master`.

Una CI en rojo deja la pull request abierta: lea la comprobación fallida desde la aplicación de GitHub y luego cierre la pull request o corrija `master`. Las pull requests que vienen de forks nunca se fusionan automáticamente: nadie ajeno al repositorio puede enviar código a `master`.

`wasm-bindgen` y `gloo` están excluidos de Dependabot a propósito: `wasm-bindgen` debe coincidir exactamente con su herramienta de línea de comandos y `gloo` sigue la versión que usa Yew, vea [Imagen Docker](/docs/docker).

## Páginas relacionadas

* [Desplegar en Heroku desde el móvil](/docs/heroku-from-phone)
* [Publicar el crate en crates.io](/docs/publish-crates-io)
* [Imagen Docker](/docs/docker)
