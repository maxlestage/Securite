---
title: Publicar el crate en crates.io
summary: Publique una nueva versión del crate Securite enviando su versión y su changelog: el workflow Publish crate pone la etiqueta, crea la release de GitHub y publica en crates.io, desde el móvil, y usted gestiona sus versiones con seguridad.
category: deploy
order: 3
---

El crate `securite`, en `crates/securite`, está listo para crates.io. La publicación se ejecuta en GitHub Actions (`.github/workflows/publish.yml`) y arranca sola cuando una nueva versión llega a `master`, así que basta con un móvil.

## Lo que ya está preparado

| Elemento | Valor |
|---|---|
| Metadatos | `description`, `keywords`, `categories`, `homepage`, `repository`, `documentation` (docs.rs) y `readme` en `crates/securite/Cargo.toml`; `rust-version` (1.85) heredado del workspace |
| Licencia | Propietaria: `license-file = "LICENSE"`, heredada del workspace; cargo copia el archivo en el paquete |
| README | `crates/securite/README.md`, que se muestra en la página de crates.io |
| docs.rs | `[package.metadata.docs.rs]` compila con todas las features y `--cfg docsrs` |
| Comprobación del paquete | La CI ejecuta `cargo publish -p securite --dry-run` en cada push, así que los problemas de empaquetado aparecen mucho antes del día de la publicación |

## Configuración inicial

### Crear un token de crates.io

1. En el navegador móvil, inicie sesión en [crates.io](https://crates.io) con su cuenta de GitHub.
2. Abra **Account Settings** y verifique su dirección de correo: crates.io rechaza las publicaciones sin ella.
3. **API Tokens** → **New Token**. Póngale un nombre y una fecha de caducidad, marque los ámbitos `publish-new` (necesario para la primera subida) y `publish-update`, y restrínjalo al crate `securite`.
4. Copie el token: solo se muestra una vez.

### Guardarlo en GitHub

La aplicación de GitHub no permite editar secretos, así que use el navegador móvil: repositorio → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**, nombre `CARGO_REGISTRY_TOKEN`, pegue el token, **Add secret**.

## Publicar una versión

### Automáticamente, desde master

Cambie la versión, redacte su sección en `CHANGELOG.md` y envíe los cambios (vea la lista de comprobación más abajo). Ningún formulario que rellenar: cuando la CI está en verde en un push a `master`, el workflow **Publish crate** lee la versión de `securite` y, si aún no tiene etiqueta:

1. pone en el commit la etiqueta `v` seguida de la versión (`v0.1.0` para `0.1.0`);
2. crea la release de GitHub de esa etiqueta, con la sección `## [0.1.0]` de `CHANGELOG.md` como notas (las notas generadas por GitHub si esa sección no existe);
3. ejecuta `cargo test -p securite` y luego `cargo publish -p securite`.

Una versión que ya tiene su etiqueta se deja tal cual: los pushes normales no publican nada. Sin el secreto `CARGO_REGISTRY_TOKEN`, o mientras `vitesse` (dependencia de la feature por defecto `vitesse`) no esté en crates.io, la etiqueta y la release se crean igualmente y la publicación se aplaza: la ejecución termina con un aviso, y usted publica más tarde desde la pestaña Actions.

### Desde la pestaña Actions

1. Aplicación de GitHub → repositorio → **Actions** → **Publish crate** → **Run workflow**.
2. Mantenga la rama `master` y **desmarque** *Dry run (package and verify only)*; después lance la ejecución.
3. El job ejecuta `cargo test -p securite` y luego `cargo publish -p securite`.

Si la casilla sigue marcada, que es lo predeterminado, el workflow solo ejecuta `cargo publish --dry-run`: un ensayo sin riesgo antes de la subida real.

Úsela para una publicación aplazada, una vez configurado el secreto o con `vitesse` ya publicado.

### Desde una etiqueta

Enviar usted mismo una etiqueta `v0.1.0` sigue lanzando el workflow, que comprueba que sea `v` seguida de la versión del crate y falla en caso contrario. Una etiqueta siempre publica de verdad. La publicación automática suele hacer innecesario este camino.

Unos minutos después de la subida, docs.rs genera la documentación en [docs.rs/securite](https://docs.rs/securite).

## Lista de comprobación de la publicación

1. Suba `version` en `crates/securite/Cargo.toml` siguiendo el versionado semántico.
2. Ponga la misma versión en la entrada `securite` del `Cargo.lock` raíz (la línea que sigue a `name = "securite"`). La compilación Docker usa `--locked` y falla si el lockfile no está al día.
3. Describa los cambios en `CHANGELOG.md`, en la raíz del repositorio (formato Keep a Changelog), bajo un título `## [0.1.1]`: esa sección se convierte en las notas de la release de GitHub. El pie de página del sitio enlaza al archivo.
4. Haga commit en una rama y deje que la [CI y la fusión automática](/docs/ci-auto-merge) lo lleven a `master`.
5. Nada más: cuando la CI está en verde en `master`, el workflow pone la etiqueta `v0.1.1`, crea la release y publica el crate.

```toml
[package]
name = "securite"
version = "0.1.1"
```

Antes de la 1.0, Cargo considera que el número menor es el de los cambios incompatibles:

```text
0.1.0 -> 0.1.1   bug fix or compatible addition
0.1.1 -> 0.2.0   breaking change (renamed type, removed method, raised MSRV)
0.9.3 -> 1.0.0   stable API, then 1.x.y follows the usual major.minor.patch rules
```

> **Consejo:** subir la versión mínima de Rust admitida (hoy 1.85) merece al menos una versión menor. Cambie a la vez `rust-version` en el `Cargo.toml` raíz y el job `msrv` de `ci.yml`.

## Lo que no se puede deshacer

* **Los nombres de crate son permanentes**: una vez publicado `securite`, el nombre queda ligado a su cuenta. Elija con cuidado el nombre de cualquier crate futuro.
* **Las versiones son inmutables**: nunca podrá subir otro contenido con el mismo número. Un error se corrige con una nueva versión.
* **Hacer yank** retira una versión defectuosa de las nuevas resoluciones de dependencias, mientras que los `Cargo.lock` existentes siguen funcionando. Necesita un terminal y un token con el ámbito `yank`, por ejemplo en un GitHub Codespace abierto en el navegador:

```bash
cargo login
cargo yank securite@0.1.1
# Changed your mind
cargo yank securite@0.1.1 --undo
```

> **Atención:** no haga nunca commit del token ni lo pegue en una issue o un registro. Si se filtra, revóquelo en **API Tokens** de crates.io, cree uno nuevo y actualice el secreto `CARGO_REGISTRY_TOKEN`.

## Páginas relacionadas

* [CI y fusión automática](/docs/ci-auto-merge)
* [Instalación](/docs/installation)
