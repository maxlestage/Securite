---
title: Publicar el crate en crates.io
summary: Publique una nueva versión del crate securite desde el móvil con un token de crates.io, un secreto de GitHub y el workflow Publish crate, y gestione sus versiones con seguridad.
category: deploy
order: 4
---

El crate `securite`, en `crates/securite`, está listo para crates.io. La publicación se ejecuta en GitHub Actions (`.github/workflows/publish.yml`), así que basta con un móvil.

## Lo que ya está preparado

| Elemento | Valor |
|---|---|
| Metadatos | `description`, `keywords`, `categories`, `homepage`, `repository`, `documentation` (docs.rs) y `readme` en `crates/securite/Cargo.toml`; `rust-version` (1.85) heredado del workspace |
| Licencia | `MIT OR Apache-2.0`, heredada del workspace, con `LICENSE-MIT` y `LICENSE-APACHE` en la carpeta del crate |
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

### Desde la pestaña Actions

1. Aplicación de GitHub → repositorio → **Actions** → **Publish crate** → **Run workflow**.
2. Mantenga la rama `master` y **desmarque** *Dry run (package and verify only)*; después lance la ejecución.
3. El job ejecuta `cargo test -p securite` y luego `cargo publish -p securite`.

Si la casilla sigue marcada, que es lo predeterminado, el workflow solo ejecuta `cargo publish --dry-run`: un ensayo sin riesgo antes de la subida real.

### Desde una etiqueta de versión

En el navegador móvil: **Releases** → **Draft a new release** → **Choose a tag**, escriba `v0.1.0` y elija **Create new tag on publish**, destino `master`, redacte las notas, **Publish release**. La nueva etiqueta lanza el workflow, que comprueba que sea `v` seguida de la versión del crate y falla en caso contrario. Una etiqueta siempre publica de verdad.

Unos minutos después de la subida, docs.rs genera la documentación en [docs.rs/securite](https://docs.rs/securite).

## Lista de comprobación de la publicación

1. Suba `version` en `crates/securite/Cargo.toml` siguiendo el versionado semántico.
2. Ponga la misma versión en la entrada `securite` del `Cargo.lock` raíz (la línea que sigue a `name = "securite"`). La compilación Docker usa `--locked` y falla si el lockfile no está al día.
3. Describa los cambios en `CHANGELOG.md`, en la raíz del repositorio (formato Keep a Changelog): el pie de página del sitio enlaza a él.
4. Haga commit en una rama y deje que la [CI y la fusión automática](/docs/ci-auto-merge) lo lleven a `master`.
5. Publique con una etiqueta de versión o desde la pestaña Actions.

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
