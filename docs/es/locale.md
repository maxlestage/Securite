---
title: Negociación del idioma
summary: Elige el idioma de cada petición entre los admitidos, a partir de la query string, una cookie o Accept-Language, se lo pasa a tus handlers y establece Content-Language y Vary.
category: everyday
order: 13
---

`Locale` decide una sola vez, para cada petición, en cuál de tus idiomas responder, de modo que ningún handler tenga que analizar `Accept-Language` por su cuenta.

## Cómo se elige el idioma

Gana la primera fuente que indique un idioma admitido:

1. la query string, `?lang=fr` (permite a un visitante cambiar de idioma con un enlace);
2. una cookie, `lang=fr` (recuerda esa elección);
3. la cabecera `Accept-Language` del navegador, con sus pesos: `de, fr-CA;q=0.9, en;q=0.5` da `fr`. Una variante regional coincide con su idioma (`fr-CA` → `fr`) y un idioma coincide con una variante regional que admitas (`pt` → `pt-BR`);
4. el idioma por defecto, el primero de tu lista.

Los valores no admitidos se ignoran y nunca se reflejan en la respuesta. El resultado es siempre una de tus etiquetas, escrita tal como la escribiste.

Los handlers lo leen con `req.get::<Lang>()`. La respuesta recibe `Content-Language` (salvo que el handler haya puesto uno) y `Vary: Accept-Language`, más `Cookie` mientras la fuente de la cookie esté activada, para que las cachés compartidas nunca den el idioma de un visitante a otro. Todos los valores de `Vary` acaban en una sola línea.

## Inicio rápido

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Locale::new(["en", "fr", "es"]));
app.get("/", |req: Request| async move {
    match req.get::<Lang>().map(Lang::as_str) {
        Some("fr") => "Bonjour !",
        Some("es") => "¡Hola!",
        _ => "Hello!",
    }
});
```

## Configuración

| Método | Valor por defecto | Descripción |
|---|---|---|
| `Locale::new([..])` | — | Etiquetas admitidas; la primera es la predeterminada. Provoca un pánico si la lista está vacía. |
| `.fallback(tag)` | la primera etiqueta | Otro idioma por defecto (se añade a los admitidos si hace falta). |
| `.query_param(Some(name))` / `.query_param(None)` | `lang` | Parámetro de la query que fuerza el idioma, o ninguno. |
| `.cookie(Some(name))` / `.cookie(None)` | `lang` | Cookie que lo recuerda, o ninguna. |

## Recordar la elección

`Locale` lee la cookie; tu selector de idioma la establece:

```rust
use vitesse::prelude::*;
use std::time::Duration;

let mut app = App::new();
app.get("/lang/:tag", |req: Request| async move {
    let tag = req.param("tag").unwrap_or("en").to_owned();
    Redirect::to("/").into_response().cookie(
        Cookie::new("lang", tag).path("/").max_age(Duration::from_secs(365 * 86_400)),
    )
});
```

## Errores comunes y consejos

- Añade `Locale` antes de una [ResponseCache](/docs/response-cache): así cada idioma tiene su propia entrada, sea cual sea el `Accept-Language` que envíe el navegador.
- La mayoría de las CDN no almacenan en caché las respuestas con `Vary: Cookie`. Para las páginas que deba almacenar una CDN, desactiva la cookie con `.cookie(None)` y usa enlaces `?lang=` o una dirección por idioma.
- Un idioma rechazado con `q=0` nunca se elige, ni siquiera a través de una variante regional: `fr;q=0, fr-CA` da el idioma por defecto.
- Para los buscadores, es preferible una dirección por idioma (`/fr/…`, `/en/…`) y usar `Locale` para elegir el destino de la redirección en `/`.

## Páginas relacionadas

- [Caché de respuestas](/docs/response-cache)
- [Cabeceras de respuesta](/docs/set-headers)
