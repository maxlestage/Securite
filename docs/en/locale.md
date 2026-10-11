---
title: Language negotiation
summary: Picks the language of every request among the supported ones, from the query string, a cookie or Accept-Language, gives it to your handlers and sets Content-Language and Vary.
category: everyday
order: 13
---

`Locale` decides once, for every request, which of your languages to answer in, so that each handler doesn't have to parse `Accept-Language` itself.

## How the language is chosen

The first source that gives a supported language wins:

1. the query string, `?lang=fr` (lets a visitor switch language with a link);
2. a cookie, `lang=fr` (remembers that choice);
3. the browser's `Accept-Language` header, weights included: `de, fr-CA;q=0.9, en;q=0.5` gives `fr`. A regional variant matches its language (`fr-CA` → `fr`) and a language matches a regional variant you support (`pt` → `pt-BR`);
4. the default language, the first one you listed.

Unsupported values are ignored, never echoed. The result is always one of your tags, written as you wrote it.

Handlers read it with `req.get::<Lang>()`. The response gets `Content-Language` (unless the handler set one) and `Vary: Accept-Language`, so caches keep one copy per language.

## Quick start

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

## Configuration

| Method | Default | Description |
|---|---|---|
| `Locale::new([..])` | — | Supported tags; the first is the default. Panics if empty. |
| `.fallback(tag)` | the first tag | Another default language (added to the supported ones if needed). |
| `.query_param(Some(name))` / `.query_param(None)` | `lang` | Query parameter that forces the language, or none. |
| `.cookie(Some(name))` / `.cookie(None)` | `lang` | Cookie that remembers it, or none. |

## Remembering the choice

`Locale` reads the cookie; your language switcher sets it:

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

## Pitfalls and tips

- Pages whose content depends on the language must not be shared by a cache that ignores `Vary`. [ResponseCache](/docs/response-cache) skips responses with `Vary`.
- For search engines, prefer one address per language (`/fr/…`, `/en/…`) and use `Locale` to pick the redirect target on `/`.

## Related pages

- [Response cache](/docs/response-cache)
- [Response headers](/docs/set-headers)
