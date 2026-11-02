---
title: Idempotency keys
summary: Answers a POST or PATCH sent again with the same Idempotency-Key with the stored first answer instead of running it twice, as with Stripe's API and the IETF draft.
category: everyday
order: 13
---

A phone loses its network right after tapping "Pay": did the payment go through? The app sends the same `POST` again, with the same `Idempotency-Key` header (as with Stripe's API and the IETF `Idempotency-Key` draft). Without `Idempotency`, the customer pays twice; with it, the second request is not run: it gets the stored answer to the first one, marked `Idempotent-Replayed: true`.

## What happens to a request

`POST` and `PATCH` requests carrying an `Idempotency-Key` are handled; the others go straight through (`PUT` and `DELETE` are idempotent by nature).

| Situation | Answer |
|---|---|
| First request with this key | Runs normally; the answer is stored for 24 hours. |
| Same key, same request | The stored answer, with `Idempotent-Replayed: true`. The handler is not called. |
| Same key while the first request still runs | `409 Conflict` with `Retry-After: 1`. |
| Same key with another request (another path, another body) | `422 Unprocessable Content`: a client bug, not a retry. |
| Invalid key (empty, over 255 characters, not visible ASCII) | `400 Bad Request`. |
| No key, with `.required()` | `400 Bad Request`. |

Server errors (`5xx`), `408`, `409` and `429` are not stored: the client may retry, and the retry runs. Keys are scoped by the client's credentials (`Authorization`, `X-Api-Key`): one client cannot read another's answers by guessing its key. Error answers are `application/problem+json`.

## Quick start

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Idempotency::new()); // POST and PATCH carrying an `Idempotency-Key`
app.post("/payments", |_req: Request| async { (201, "paid") });
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `.ttl(duration)` | 24 hours | How long an answer is kept. |
| `.methods([...])` | `POST`, `PATCH` | The methods it applies to. |
| `.required()` | off | Refuses (`400`) the requests of these methods that carry no key. |
| `.header(name)` | `Idempotency-Key` | Another header (`X-Idempotency-Key`…). |
| `.max_body(bytes)` | `1 MiB` | Largest request body (larger: `413`) and largest answer stored (larger: sent but not stored). |
| `.store(store)` | `MemoryStore` | Where answers are kept: `MemoryStore`, or a `RedisStore` shared by every instance. |
| `.on_error(f)` | — | Called when the store fails (the request then runs as if it had no key). |

## Sharing the answers with Redis

With several instances behind a load balancer, a retry may reach another instance than the first request. Give `Idempotency` the same `RedisStore` as the [response cache](/docs/response-cache) (feature `redis` or `redis-tls`) so every instance sees the stored answers:

```rust
use pratique::prelude::*;
use vitesse::prelude::*;

let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
let store = RedisStore::open(&url).expect("invalid REDIS_URL").prefix("shop:idempotency:");
let mut app = App::new();
app.middleware(
    Idempotency::new()
        .store(store)
        .on_error(|e| eprintln!("idempotency: {e}")),
);
```

## Related pages

- [Pratique, everyday middlewares](/docs/pratique)
- [Response cache](/docs/response-cache)
- [Webhook signatures](/docs/webhook-signatures)
