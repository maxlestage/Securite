//! Overhead of the shield on a realistic request.
//!
//! ```sh
//! cargo bench -p securite
//! ```

use std::hint::black_box;
use std::net::SocketAddr;

use criterion::{Criterion, criterion_group, criterion_main};
use http::{Request, Response};
use securite::prelude::*;
use std::convert::Infallible;
use tower::{Service, ServiceExt};

fn request(uri: &str) -> Request<String> {
    let mut r = Request::builder()
        .uri(uri)
        .header("host", "example.com")
        .header(
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        )
        .header("accept", "text/html,application/xhtml+xml")
        .header("accept-language", "fr-FR,fr;q=0.9,en;q=0.8")
        .header("cookie", "session=abc123; theme=dark")
        .header("referer", "https://example.com/products")
        .body(String::new())
        .unwrap();
    r.extensions_mut()
        .insert(PeerAddr("203.0.113.7:5555".parse::<SocketAddr>().unwrap()));
    r
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let handler = tower::service_fn(|_req: Request<String>| async {
        Ok::<_, Infallible>(Response::new(http_body_util::Full::new(bytes_static())))
    });

    let mut group = c.benchmark_group("shield");
    for (name, shield) in [
        ("baseline (no shield)", None),
        (
            "recommended",
            Some(
                ShieldBuilder::recommended()
                    .guard(RateLimit::per_second(1_000_000))
                    .build(),
            ),
        ),
        (
            "strict",
            Some(
                ShieldBuilder::strict()
                    .guard(RateLimit::per_second(1_000_000))
                    .without("concurrency")
                    .build(),
            ),
        ),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let req = request("/search?q=rust+web+security&page=2");
                    match &shield {
                        Some(s) => {
                            let mut svc = tower_layer::Layer::layer(s, handler);
                            let res = svc.ready().await.unwrap().call(req).await.unwrap();
                            black_box(res);
                        }
                        None => {
                            let mut svc = handler;
                            let res = svc.ready().await.unwrap().call(req).await.unwrap();
                            black_box(res);
                        }
                    }
                })
            })
        });
    }
    group.finish();

    let waf = Waf::new();
    c.bench_function("waf inspect (clean request)", |b| {
        let parts = request("/search?q=rust+web+security&page=2").into_parts().0;
        b.iter(|| black_box(waf.inspect(black_box(&parts))))
    });
    c.bench_function("waf inspect (sqli)", |b| {
        let parts = request("/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--")
            .into_parts()
            .0;
        b.iter(|| black_box(waf.inspect(black_box(&parts))))
    });
    let set =
        IpSet::parse((0..10_000).map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))).unwrap();
    c.bench_function("ip set lookup (10k ranges)", |b| {
        let ip = "10.20.30.40".parse().unwrap();
        b.iter(|| black_box(set.contains(black_box(ip))))
    });
}

fn bytes_static() -> bytes::Bytes {
    bytes::Bytes::from_static(b"hello")
}

criterion_group!(benches, bench);
criterion_main!(benches);
