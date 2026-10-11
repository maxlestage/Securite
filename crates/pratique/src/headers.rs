//! Headers added to, replaced in or removed from every response.

use vitesse::http::header::{HeaderName, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response};

#[derive(Debug, Clone)]
enum Op {
    /// Added when the response doesn't have it.
    IfMissing(HeaderName, HeaderValue),
    /// Always replaces the value.
    Set(HeaderName, HeaderValue),
    /// Appended to the existing values.
    Append(HeaderName, HeaderValue),
    Remove(HeaderName),
}

/// Edits the headers of every response, in the order given.
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(
///     SetHeaders::new()
///         .set("x-powered-by", "Vitesse")
///         .if_missing("content-language", "en")
///         .append("link", "</app.css>; rel=preload; as=style")
///         .remove("x-debug"),
/// );
/// ```
#[derive(Debug, Clone, Default)]
pub struct SetHeaders {
    ops: Vec<Op>,
}

fn pair(name: &str, value: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_bytes(name.as_bytes()).expect("invalid header name"),
        HeaderValue::from_str(value).expect("invalid header value"),
    )
}

impl SetHeaders {
    /// No change yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `name: value` when the response doesn't have `name`.
    ///
    /// # Panics
    /// If the name or the value is invalid.
    pub fn if_missing(mut self, name: &str, value: &str) -> Self {
        let (name, value) = pair(name, value);
        self.ops.push(Op::IfMissing(name, value));
        self
    }

    /// Sets `name: value`, replacing what the handler set.
    ///
    /// # Panics
    /// If the name or the value is invalid.
    pub fn set(mut self, name: &str, value: &str) -> Self {
        let (name, value) = pair(name, value);
        self.ops.push(Op::Set(name, value));
        self
    }

    /// Adds one more `name: value`, keeping the existing ones.
    ///
    /// # Panics
    /// If the name or the value is invalid.
    pub fn append(mut self, name: &str, value: &str) -> Self {
        let (name, value) = pair(name, value);
        self.ops.push(Op::Append(name, value));
        self
    }

    /// Removes `name` from every response.
    ///
    /// # Panics
    /// If the name is invalid.
    pub fn remove(mut self, name: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("invalid header name");
        self.ops.push(Op::Remove(name));
        self
    }
}

impl Middleware for SetHeaders {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        Box::pin(async move {
            let mut res = next.run(req).await;
            let headers = res.headers_mut();
            for op in &self.ops {
                match op {
                    Op::IfMissing(name, value) => {
                        headers.entry(name).or_insert_with(|| value.clone());
                    }
                    Op::Set(name, value) => {
                        headers.insert(name, value.clone());
                    }
                    Op::Append(name, value) => {
                        headers.append(name, value.clone());
                    }
                    Op::Remove(name) => {
                        headers.remove(name);
                    }
                }
            }
            res
        })
    }
}
