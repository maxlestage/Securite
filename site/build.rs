//! Compiles `../docs/{en,fr,es}/*.md` and `snippets/*` into Rust statics at build
//! time: the server never parses Markdown, and the pages are compiled into the binary.
//!
//! Only the native build (the server side of the crate) needs them: the WebAssembly
//! bundle gets nothing, so it stays small.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html};

const LANGS: [&str; 3] = ["en", "fr", "es"];

fn main() {
    println!("cargo:rerun-if-changed=../docs");
    println!("cargo:rerun-if-changed=snippets");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=static");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        return;
    }
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let docs_dir = Path::new("../docs");
    // Changes with the content of the site: part of the service worker version.
    let mut content_hash = 0xcbf2_9ce4_8422_2325_u64;

    let mut code = String::from("pub static DOCS: &[DocPage] = &[\n");
    for lang in LANGS {
        let dir = docs_dir.join(lang);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        files.sort();
        for path in files {
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            println!("cargo:rerun-if-changed={}", path.display());
            let slug = path.file_stem().unwrap().to_string_lossy().to_string();
            let raw = fs::read_to_string(&path).unwrap();
            content_hash = fnv1a_from(content_hash, raw.as_bytes());
            let (meta, body) = front_matter(&raw);
            let get = |k: &str| {
                meta.iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            };
            let (html, toc) = render(&body);
            let html = internal_links(&html);
            let order: u32 = get("order").parse().unwrap_or(99);
            let mut toc_code = String::from("&[");
            for (id, text, level) in &toc {
                let _ = write!(toc_code, "({id:?}, {text:?}, {level}),");
            }
            toc_code.push(']');
            let search = format!(
                "{} {} {}",
                get("title"),
                get("summary"),
                toc.iter()
                    .map(|t| t.1.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
            .to_lowercase();
            let _ = writeln!(
                code,
                "    DocPage {{ lang: {lang:?}, slug: {slug:?}, category: {:?}, order: {order}, title: {:?}, summary: {:?}, body: {html:?}, toc: {toc_code}, search: {search:?} }},",
                get("category"),
                get("title"),
                get("summary"),
            );
        }
    }
    code.push_str("];\n");

    // Highlighted code snippets for the home page.
    let mut snippets = String::new();
    if let Ok(entries) = fs::read_dir("snippets") {
        let mut files: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        files.sort();
        for path in files {
            let name = path
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .to_uppercase()
                .replace('-', "_");
            let lang = path.extension().and_then(|e| e.to_str()).unwrap_or("text");
            let src = fs::read_to_string(&path).unwrap();
            content_hash = fnv1a_from(content_hash, src.as_bytes());
            let _ = writeln!(
                snippets,
                "pub const {name}: &str = {:?};",
                highlight(src.trim_end(), lang)
            );
            let _ = writeln!(
                snippets,
                "pub const {name}_RAW: &str = {:?};",
                src.trim_end()
            );
        }
    }
    fs::write(Path::new(&out_dir).join("snippets_gen.rs"), snippets).unwrap();

    // The page code and the static files are part of the version too.
    for dir in ["src", "static"] {
        content_hash = hash_dir(content_hash, Path::new(dir));
    }
    let _ = writeln!(
        code,
        "/// Hash of the documentation, the snippets, the page code and the static files.\npub const CONTENT_HASH: &str = \"{content_hash:016x}\";"
    );
    fs::write(Path::new(&out_dir).join("docs_gen.rs"), code).unwrap();
}

fn hash_dir(mut hash: u64, dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return hash;
    };
    let mut paths: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            hash = hash_dir(hash, &path);
        } else if let Ok(bytes) = fs::read(&path) {
            hash = fnv1a_from(hash, path.to_string_lossy().as_bytes());
            hash = fnv1a_from(hash, &bytes);
        }
    }
    hash
}

/// Links between pages are written `/docs/<slug>` in Markdown. They become
/// `@BASE@/@LANG@/docs/<slug>/`: the server fills in the base path (`/Securite` on
/// GitHub Pages) and the language of the page being read.
fn internal_links(html: &str) -> String {
    const OPEN: &str = "href=\"/docs";
    let mut out = String::with_capacity(html.len() + 256);
    let mut rest = html;
    while let Some(i) = rest.find(OPEN) {
        out.push_str(&rest[..i]);
        let after = &rest[i + OPEN.len()..];
        let Some(end) = after.find('"') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let target = &after[..end];
        let (path, fragment) = match target.split_once('#') {
            Some((p, f)) => (p, format!("#{f}")),
            None => (target, String::new()),
        };
        let slug = path.trim_matches('/');
        if slug.is_empty() {
            let _ = write!(out, "href=\"@BASE@/@LANG@/docs/{fragment}\"");
        } else {
            let _ = write!(out, "href=\"@BASE@/@LANG@/docs/{slug}/{fragment}\"");
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// 64-bit FNV-1a, continued from `seed`.
fn fnv1a_from(seed: u64, data: &[u8]) -> u64 {
    data.iter().fold(seed, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn front_matter(raw: &str) -> (Vec<(String, String)>, String) {
    let raw = raw.trim_start_matches('\u{feff}');
    let Some(rest) = raw.strip_prefix("---") else {
        return (Vec::new(), raw.to_string());
    };
    let Some(end) = rest.find("\n---") else {
        return (Vec::new(), raw.to_string());
    };
    let meta = rest[..end]
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let v = v.trim().trim_matches('"').to_string();
            Some((k.trim().to_string(), v))
        })
        .collect();
    let body = rest[end + 4..]
        .trim_start_matches(['-', '\r', '\n'])
        .to_string();
    (meta, body)
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars().flat_map(char::to_lowercase) {
        let c = match c {
            'à' | 'â' | 'á' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' | 'í' => 'i',
            'ô' | 'ö' | 'ó' => 'o',
            'û' | 'ù' | 'ü' | 'ú' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            c => c,
        };
        if c.is_ascii_alphanumeric() {
            out.push(c);
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    out.trim_end_matches('-').to_string()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Renders markdown, returning the HTML and the table of contents.
fn render(md: &str) -> (String, Vec<(String, String, u8)>) {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(md, opts);

    let mut out = String::new();
    let mut toc = Vec::new();
    let mut buffer: Vec<Event<'_>> = Vec::new();
    let mut in_heading: Option<u8> = None;
    let mut code_lang: Option<String> = None;
    let mut code_text = String::new();

    for event in parser {
        if let Some(level) = in_heading {
            match event {
                Event::End(TagEnd::Heading(_)) => {
                    let text: String = buffer
                        .iter()
                        .filter_map(|e| match e {
                            Event::Text(t) | Event::Code(t) => Some(t.to_string()),
                            _ => None,
                        })
                        .collect();
                    let mut inner = String::new();
                    html::push_html(&mut inner, buffer.drain(..));
                    let mut id = slugify(&text);
                    let mut n = 2;
                    while toc.iter().any(|(i, _, _)| *i == id) {
                        id = format!("{}-{n}", slugify(&text));
                        n += 1;
                    }
                    let _ = writeln!(
                        out,
                        "<h{level} id=\"{id}\"><a class=\"anchor\" href=\"#{id}\">#</a>{inner}</h{level}>"
                    );
                    toc.push((id, text, level));
                    in_heading = None;
                }
                e => buffer.push(e),
            }
            continue;
        }
        if code_lang.is_some() {
            match event {
                Event::Text(t) => code_text.push_str(&t),
                Event::End(TagEnd::CodeBlock) => {
                    let lang = code_lang.take().unwrap();
                    let label = if lang.is_empty() {
                        "text".to_string()
                    } else {
                        lang.clone()
                    };
                    let _ = writeln!(
                        out,
                        "<div class=\"code\"><div class=\"code-head\"><span class=\"dots\"><i></i><i></i><i></i></span><span class=\"code-lang\">{}</span><button class=\"copy\" type=\"button\" aria-label=\"Copy\">⧉</button></div><pre><code class=\"lang-{}\">{}</code></pre></div>",
                        escape(&label),
                        escape(&label),
                        highlight(code_text.trim_end_matches('\n'), &lang)
                    );
                    code_text.clear();
                }
                _ => {}
            }
            continue;
        }
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                in_heading = Some(match level {
                    HeadingLevel::H1 | HeadingLevel::H2 => 2,
                    _ => 3,
                });
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                code_lang = Some(match kind {
                    CodeBlockKind::Fenced(l) => {
                        l.split([',', ' ']).next().unwrap_or("").to_string()
                    }
                    CodeBlockKind::Indented => String::new(),
                });
            }
            e => html::push_html(&mut out, std::iter::once(e)),
        }
    }

    // Callouts, responsive tables, external links.
    for (label, class) in [
        ("Tip:", "tip"),
        ("Astuce :", "tip"),
        ("Astuce:", "tip"),
        ("Consejo:", "tip"),
        ("Note:", "tip"),
        ("Warning:", "warn"),
        ("Attention :", "warn"),
        ("Attention:", "warn"),
        ("Atención:", "warn"),
        ("Important:", "warn"),
    ] {
        out = out.replace(
            &format!("<blockquote>\n<p><strong>{label}</strong>"),
            &format!("<blockquote class=\"callout {class}\">\n<p><strong>{label}</strong>"),
        );
    }
    out = out
        .replace("<table>", "<div class=\"table-wrap\"><table>")
        .replace("</table>", "</table></div>");
    out = out.replace(
        "<a href=\"http",
        "<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"http",
    );
    (out, toc)
}

// ---------------------------------------------------------------------------
// Tiny syntax highlighter
// ---------------------------------------------------------------------------

const RUST_KW: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while",
];

fn span(out: &mut String, class: &str, text: &str) {
    let _ = write!(out, "<span class=\"tk-{class}\">{}</span>", escape(text));
}

pub fn highlight(src: &str, lang: &str) -> String {
    match lang {
        "rust" | "rs" => highlight_rust(src),
        "toml" => highlight_hash_comments(src, true),
        "bash" | "sh" | "shell" | "yaml" | "yml" => highlight_hash_comments(src, false),
        "json" => highlight_json(src),
        _ => escape(src),
    }
}

fn highlight_rust(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // Comments
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            let end = chars[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(chars.len(), |p| i + p);
            span(&mut out, "com", &chars[i..end].iter().collect::<String>());
            i = end;
            continue;
        }
        // Strings
        if c == '"'
            || (c == 'r' && chars.get(i + 1) == Some(&'#'))
            || (c == 'b' && chars.get(i + 1) == Some(&'"'))
        {
            let start = i;
            if c == 'r' {
                let hashes = chars[i + 1..].iter().take_while(|&&c| c == '#').count();
                let close: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                let body_start = i + 1 + hashes + 1;
                let rest: String = chars[body_start.min(chars.len())..].iter().collect();
                let end = rest.find(&close).map_or(chars.len(), |p| {
                    body_start + rest[..p].chars().count() + close.chars().count()
                });
                span(
                    &mut out,
                    "str",
                    &chars[start..end].iter().collect::<String>(),
                );
                i = end;
                continue;
            }
            i += if c == 'b' { 2 } else { 1 };
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(chars.len());
            span(&mut out, "str", &chars[start..i].iter().collect::<String>());
            continue;
        }
        // Char literal vs lifetime
        if c == '\'' {
            if chars.get(i + 2) == Some(&'\'')
                || (chars.get(i + 1) == Some(&'\\') && chars.get(i + 3) == Some(&'\''))
            {
                let end = if chars.get(i + 1) == Some(&'\\') {
                    i + 4
                } else {
                    i + 3
                };
                span(&mut out, "str", &chars[i..end].iter().collect::<String>());
                i = end;
                continue;
            }
            let end = i
                + 1
                + chars[i + 1..]
                    .iter()
                    .take_while(|c| c.is_alphanumeric() || **c == '_')
                    .count();
            span(&mut out, "life", &chars[i..end].iter().collect::<String>());
            i = end;
            continue;
        }
        // Attributes
        if c == '#'
            && (chars.get(i + 1) == Some(&'[')
                || (chars.get(i + 1) == Some(&'!') && chars.get(i + 2) == Some(&'[')))
        {
            let mut depth = 0;
            let start = i;
            while i < chars.len() {
                if chars[i] == '[' {
                    depth += 1;
                } else if chars[i] == ']' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
            span(
                &mut out,
                "attr",
                &chars[start..i].iter().collect::<String>(),
            );
            continue;
        }
        // Numbers
        if c.is_ascii_digit() {
            let end = i + chars[i..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == '_' || **c == '.')
                .count();
            span(&mut out, "num", &chars[i..end].iter().collect::<String>());
            i = end;
            continue;
        }
        // Identifiers
        if c.is_alphabetic() || c == '_' {
            let end = i + chars[i..]
                .iter()
                .take_while(|c| c.is_alphanumeric() || **c == '_')
                .count();
            let word: String = chars[i..end].iter().collect();
            let next = chars.get(end).copied();
            let class = if RUST_KW.contains(&word.as_str()) {
                Some("kw")
            } else if next == Some('!') {
                Some("mac")
            } else if word.chars().next().is_some_and(char::is_uppercase) {
                Some("ty")
            } else if next == Some('(')
                || (next == Some(':') && chars.get(end + 1) == Some(&':') && false)
            {
                Some("fn")
            } else {
                None
            };
            match class {
                Some(cl) => span(&mut out, cl, &word),
                None => out.push_str(&escape(&word)),
            }
            i = end;
            continue;
        }
        out.push_str(&escape(&c.to_string()));
        i += 1;
    }
    out
}

fn highlight_hash_comments(src: &str, toml: bool) -> String {
    let mut out = String::new();
    for (n, line) in src.lines().enumerate() {
        if n > 0 {
            out.push('\n');
        }
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        out.push_str(indent);
        if trimmed.starts_with('#') {
            span(&mut out, "com", trimmed);
            continue;
        }
        if toml && trimmed.starts_with('[') {
            span(&mut out, "ty", trimmed);
            continue;
        }
        let mut first_word = !toml;
        let mut rest = trimmed;
        if let (true, Some((key, value))) = (toml, trimmed.split_once('=')) {
            span(&mut out, "fn", key);
            out.push('=');
            rest = value;
        }
        // Tokenise the rest: strings, flags, words.
        let chars: Vec<char> = rest.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '"' || c == '\'' {
                let end = chars[i + 1..]
                    .iter()
                    .position(|&x| x == c)
                    .map_or(chars.len(), |p| i + p + 2);
                span(&mut out, "str", &chars[i..end].iter().collect::<String>());
                i = end;
                first_word = false;
                continue;
            }
            if c == '#' && !toml && (i == 0 || chars[i - 1] == ' ') {
                span(&mut out, "com", &chars[i..].iter().collect::<String>());
                break;
            }
            if c.is_whitespace() || "|&;=(){}[],".contains(c) {
                out.push_str(&escape(&c.to_string()));
                if "|&;".contains(c) {
                    first_word = !toml;
                }
                i += 1;
                continue;
            }
            let end = i + chars[i..]
                .iter()
                .take_while(|c| !c.is_whitespace() && !"|&;=(){}[],\"'".contains(**c))
                .count();
            let word: String = chars[i..end].iter().collect();
            if first_word {
                span(&mut out, "fn", &word);
                first_word = false;
            } else if word.starts_with('-') {
                span(&mut out, "attr", &word);
            } else if word.chars().all(|c| c.is_ascii_digit() || c == '.')
                || word == "true"
                || word == "false"
            {
                span(&mut out, "num", &word);
            } else if word.ends_with(':') && !toml {
                span(&mut out, "fn", &word);
            } else {
                out.push_str(&escape(&word));
            }
            i = end;
        }
    }
    out
}

fn highlight_json(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(chars.len());
            let s: String = chars[start..i].iter().collect();
            let is_key = chars[i..].iter().find(|c| !c.is_whitespace()) == Some(&':');
            span(&mut out, if is_key { "fn" } else { "str" }, &s);
            continue;
        }
        if c.is_ascii_digit() || c == '-' {
            let end = i + chars[i..]
                .iter()
                .take_while(|c| c.is_ascii_digit() || "-.eE+".contains(**c))
                .count();
            span(&mut out, "num", &chars[i..end].iter().collect::<String>());
            i = end;
            continue;
        }
        if c.is_alphabetic() {
            let end = i + chars[i..].iter().take_while(|c| c.is_alphabetic()).count();
            span(&mut out, "kw", &chars[i..end].iter().collect::<String>());
            i = end;
            continue;
        }
        out.push_str(&escape(&c.to_string()));
        i += 1;
    }
    out
}
