#!/usr/bin/env python3
"""Prepares the Trunk output (site/dist) for GitHub Pages.

GitHub Pages cannot send HTTP headers, so the security headers the axum
server normally adds are replaced by what HTML allows:

* a strict Content-Security-Policy <meta> tag, with the SHA-256 hash of the
  inline bootstrap script injected by Trunk (no 'unsafe-inline' for scripts);
* a Referrer-Policy <meta> tag.

It also copies index.html to 404.html so that deep links such as
/docs/waf load the single-page app, and adds .nojekyll.

Usage: python3 .github/scripts/pages-postprocess.py site/dist
"""

import base64
import hashlib
import re
import shutil
import sys
from pathlib import Path


def inline_script_hashes(html: str) -> list[str]:
    hashes = []
    for match in re.finditer(r"<script\b([^>]*)>(.*?)</script\s*>", html, re.S | re.I):
        attrs, body = match.group(1), match.group(2)
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append("'sha256-" + base64.b64encode(digest).decode() + "'")
    return hashes


def main() -> None:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "site/dist")
    index = dist / "index.html"
    html = index.read_text(encoding="utf-8")

    script_src = " ".join(["'self'", "'wasm-unsafe-eval'", *inline_script_hashes(html)])
    csp = "; ".join(
        [
            "default-src 'self'",
            f"script-src {script_src}",
            "style-src 'self'",
            "style-src-attr 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests",
        ]
    )
    metas = (
        f'\n    <meta http-equiv="Content-Security-Policy" content="{csp}" />'
        '\n    <meta name="referrer" content="strict-origin-when-cross-origin" />'
    )
    # Right after <meta charset>, before any script or stylesheet.
    html, count = re.subn(r"(<meta\s+charset=[^>]*>)", r"\1" + metas.replace("\\", "\\\\"), html, count=1, flags=re.I)
    if count != 1:
        sys.exit("pages-postprocess: <meta charset> not found in index.html")

    index.write_text(html, encoding="utf-8")
    shutil.copyfile(index, dist / "404.html")
    (dist / ".nojekyll").write_text("", encoding="utf-8")
    print(f"pages-postprocess: CSP with {script_src.count('sha256-')} script hash(es), 404.html, .nojekyll")


if __name__ == "__main__":
    main()
