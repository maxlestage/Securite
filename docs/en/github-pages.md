---
title: Deploy to GitHub Pages
summary: Publish the website for free on GitHub Pages with a GitHub Actions workflow, set up once from a phone, then updated on every merge into master.
category: deploy
order: 2
---

`.github/workflows/pages.yml` builds the Yew + WebAssembly website and publishes it on GitHub Pages at `https://<owner>.github.io/<repository>/` (for this repository: `https://maxlestage.github.io/Securite/`). It is free for public repositories and needs no secret.

GitHub Pages is a static host. The animated home page, the documentation hub and every documentation page work exactly as on Heroku. The live attack playground and the live statistics need the axum server: on Pages they show a short notice instead. Use [Heroku](/docs/heroku-from-phone) or [Docker](/docs/docker) for the full demo.

## One-time setup from your phone

1. Open the repository in a mobile browser and tap **Settings** (switch to the desktop view if the tab is hidden).
2. Tap **Pages** in the side menu.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. GitHub app → repository → **Actions** → **Deploy to GitHub Pages** → **Run workflow**.

After about three minutes the run summary shows the address of the site. Until step 3 is done, the workflow still builds the site on every merge, to catch errors, and ends with the notice *GitHub Pages not enabled* instead of failing.

## What the workflow does

It runs on every push to `master`, after every successful Auto-merge or Dependabot auto-merge run (see [CI and auto-merge](/docs/ci-auto-merge)), and on demand. Runs never overlap.

1. **Check**: asks the GitHub API whether Pages is enabled with the *GitHub Actions* source.
2. **Base path**: `/<repository>/`, or `/` when you configured a custom domain.
3. **Build**: `SITE_BASE=/Securite/ trunk build --release --public-url /Securite/`. `SITE_BASE` is read at compile time, so the router, the documentation files and the API calls all live under the sub-path.
4. **Harden**: `.github/scripts/pages-postprocess.py` adds the security headers that a static host can carry, copies `index.html` to `404.html` and adds `.nojekyll`.
5. **Deploy**: `actions/upload-pages-artifact` then `actions/deploy-pages`, in the `github-pages` environment.

## Security on a static host

GitHub Pages does not let you send HTTP headers, so the post-processing step injects what HTML allows, right after `<meta charset>`:

| Protection | How |
|---|---|
| Content-Security-Policy | `<meta http-equiv>` with `default-src 'self'`, `object-src 'none'`, `base-uri 'self'` and the same strict `script-src` as the server |
| Inline bootstrap script | allowed by its SHA-256 hash, computed after `trunk build`, never with `'unsafe-inline'` |
| WebAssembly | `'wasm-unsafe-eval'` only, no `'unsafe-eval'` |
| Referrer-Policy | `<meta name="referrer" content="strict-origin-when-cross-origin">` |
| HTTPS | enforced by GitHub Pages (tick **Enforce HTTPS** in Settings → Pages) |

> **Warning:** some protections only exist as HTTP headers: `frame-ancestors` (clickjacking), HSTS, `X-Content-Type-Options`, COOP and CORP. A browser ignores them in a `<meta>` tag. For an application that handles user data, serve it with the axum server and the securite `Shield`, as on Heroku.

## Deep links

A single-page application has one HTML file. When someone opens `/Securite/docs/waf` directly, GitHub Pages finds no such file and serves `404.html`, which is a copy of `index.html`: the app starts and the router displays the right page. Browsers show the page normally. Only the HTTP status is 404, which matters for search engines, not for readers.

## Custom domain

1. In your DNS, add a `CNAME` record pointing `www.example.com` to `<owner>.github.io`.
2. Settings → Pages → **Custom domain** → enter the domain → **Save**, then tick **Enforce HTTPS** once the certificate is ready.
3. Run the workflow again: it detects the custom domain and builds the site for the `/` base path.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Notice *GitHub Pages not enabled* | Set Settings → Pages → Source to **GitHub Actions**, then run the workflow again |
| `Branch "…" is not allowed to deploy to github-pages` | Settings → Environments → `github-pages` → allow the `master` branch |
| Blank page, 404 on `.wasm` or `.js` | The base path does not match the address: check the custom domain, then run the workflow again |
| Playground shows the static-hosting notice | Expected on Pages: deploy the server to [Heroku](/docs/heroku-from-phone) for the live demo |

## Related pages

- [Deploy to Heroku from your phone](/docs/heroku-from-phone)
- [Docker image](/docs/docker)
- [CI and auto-merge](/docs/ci-auto-merge)
- [Security headers](/docs/security-headers)
