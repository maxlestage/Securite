---
title: Deploy to GitHub Pages
summary: Publish the website for free on GitHub Pages with a GitHub Actions workflow, set up once from a phone, then updated on every merge into master.
category: deploy
order: 2
---

`.github/workflows/pages.yml` builds the website and publishes a static copy on GitHub Pages at `https://<owner>.github.io/<repository>/` (for this repository: `https://maxlestage.github.io/Securite/`). It is free for public repositories and needs no secret.

GitHub Pages is a static host. The pages are the ones the Vitesse server renders with [Active](https://maxlestage.github.io/Active/), written to files: the animated home page, the documentation hub and every documentation page work exactly as on Heroku, in the three languages, and the copy is an installable app that works offline. The live attack playground and the live statistics need the Vitesse server: on Pages the playground says so and links to the deployment guide. Use [Heroku](/docs/heroku-from-phone) or [Docker](/docs/docker) for the full demo.

## One-time setup from your phone

1. Open the repository in a mobile browser and tap **Settings** (switch to the desktop view if the tab is hidden).
2. Tap **Pages** in the side menu.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. GitHub app → repository → **Actions** → **Deploy to GitHub Pages** → **Run workflow**.

After about three minutes the run summary shows the address of the site. Until step 3 is done, the workflow still builds the site on every merge, to catch errors, and ends with the notice *GitHub Pages not enabled* instead of failing.

## What the workflow does

It runs on every push to `master`, after every successful Auto-merge or Dependabot auto-merge run (see [CI and auto-merge](/docs/ci-auto-merge)), and on demand. Runs never overlap.

1. **Check**: asks the GitHub API whether Pages is enabled with the *GitHub Actions* source.
2. **Base path**: `/<repository>` and the address `https://<owner>.github.io/<repository>`, or the root of your custom domain.
3. **Browser bundle**: `cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release`, then `wasm-bindgen --target web` (the prebuilt command-line tool of the version locked in `Cargo.lock`).
4. **Export**: `BASE_PATH=/Securite SITE_URL=https://maxlestage.github.io/Securite cargo run --release -p securite-server -- export dist`. The server renders every page with its own code (3 languages × home page, documentation hub, 33 documentation pages and playground), with every link behind the base path, and writes the web app manifest, the service worker, `sitemap.xml`, `robots.txt`, `404.html`, `.nojekyll`, the style sheet, the icons and the WebAssembly bundle.
5. **Deploy**: `actions/upload-pages-artifact` then `actions/deploy-pages`, in the `github-pages` environment.

## Security on a static host

GitHub Pages does not let you send HTTP headers, so the export writes what HTML allows into every page, right after `<meta charset>`:

| Protection | How |
|---|---|
| Content-Security-Policy | `<meta http-equiv>` with `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `worker-src 'self'`, `manifest-src 'self'` and the same strict `script-src` and `style-src` as the server |
| Inline scripts and style | the WebAssembly loader, the service worker registration and the small style of Active are allowed by their SHA-256 hashes, computed for each page during the export, never with `'unsafe-inline'` |
| WebAssembly | `'wasm-unsafe-eval'` only, no `'unsafe-eval'` |
| Referrer-Policy | `<meta name="referrer" content="strict-origin-when-cross-origin">` |
| HTTPS | enforced by GitHub Pages (tick **Enforce HTTPS** in Settings → Pages) |

> **Warning:** some protections only exist as HTTP headers: `frame-ancestors` (clickjacking), HSTS, `X-Content-Type-Options`, COOP and CORP. A browser ignores them in a `<meta>` tag. For an application that handles user data, serve it with the Vitesse server and the Securite `Shield`, as on Heroku.

## Addresses and offline use

Every page is a real HTML file, for example `/Securite/fr/docs/waf/index.html`: links to any page answer 200 with complete SEO tags (canonical address, language alternates, Open Graph, JSON-LD), and `sitemap.xml` lists every page in every language. `/Securite/` links the three languages and opens the English site (the server picks the language from the browser instead); unknown addresses get `404.html`.

The copy is a Progressive Web App: the browser offers to install it, and its service worker, scoped to `/Securite/`, keeps the home pages, the documentation hubs, the style sheet and the WebAssembly bundle for offline use, as well as every page you read. A new deployment changes the version of the worker, which then replaces the old files.

## Custom domain

1. In your DNS, add a `CNAME` record pointing `www.example.com` to `<owner>.github.io`.
2. Settings → Pages → **Custom domain** → enter the domain → **Save**, then tick **Enforce HTTPS** once the certificate is ready.
3. Run the workflow again: it detects the custom domain and exports the site for the root of the domain.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Notice *GitHub Pages not enabled* | Set Settings → Pages → Source to **GitHub Actions**, then run the workflow again |
| `Branch "…" is not allowed to deploy to github-pages` | Settings → Environments → `github-pages` → allow the `master` branch |
| Page without style, 404 on `.css`, `.js` or `.wasm` | The base path does not match the address: check the custom domain, then run the workflow again |
| Playground shows the static-hosting notice | Expected on Pages: deploy the server to [Heroku](/docs/heroku-from-phone) for the live demo |

## Related pages

- [Deploy to Heroku from your phone](/docs/heroku-from-phone)
- [Docker image](/docs/docker)
- [CI and auto-merge](/docs/ci-auto-merge)
- [Security headers](/docs/security-headers)
