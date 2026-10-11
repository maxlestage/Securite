---
title: Deploy to Heroku from your phone
summary: Put the securite website online without a computer, with the one-tap Deploy button, GitHub Actions on every merge, or the Heroku GitHub integration.
category: deploy
order: 1
---

The repository ships everything Heroku needs: a `Dockerfile`, a `heroku.yml` for the container stack and an `app.json` for the Deploy button. Every step below works from a mobile browser or the GitHub mobile app. Menu names are those of the English interfaces.

## Before you start

* A **verified** Heroku account, that is with a payment method on file. Heroku has no free dynos: the app runs on a paid dyno (Eco, Basic or higher), so check [Heroku's pricing page](https://www.heroku.com/pricing) first. Eco dynos sleep when idle, so the first visit after a pause is slow.
* For methods B and C, write access to the GitHub repository or to your fork.

## Method A, the Deploy button

1. Open the Deploy to Heroku link, or tap the **Deploy to Heroku** button of the README, and sign in to Heroku.
2. Choose an **App name**: lowercase letters, digits and dashes, unique across Heroku. Pick a region.
3. Keep the config vars pre-filled from `app.json`:
   * `SECURITE_ENV=production` turns on the HTTPS redirect, HSTS and `upgrade-insecure-requests`, and reads the client IP from Heroku's `X-Forwarded-For`.
   * `RUST_LOG=info` is the log filter; security events use the `securite` target.
4. Tap **Deploy app**. As `app.json` declares `"stack": "container"`, Heroku builds the image described by `heroku.yml`, that is the repository `Dockerfile`. The first build takes about 10 to 15 minutes because all the Rust code compiles from scratch.
5. When the build is done, tap **View** to open the site.

An app created with the button is a snapshot: later commits are not deployed. Set up method B with the same app name to keep it up to date.

## Method B, GitHub Actions on every merge

Recommended for continuous delivery: `.github/workflows/deploy.yml` ships `master` to Heroku.

### Copy the Heroku API key

1. In the mobile browser, open the Heroku dashboard, tap your avatar, then **Account settings**.
2. Scroll to **API Key**, tap **Reveal** and copy the key. If the page is cut off, switch the browser to desktop site mode.

> **Tip:** to keep your main key private, create a dedicated token under **Account settings** → **Applications** → **Authorizations** → **Create authorization**.

### Add the repository secrets

The GitHub mobile app cannot edit secrets: use the mobile browser.

1. Open the repository on github.com and tap **Settings** (in desktop site mode if the tab is hidden).
2. **Secrets and variables** → **Actions** → **New repository secret**.
3. Create `HEROKU_API_KEY` with the key.
4. Create `HEROKU_APP_NAME` with a unique name, for example `securite-yourname`. A repository variable with that name also works.

### What each run does

The workflow starts on every push to `master`, after every successful Auto-merge run (see [CI and auto-merge](/docs/ci-auto-merge)), and on demand. Runs never overlap.

The whole CI (tests, lints, website build) first runs again on `master`; nothing is deployed unless it is green. Then:

1. **Check configuration**: if a secret is missing, the run ends with the notice *Heroku deploy skipped*, not with a failure.
2. **Prepare the Heroku app**: creates the app if it does not exist, sets its stack to `container`, and sets `SECURITE_ENV=production` unless the variable already exists.
3. **Push to Heroku**: a `git push --force` of `master` to the app's Heroku Git repository. Heroku builds the image with `heroku.yml`.
4. **Smoke test**: polls `/api/health` every 10 seconds for up to 5 minutes, then prints the CSP, HSTS and request ID headers.

To deploy by hand: GitHub app → repository → **Actions** → **Deploy to Heroku** → **Run workflow**.

## Method C, the Heroku GitHub integration

1. Heroku dashboard → your app → **Deploy** → **Deployment method** → **GitHub** → **Connect to GitHub**, and authorize Heroku.
2. Search for the repository and tap **Connect**.
3. Under **Automatic deploys**, choose `master`, then **Enable Automatic Deploys**. **Manual deploy** → **Deploy Branch** starts a first build.

> **Warning:** the app stack must be `container`, otherwise Heroku ignores `heroku.yml` and looks for a buildpack. Methods A and B set it for you; otherwise you need `heroku stack:set container` from the Heroku CLI, which requires a computer. Prefer A or B, and never combine B and C on one app, or each merge builds twice.

## Check the deployment

1. Tap **Open app** in the dashboard, or open the URL printed by the smoke test. New apps get an address like `https://<name>-<random>.herokuapp.com`.
2. `/api/health` answers `ok`; `/api/stats` returns the live shield counters as JSON.
3. Read the response headers in the **Smoke test** log, or with an online scanner such as [securityheaders.com](https://securityheaders.com).
4. Open the **Playground** page and attack the site: the WAF blocks the payloads and the counters move.

## Logs

Heroku dashboard → your app → **More** → **View logs**. Blocked requests are `WARN` lines with the `securite` target:

```text
app[web.1]: 2026-10-10T08:12:44.913245Z  WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(203.0.113.7) method=GET path="/api/demo" request_id="3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44"
```

To change the verbosity, edit `RUST_LOG` under **Settings** → **Reveal Config Vars**, for example `warn,securite=info`. Saving restarts the app. See [Security events](/docs/events-stats).

## Custom domain

1. **Settings** → **Domains** → **Add domain**, for example `www.example.com`. Heroku shows a DNS target.
2. At your DNS provider, create a `CNAME` record from `www` to that target (`ALIAS` or `ANAME` for a bare domain).
3. **Settings** → **SSL Certificates**: enable Automated Certificate Management, and Heroku issues and renews the certificate. Availability depends on the dyno type.

> **Warning:** production mode sends HSTS with `includeSubDomains` for two years, so the host and its subdomains must keep serving HTTPS. With a CDN proxy in front of Heroku, change the client IP source in `server/src/main.rs` (see [Client IP](/docs/client-ip)).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| The build runs for 10 to 15 minutes | Expected: every Rust crate compiles in release mode. Follow the build log to the end. |
| `H10 App crashed` | The process exited at start. Read the log lines just before, fix the cause, then **More** → **Restart all dynos**. |
| `R10 Boot timeout` | Nothing listened on `$PORT`. Heroku sets `PORT` at each start and the server reads it: never hard-code a port in `main.rs` or the `Dockerfile`. |
| *Heroku deploy skipped* | `HEROKU_API_KEY` or `HEROKU_APP_NAME` is missing or misspelled. Use repository secrets, not environment secrets. |
| `Name is already taken` | App names are global: choose another one. |
| Smoke test fails | In **Resources**, check that the `web` dyno is on, then read the logs. |
| `401` while preparing the app | The API key changed: update the secret. |

## Related pages

* [Docker image](/docs/docker)
* [CI and auto-merge](/docs/ci-auto-merge)
* [HTTPS redirect](/docs/https-redirect)
* [Client IP](/docs/client-ip)
