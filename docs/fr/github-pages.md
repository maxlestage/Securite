---
title: Déployer sur GitHub Pages
summary: Publiez gratuitement le site sur GitHub Pages grâce à un workflow GitHub Actions, configuré une fois depuis votre téléphone puis mis à jour à chaque fusion sur master.
category: deploy
order: 2
---

`.github/workflows/pages.yml` construit le site et en publie une copie statique sur GitHub Pages à l'adresse `https://<propriétaire>.github.io/<dépôt>/` (pour ce dépôt : `https://maxlestage.github.io/Securite/`). C'est gratuit pour les dépôts publics et aucun secret n'est nécessaire.

GitHub Pages est un hébergement statique. Les pages sont celles que le serveur Vitesse rend avec [active](https://maxlestage.github.io/Active/), écrites dans des fichiers : la page d'accueil animée, le hub de documentation et toutes les pages de documentation fonctionnent exactement comme sur Heroku, dans les trois langues, et la copie est une application installable qui fonctionne hors ligne. Le playground d'attaques et les statistiques en direct ont besoin du serveur Vitesse : sur Pages, le playground le signale et renvoie vers le guide de déploiement. Utilisez [Heroku](/docs/heroku-from-phone) ou [Docker](/docs/docker) pour la démo complète.

## Configuration unique depuis votre téléphone

1. Ouvrez le dépôt dans un navigateur mobile et touchez **Settings** (passez en affichage ordinateur si l'onglet est masqué).
2. Touchez **Pages** dans le menu latéral.
3. Sous **Build and deployment**, choisissez **GitHub Actions** comme **Source**.
4. Application GitHub → dépôt → **Actions** → **Deploy to GitHub Pages** → **Run workflow**.

Environ trois minutes plus tard, le résumé de l'exécution affiche l'adresse du site. Tant que l'étape 3 n'est pas faite, le workflow construit quand même le site à chaque fusion, pour détecter les erreurs, et se termine avec l'avis *GitHub Pages not enabled* au lieu d'échouer.

## Ce que fait le workflow

Il s'exécute à chaque push sur `master`, après chaque exécution réussie d'Auto-merge ou de Dependabot auto-merge (voir [CI et fusion automatique](/docs/ci-auto-merge)), et à la demande. Deux exécutions ne se chevauchent jamais.

1. **Vérification** : demande à l'API GitHub si Pages est activé avec la source *GitHub Actions*.
2. **Chemin de base** : `/<dépôt>` et l'adresse `https://<propriétaire>.github.io/<dépôt>`, ou la racine de votre domaine personnalisé.
3. **Bundle navigateur** : `cargo build -p securite-site --lib --target wasm32-unknown-unknown --profile wasm-release`, puis `wasm-bindgen --target web` (l'outil en ligne de commande précompilé, de la version verrouillée dans `Cargo.lock`).
4. **Export** : `BASE_PATH=/Securite SITE_URL=https://maxlestage.github.io/Securite cargo run --release -p securite-server -- export dist`. Le serveur rend chaque page avec son propre code (3 langues × page d'accueil, hub de documentation, 33 pages de documentation et playground), tous les liens sous le chemin de base, et écrit le manifeste d'application web, le service worker, `sitemap.xml`, `robots.txt`, `404.html`, `.nojekyll`, la feuille de style, les icônes et le bundle WebAssembly.
5. **Déploiement** : `actions/upload-pages-artifact` puis `actions/deploy-pages`, dans l'environnement `github-pages`.

## Sécurité sur un hébergement statique

GitHub Pages ne permet pas d'envoyer d'en-têtes HTTP : l'export écrit donc dans chaque page ce que le HTML autorise, juste après `<meta charset>` :

| Protection | Comment |
|---|---|
| Content-Security-Policy | `<meta http-equiv>` avec `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `worker-src 'self'`, `manifest-src 'self'` et les mêmes `script-src` et `style-src` stricts que le serveur |
| Scripts et style inline | le chargeur WebAssembly, l'enregistrement du service worker et le petit style d'active sont autorisés par leurs hashes SHA-256, calculés pour chaque page pendant l'export, jamais avec `'unsafe-inline'` |
| WebAssembly | uniquement `'wasm-unsafe-eval'`, jamais `'unsafe-eval'` |
| Referrer-Policy | `<meta name="referrer" content="strict-origin-when-cross-origin">` |
| HTTPS | imposé par GitHub Pages (cochez **Enforce HTTPS** dans Settings → Pages) |

> **Attention :** certaines protections n'existent que sous forme d'en-têtes HTTP : `frame-ancestors` (clickjacking), HSTS, `X-Content-Type-Options`, COOP et CORP. Un navigateur les ignore dans une balise `<meta>`. Pour une application qui traite des données d'utilisateurs, servez-la avec le serveur Vitesse et le `Shield` de securite, comme sur Heroku.

## Adresses et usage hors ligne

Chaque page est un vrai fichier HTML, par exemple `/Securite/fr/docs/waf/index.html` : les liens vers n'importe quelle page répondent 200 avec des balises SEO complètes (adresse canonique, versions dans les autres langues, Open Graph, JSON-LD), et `sitemap.xml` liste toutes les pages dans toutes les langues. `/Securite/` propose les trois langues et ouvre le site en anglais (le serveur, lui, choisit la langue d'après le navigateur) ; les adresses inconnues reçoivent `404.html`.

La copie est une Progressive Web App : le navigateur propose de l'installer, et son service worker, limité à `/Securite/`, garde pour l'usage hors ligne les pages d'accueil, les hubs de documentation, la feuille de style et le bundle WebAssembly, ainsi que chaque page lue. Un nouveau déploiement change la version du worker, qui remplace alors les anciens fichiers.

## Domaine personnalisé

1. Dans votre DNS, ajoutez un enregistrement `CNAME` qui fait pointer `www.example.com` vers `<propriétaire>.github.io`.
2. Settings → Pages → **Custom domain** → saisissez le domaine → **Save**, puis cochez **Enforce HTTPS** quand le certificat est prêt.
3. Relancez le workflow : il détecte le domaine personnalisé et exporte le site pour la racine du domaine.

## Dépannage

| Symptôme | Solution |
|---|---|
| Avis *GitHub Pages not enabled* | Choisissez **GitHub Actions** dans Settings → Pages → Source, puis relancez le workflow |
| `Branch "…" is not allowed to deploy to github-pages` | Settings → Environments → `github-pages` → autorisez la branche `master` |
| Page sans style, 404 sur le `.css`, le `.js` ou le `.wasm` | Le chemin de base ne correspond pas à l'adresse : vérifiez le domaine personnalisé, puis relancez le workflow |
| Le playground affiche le message d'hébergement statique | Normal sur Pages : déployez le serveur sur [Heroku](/docs/heroku-from-phone) pour la démo en direct |

## Pages liées

- [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)
- [Image Docker](/docs/docker)
- [CI et fusion automatique](/docs/ci-auto-merge)
- [En-têtes de sécurité](/docs/security-headers)
