---
title: Déployer sur GitHub Pages
summary: Publiez gratuitement le site sur GitHub Pages grâce à un workflow GitHub Actions, configuré une fois depuis votre téléphone puis mis à jour à chaque fusion sur master.
category: deploy
order: 2
---

`.github/workflows/pages.yml` construit le site Yew + WebAssembly et le publie sur GitHub Pages à l'adresse `https://<propriétaire>.github.io/<dépôt>/` (pour ce dépôt : `https://maxlestage.github.io/Securite/`). C'est gratuit pour les dépôts publics et aucun secret n'est nécessaire.

GitHub Pages est un hébergement statique. La page d'accueil animée, le hub de documentation et toutes les pages de documentation fonctionnent exactement comme sur Heroku. Le playground d'attaques et les statistiques en direct ont besoin du serveur axum : sur Pages, ils affichent un court message à la place. Utilisez [Heroku](/docs/heroku-from-phone) ou [Docker](/docs/docker) pour la démo complète.

## Configuration unique depuis votre téléphone

1. Ouvrez le dépôt dans un navigateur mobile et touchez **Settings** (passez en affichage ordinateur si l'onglet est masqué).
2. Touchez **Pages** dans le menu latéral.
3. Sous **Build and deployment**, choisissez **GitHub Actions** comme **Source**.
4. Application GitHub → dépôt → **Actions** → **Deploy to GitHub Pages** → **Run workflow**.

Environ trois minutes plus tard, le résumé de l'exécution affiche l'adresse du site. Tant que l'étape 3 n'est pas faite, le workflow construit quand même le site à chaque fusion, pour détecter les erreurs, et se termine avec l'avis *GitHub Pages not enabled* au lieu d'échouer.

## Ce que fait le workflow

Il s'exécute à chaque push sur `master`, après chaque exécution réussie d'Auto-merge ou de Dependabot auto-merge (voir [CI et fusion automatique](/docs/ci-auto-merge)), et à la demande. Deux exécutions ne se chevauchent jamais.

1. **Vérification** : demande à l'API GitHub si Pages est activé avec la source *GitHub Actions*.
2. **Chemin de base** : `/<dépôt>/`, ou `/` si vous avez configuré un domaine personnalisé.
3. **Build** : `SITE_BASE=/Securite/ trunk build --release --public-url /Securite/`. `SITE_BASE` est lu à la compilation : le routeur, les fichiers de documentation et les appels d'API vivent tous sous le sous-chemin.
4. **Durcissement** : `.github/scripts/pages-postprocess.py` ajoute les en-têtes de sécurité qu'un hébergement statique peut porter, copie `index.html` vers `404.html` et ajoute `.nojekyll`.
5. **Déploiement** : `actions/upload-pages-artifact` puis `actions/deploy-pages`, dans l'environnement `github-pages`.

## Sécurité sur un hébergement statique

GitHub Pages ne permet pas d'envoyer d'en-têtes HTTP : l'étape de post-traitement injecte donc ce que le HTML autorise, juste après `<meta charset>` :

| Protection | Comment |
|---|---|
| Content-Security-Policy | `<meta http-equiv>` avec `default-src 'self'`, `object-src 'none'`, `base-uri 'self'` et le même `script-src` strict que le serveur |
| Script d'amorçage inline | autorisé par son hash SHA-256, calculé après `trunk build`, jamais avec `'unsafe-inline'` |
| WebAssembly | uniquement `'wasm-unsafe-eval'`, jamais `'unsafe-eval'` |
| Referrer-Policy | `<meta name="referrer" content="strict-origin-when-cross-origin">` |
| HTTPS | imposé par GitHub Pages (cochez **Enforce HTTPS** dans Settings → Pages) |

> **Attention :** certaines protections n'existent que sous forme d'en-têtes HTTP : `frame-ancestors` (clickjacking), HSTS, `X-Content-Type-Options`, COOP et CORP. Un navigateur les ignore dans une balise `<meta>`. Pour une application qui traite des données d'utilisateurs, servez-la avec le serveur axum et le `Shield` de securite, comme sur Heroku.

## Liens directs

Une application monopage n'a qu'un seul fichier HTML. Quand quelqu'un ouvre directement `/Securite/docs/waf`, GitHub Pages ne trouve pas ce fichier et sert `404.html`, qui est une copie de `index.html` : l'application démarre et le routeur affiche la bonne page. Les navigateurs affichent la page normalement. Seul le statut HTTP vaut 404, ce qui compte pour les moteurs de recherche, pas pour les lecteurs.

## Domaine personnalisé

1. Dans votre DNS, ajoutez un enregistrement `CNAME` qui fait pointer `www.example.com` vers `<propriétaire>.github.io`.
2. Settings → Pages → **Custom domain** → saisissez le domaine → **Save**, puis cochez **Enforce HTTPS** quand le certificat est prêt.
3. Relancez le workflow : il détecte le domaine personnalisé et construit le site pour le chemin de base `/`.

## Dépannage

| Symptôme | Solution |
|---|---|
| Avis *GitHub Pages not enabled* | Choisissez **GitHub Actions** dans Settings → Pages → Source, puis relancez le workflow |
| `Branch "…" is not allowed to deploy to github-pages` | Settings → Environments → `github-pages` → autorisez la branche `master` |
| Page blanche, 404 sur le `.wasm` ou le `.js` | Le chemin de base ne correspond pas à l'adresse : vérifiez le domaine personnalisé, puis relancez le workflow |
| Le playground affiche le message d'hébergement statique | Normal sur Pages : déployez le serveur sur [Heroku](/docs/heroku-from-phone) pour la démo en direct |

## Pages liées

- [Déployer sur Heroku depuis votre téléphone](/docs/heroku-from-phone)
- [Image Docker](/docs/docker)
- [CI et fusion automatique](/docs/ci-auto-merge)
- [En-têtes de sécurité](/docs/security-headers)
