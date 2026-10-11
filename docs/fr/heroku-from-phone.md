---
title: Déployer sur Heroku depuis votre téléphone
summary: Mettez le site securite en ligne sans ordinateur, avec le bouton Deploy en un geste, GitHub Actions à chaque fusion ou l'intégration GitHub de Heroku.
category: deploy
order: 1
---

Le dépôt contient tout ce dont Heroku a besoin : un `Dockerfile`, un `heroku.yml` pour la stack container et un `app.json` pour le bouton Deploy. Toutes les étapes ci-dessous se font depuis un navigateur mobile ou l'application GitHub. Les libellés cités sont ceux des interfaces en anglais.

## Avant de commencer

* Un compte Heroku **vérifié**, c'est-à-dire avec un moyen de paiement enregistré. Heroku n'a plus de dynos gratuits : l'application tourne sur un dyno payant (Eco, Basic ou supérieur), consultez donc d'abord la [page des tarifs de Heroku](https://www.heroku.com/pricing). Les dynos Eco se mettent en veille sans trafic : la première visite après une pause est lente.
* Pour les méthodes B et C, un accès en écriture au dépôt GitHub ou à votre fork.

## Méthode A, le bouton Deploy

1. Ouvrez le lien Deploy to Heroku, ou touchez le bouton **Deploy to Heroku** du README, et connectez-vous à Heroku.
2. Choisissez un **App name** : lettres minuscules, chiffres et tirets, unique sur tout Heroku. Choisissez une région.
3. Conservez les variables de configuration préremplies par `app.json` :
   * `SECURITE_ENV=production` active la redirection HTTPS, HSTS et `upgrade-insecure-requests`, et lit l'IP du client dans l'en-tête `X-Forwarded-For` de Heroku.
   * `RUST_LOG=info` est le filtre de journalisation ; les événements de sécurité utilisent la cible `securite`.
4. Touchez **Deploy app**. Comme `app.json` déclare `"stack": "container"`, Heroku construit l'image décrite par `heroku.yml`, c'est-à-dire le `Dockerfile` du dépôt. Le premier build prend environ 10 à 15 minutes, car tout le code Rust est compilé à partir de zéro.
5. Une fois le build terminé, touchez **View** pour ouvrir le site.

Une application créée avec le bouton est un instantané : les commits suivants ne sont pas déployés. Mettez en place la méthode B avec le même nom d'application pour la tenir à jour.

## Méthode B, GitHub Actions à chaque fusion

C'est la méthode recommandée pour la livraison continue : `.github/workflows/deploy.yml` déploie `master` sur Heroku.

### Copier la clé d'API Heroku

1. Dans le navigateur mobile, ouvrez le tableau de bord Heroku, touchez votre avatar, puis **Account settings**.
2. Faites défiler jusqu'à **API Key**, touchez **Reveal** et copiez la clé. Si la page est tronquée, passez le navigateur en mode « version pour ordinateur ».

> **Astuce :** pour garder votre clé principale privée, créez un jeton dédié dans **Account settings** → **Applications** → **Authorizations** → **Create authorization**.

### Ajouter les secrets du dépôt

L'application GitHub ne permet pas de modifier les secrets : utilisez le navigateur mobile.

1. Ouvrez le dépôt sur github.com et touchez **Settings** (en mode « version pour ordinateur » si l'onglet est masqué).
2. **Secrets and variables** → **Actions** → **New repository secret**.
3. Créez `HEROKU_API_KEY` avec la clé.
4. Créez `HEROKU_APP_NAME` avec un nom unique, par exemple `securite-votrenom`. Une variable de dépôt portant ce nom fonctionne aussi.

### Ce que fait chaque exécution

Le workflow démarre à chaque push sur `master`, après chaque exécution réussie d'Auto-merge (voir [CI et fusion automatique](/docs/ci-auto-merge)), et à la demande. Deux exécutions ne se chevauchent jamais.

Toute la CI (tests, lints, build du site) est d'abord relancée sur `master` ; rien n'est déployé si elle n'est pas verte. Ensuite :

1. **Check configuration** : s'il manque un secret, l'exécution se termine avec l'avis *Heroku deploy skipped*, et non en échec.
2. **Prepare the Heroku app** : crée l'application si elle n'existe pas, règle sa stack sur `container`, et définit `SECURITE_ENV=production` sauf si la variable existe déjà.
3. **Push to Heroku** : un `git push --force` de `master` vers le dépôt Git Heroku de l'application. Heroku construit l'image avec `heroku.yml`.
4. **Smoke test** : interroge `/api/health` toutes les 10 secondes pendant 5 minutes au plus, puis affiche les en-têtes CSP, HSTS et d'identifiant de requête.

Pour déployer à la main : application GitHub → dépôt → **Actions** → **Deploy to Heroku** → **Run workflow**.

## Méthode C, l'intégration GitHub de Heroku

1. Tableau de bord Heroku → votre application → **Deploy** → **Deployment method** → **GitHub** → **Connect to GitHub**, puis autorisez Heroku.
2. Recherchez le dépôt et touchez **Connect**.
3. Sous **Automatic deploys**, choisissez `master`, puis **Enable Automatic Deploys**. **Manual deploy** → **Deploy Branch** lance un premier build.

> **Attention :** la stack de l'application doit être `container`, sinon Heroku ignore `heroku.yml` et cherche un buildpack. Les méthodes A et B la règlent pour vous ; sinon, il faut lancer `heroku stack:set container` depuis la CLI Heroku, ce qui exige un ordinateur. Préférez A ou B, et ne combinez jamais B et C sur une même application : chaque fusion déclencherait deux builds.

## Vérifier le déploiement

1. Touchez **Open app** dans le tableau de bord, ou ouvrez l'URL affichée par le smoke test. Les nouvelles applications reçoivent une adresse du type `https://<name>-<random>.herokuapp.com`.
2. `/api/health` répond `ok` ; `/api/stats` renvoie les compteurs du bouclier en JSON.
3. Consultez les en-têtes de réponse dans le journal de l'étape **Smoke test**, ou avec un analyseur en ligne comme [securityheaders.com](https://securityheaders.com).
4. Ouvrez la page **Playground** et attaquez le site : le WAF bloque les charges malveillantes et les compteurs évoluent.

## Journaux

Tableau de bord Heroku → votre application → **More** → **View logs**. Les requêtes bloquées apparaissent sous forme de lignes `WARN` avec la cible `securite` :

```text
app[web.1]: 2026-10-10T08:12:44.913245Z  WARN securite: request blocked guard="waf" code="waf_blocked" status=403 ip=Some(203.0.113.7) method=GET path="/api/demo" request_id="3f2b8c1e-9a4d-4f6b-8e21-7c5d0a9b1e44"
```

Pour changer le niveau de détail, modifiez `RUST_LOG` dans **Settings** → **Reveal Config Vars**, par exemple `warn,securite=info`. L'enregistrement redémarre l'application. Voir [Événements de sécurité](/docs/events-stats).

## Domaine personnalisé

1. **Settings** → **Domains** → **Add domain**, par exemple `www.example.com`. Heroku affiche une cible DNS.
2. Chez votre fournisseur DNS, créez un enregistrement `CNAME` de `www` vers cette cible (`ALIAS` ou `ANAME` pour un domaine nu).
3. **Settings** → **SSL Certificates** : activez Automated Certificate Management, et Heroku émet puis renouvelle le certificat. La disponibilité dépend du type de dyno.

> **Attention :** le mode production envoie HSTS avec `includeSubDomains` pour deux ans : l'hôte et ses sous-domaines doivent continuer à servir du HTTPS. Avec un proxy CDN devant Heroku, changez la source d'IP client dans `server/src/main.rs` (voir [IP du client](/docs/client-ip)).

## Dépannage

| Symptôme | Cause et solution |
|---|---|
| Le build dure 10 à 15 minutes | Normal : chaque crate Rust est compilée en mode release. Suivez le journal de build jusqu'au bout. |
| `H10 App crashed` | Le processus s'est arrêté au démarrage. Lisez les lignes de journal juste avant, corrigez la cause, puis **More** → **Restart all dynos**. |
| `R10 Boot timeout` | Rien n'écoutait sur `$PORT`. Heroku définit `PORT` à chaque démarrage et le serveur le lit : ne codez jamais un port en dur dans `main.rs` ou le `Dockerfile`. |
| Avis *Heroku deploy skipped* | `HEROKU_API_KEY` ou `HEROKU_APP_NAME` manque ou est mal orthographié. Utilisez des secrets de dépôt, pas des secrets d'environnement. |
| `Name is already taken` | Les noms d'application sont globaux : choisissez-en un autre. |
| Le smoke test échoue | Dans **Resources**, vérifiez que le dyno `web` est activé, puis lisez les journaux. |
| `401` pendant la préparation de l'application | La clé d'API a changé : mettez le secret à jour. |

## Pages associées

* [Image Docker](/docs/docker)
* [CI et fusion automatique](/docs/ci-auto-merge)
* [Redirection HTTPS](/docs/https-redirect)
* [IP du client](/docs/client-ip)
