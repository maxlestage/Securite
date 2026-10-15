---
title: Autorisations
summary: Gates, policies et voters dans l'esprit de Laravel et Symfony, refus par défaut, pour décider ce que chaque utilisateur peut faire de chaque ressource.
category: access
order: 7
---

L'authentification vous dit *qui* appelle ; l'autorisation décide *ce qu'il* peut faire, et sur *quel* enregistrement. `Gate` centralise ces règles : des capacités sans ressource (`"create-post"`), des policies sur un type de ressource (`"edit-post"` sur un `Post`) et des voters qui regroupent les règles d'un domaine. Il réunit `Gate::define` / `Gate::before` de Laravel et les voters et stratégies de décision de Symfony.

## Menaces couvertes

- **A01:2021 Contrôle d'accès défaillant**, le risque web le plus fréquent : références directes non sécurisées à des objets (passer de `/invoices/42` à `/invoices/43`), élévation de privilèges, contrôle oublié dans un handler parmi d'autres (CWE-284, CWE-639, CWE-862).
- **Règles qui échouent ouvertes** : une capacité que personne n'a définie, une ressource d'un type inattendu ou une décision où tous les voters s'abstiennent valent refus.

## Démarrage rapide

```rust
use securite::prelude::*;

struct User { id: u64, admin: bool }
struct Post { author: u64, published: bool }

let gate = Gate::<User>::new()
    // Les administrateurs peuvent tout faire.
    .before(|user, _ability| user.admin.then_some(true))
    .define("create-post", |_user| true)
    .define_for("edit-post", |user, post: &Post| post.author == user.id)
    .define_for("view-post", |user, post: &Post| post.published || post.author == user.id);

// Dans un handler :
let post = load_post(id)?;
gate.authorize_for(&user, "edit-post", &post)?; // Err(Forbidden) en cas de refus
```

Construisez la gate une fois au démarrage et partagez-la (elle est `Clone`, `Send` et `Sync`).

## Comment une décision est prise

1. Les **hooks `before`** passent d'abord, dans l'ordre. `Some(true)` accorde, `Some(false)` refuse (un utilisateur banni), `None` laisse décider les règles.
2. Les **règles** définies pour la capacité votent : les règles `define` ne votent que sans ressource, les règles `define_for::<R>` seulement sur une ressource de type `R`. Sinon elles s'abstiennent.
3. Les **voters** votent pour chaque capacité ; ils s'abstiennent sur ce qu'ils ne gèrent pas.
4. La **stratégie** combine les votes. Si tous s'abstiennent, la réponse est non.

| Stratégie | Accordé quand |
|---|---|
| `Affirmative` (défaut) | au moins un vote accorde |
| `Consensus` | plus de votes accordent que de votes refusent (l'égalité refuse) |
| `Unanimous` | aucun vote ne refuse et au moins un accorde |

## Voters

Un voter regroupe les règles d'un type de ressource, comme un voter Symfony ou une classe policy de Laravel :

```rust
use std::any::Any;
use securite::authz::{Gate, Strategy, Vote, Voter};

struct InvoiceVoter;

impl Voter<User> for InvoiceVoter {
    fn vote(&self, user: &User, ability: &str, resource: Option<&dyn Any>) -> Vote {
        let Some(invoice) = resource.and_then(|r| r.downcast_ref::<Invoice>()) else {
            return Vote::Abstain;
        };
        match ability {
            "invoice.view" => (invoice.owner == user.id).into(),
            "invoice.refund" => (invoice.owner == user.id && !invoice.refunded).into(),
            _ => Vote::Abstain,
        }
    }
}

let gate = Gate::new()
    .voter(InvoiceVoter)
    .voter(AccountFrozenVoter) // refuse tout aux comptes gelés
    .strategy(Strategy::Unanimous);
```

Avec `Unanimous`, un seul `Deny` l'emporte sur n'importe quel nombre d'accords, ce qui convient à des règles comme « un compte gelé ne peut rien faire ».

## Refus

`authorize` et `authorize_for` renvoient `Result<(), Forbidden>`. `Forbidden::into_rejection()` transforme l'erreur en [réponse problem](/docs/error-format) `403` avec le code `forbidden` ; la capacité refusée est journalisée dans les détails et jamais envoyée au client. Vous pouvez aussi convertir `Forbidden` en votre propre type d'erreur, ou répondre `404` plutôt que `403` pour cacher l'existence d'un enregistrement.

## API

| Méthode | Description |
|---|---|
| `Gate::new()` | Gate vide : tout est refusé. |
| `.before(f)` | `Fn(&U, &str) -> Option<bool>` exécuté avant les règles. |
| `.define(ability, f)` | `Fn(&U) -> bool`, pour les capacités sans ressource. |
| `.define_for(ability, f)` | `Fn(&U, &R) -> bool`, pour les capacités sur une ressource de type `R`. |
| `.voter(v)` | Ajoute un `Voter<U>`. |
| `.strategy(s)` | `Affirmative`, `Consensus` ou `Unanimous`. |
| `.allow_if_all_abstain(b)` | Accorde quand tout le monde s'abstient (désactivé par défaut). |
| `.allows` / `.allows_for` / `.denies` | `bool`. |
| `.any(user, abilities)` / `.all(user, abilities)` | Plusieurs capacités sans ressource. |
| `.authorize` / `.authorize_for` | `Result<(), Forbidden>`. |
| `.abilities()` | Noms des capacités définies. |

## Pièges et conseils

- Vérifiez l'autorisation dans **chaque** handler qui lit ou modifie un enregistrement, API JSON et exports en tâche de fond compris ; chargez d'abord l'enregistrement et passez-le à la gate.
- Le type de ressource doit correspondre exactement : `define_for::<Post>` ne vote pas sur un `&Post` passé comme `&&Post`, ni sur un `Arc<Post>` ; elle s'abstient, ce qui refuse.
- Gardez les hooks `before` courts et explicites : un `Some(true)` trop large est un passe-partout.
- Les règles s'exécutent de façon synchrone : chargez ce dont elles ont besoin (rôles, appartenance à une équipe) avant d'appeler la gate.

## Pages associées

- [Authentification](/docs/auth)
- [Hachage des mots de passe](/docs/passwords)
- [URL signées](/docs/signed-urls)
- [Format des erreurs](/docs/error-format)
