# Documentation format

Every page exists in three languages: `docs/en/<slug>.md`, `docs/fr/<slug>.md`, `docs/es/<slug>.md`.
The website (`site/build.rs`) compiles them to HTML at build time.

```markdown
---
title: Rate limiting
summary: One sentence shown on cards and in search results.
category: traffic
order: 1
---

Intro paragraph (no `#` title: the title comes from the front matter).

## Section

### Sub-section
```

* Categories: `start`, `browser`, `traffic`, `access`, `threats`, `integrity`, `everyday` (the `pratique` crate), `deploy`.
* Only `##` and `###` headings (they build the on-page table of contents).
* Code fences must declare a language: `rust`, `toml`, `bash`, `json`, `yaml`, `text`.
* Links to other pages: `/docs/<slug>`.
* Callouts: a blockquote starting with `**Tip:**`, `**Warning:**` (FR: `**Astuce :**`, `**Attention :**`; ES: `**Consejo:**`, `**Atención:**`).
