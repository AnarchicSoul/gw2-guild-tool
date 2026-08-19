# GW2 Guild Tool

Petit outil pour les membres d'une guilde Guild Wars 2 : chacun lie son compte via sa clé API officielle, et l'app détecte automatiquement les autres membres inscrits qui partagent une même guilde — sans jamais qu'un utilisateur ait à échanger sa clé avec qui que ce soit.

100% sur les tiers gratuits : Cloudflare Workers + D1 + Pages, GitHub Actions, Terraform Cloud.

## Architecture

```
┌─────────────┐        Bearer token         ┌──────────────────┐
│   GUI        │ ───────────────────────────▶│  Cloudflare       │
│ (GitHub      │                              │  Worker (API)     │
│  Pages,      │◀─── JSON ────────────────────│  api/src/index.js │
│  statique)   │                              └─────────┬─────────┘
└──────┬───────┘                                        │
       │ appel direct                                   │ D1 (SQL)
       ▼                                                 ▼
┌─────────────┐                              ┌──────────────────┐
│ api.guildwars2  │                          │  D1 (SQLite)      │
│    .com          │                          │  comptes, clés    │
└─────────────┘                              │  chiffrées, guildes│
                                              └──────────────────┘
```

- **`gui/`** — page statique (HTML/CSS/JS vanilla, aucune dépendance), déployée sur GitHub Pages.
- **`api/`** — Worker Cloudflare, code déployé via `wrangler`.
- **`terraform/`** — infrastructure Cloudflare (D1, Worker, bindings, observabilité) pilotée depuis GitHub Actions, state distant sur Terraform Cloud.

## Décisions techniques notables

**L'API Guild Wars 2 est appelée depuis le navigateur, jamais depuis le Worker.**
Les Workers Cloudflare sortent via des IP mutualisées entre des milliers de comptes ; l'API GW2 rate-limite (au moins en partie) par IP source, ce qui provoquait des 429 sans rapport avec l'usage réel de l'app. Le navigateur de chaque utilisateur, lui, part de sa propre IP — exactement comme n'importe quel client GW2 normal. Le Worker fait donc confiance aux infos rapportées par le client (id/nom/guildes) plutôt que de les revérifier lui-même : compromis assumé et documenté dans le code, acceptable pour un outil entre membres de confiance d'une même guilde.

**Auth par token Bearer, pas par cookie.**
La GUI et l'API vivent sur deux origines différentes (GitHub Pages / `workers.dev`). Les cookies tiers `SameSite=None` sont de plus en plus restreints par les navigateurs (Safari ITP, etc.) indépendamment de leur `Max-Age` côté serveur. Le token de session est donc renvoyé dans le corps JSON à la connexion, stocké en `localStorage`, et envoyé via un header `Authorization: Bearer`.

**Mots de passe en PBKDF2-SHA256, 100 000 itérations.**
C'est le plafond dur du runtime Cloudflare Workers pour `crypto.subtle.deriveBits` (`NotSupportedError` au-delà), quel que soit le plan — pas un choix de compromis, la limite maximale disponible sur cette plateforme.

**Clés API GW2 chiffrées en AES-256-GCM** avant stockage en base, avec la clé de chiffrement en secret Worker (jamais dans le code ni dans le state Terraform en clair).

**Terraform gère l'infrastructure, `wrangler` gère le code.**
Le state Terraform vit sur Terraform Cloud (workspace en exécution distante) — seul le dossier `terraform/` est envoyé aux runners, donc le contenu du Worker ne peut pas y être référencé en relatif. Le `cloudflare_workers_script` est créé avec un contenu placeholder et un `lifecycle.ignore_changes` sur les champs de code : Terraform possède les bindings, l'observabilité, la config — jamais le contenu applicatif, qui reste sous le contrôle exclusif de `wrangler deploy` en CI.

**Observabilité et analytics, tout en free tier.**
Logs + traces via `observability` (Workers Logs, 200k events/jour), et un dataset **Workers Analytics Engine** (`gw2_guild_tool_events`, 100k points/jour) qui suit les événements métier (inscriptions, connexions, liaisons GW2 réussies/échouées, requêtes de matching) via `writeDataPoint()` fire-and-forget — interrogeable en SQL via `/accounts/{id}/analytics_engine/sql` ou le dashboard Cloudflare.

## Stack

| Composant | Techno |
|---|---|
| API | Cloudflare Workers (JS, modules ES) |
| Base de données | Cloudflare D1 (SQLite) |
| Analytics | Cloudflare Workers Analytics Engine |
| Frontend | HTML/CSS/JS vanilla, aucun framework |
| Hébergement frontend | GitHub Pages |
| Infra as Code | Terraform (provider `cloudflare/cloudflare` ~5.0) |
| State Terraform | Terraform Cloud (remote execution) |
| CI/CD | GitHub Actions |

## Développement local

```bash
cd api
npm install
npx wrangler dev          # API en local
npx wrangler d1 execute gw2-guild-tool-dev --remote --file=./schema.sql
```

La GUI (`gui/index.html`) est un fichier statique : ouvrable directement dans un navigateur, aucun build nécessaire.

## Déploiement

Automatique sur push vers `main`/`master` via `.github/workflows/deploy.yml` :

1. **Terraform** applique l'infra Cloudflare (D1, Worker, bindings, observabilité) via Terraform Cloud
2. **`wrangler`** déploie le code du Worker et applique le schéma D1
3. **GitHub Pages** publie `gui/`

Secrets requis (Settings → Secrets and variables → Actions) :

| Nom | Description |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Permissions : Account → D1 → Edit, Account → Workers Scripts → Edit |
| `GW2_ENCRYPTION_KEY` | Clé AES-256 en base64, pour chiffrer les clés API GW2 stockées |
| `TF_API_TOKEN` | User API Token Terraform Cloud |

Et une variable (non sensible) : `CLOUDFLARE_ACCOUNT_ID`.
