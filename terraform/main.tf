terraform {
  required_version = ">= 1.9"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }

  cloud {
    organization = "johanduval"

    workspaces {
      name = "gw2_guild_tool"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# Base de données SQLite (comptes, clés API chiffrées, appartenance aux guildes)
resource "cloudflare_d1_database" "gw2_guild_db" {
  account_id = var.cloudflare_account_id
  name       = "gw2-guild-tool-${var.environment}"

  # Fixé explicitement : sans ça, le provider tente de repasser ce champ à
  # null à chaque apply (bug de drift), ce que l'API Cloudflare rejette (400).
  read_replication = {
    mode = "disabled"
  }
}

# Worker qui expose l'API. Terraform s'exécute à distance sur HCP Terraform
# (workspace en mode "Remote") : seul le dossier terraform/ est envoyé aux
# runners, donc impossible d'y référencer ../api/src/index.js. Terraform gère
# ici uniquement l'infra (bindings, observability, compat date) ; le contenu
# réel du script est déployé séparément via `wrangler deploy` (voir
# api/wrangler.toml et le workflow GitHub Actions) — d'où le contenu
# placeholder ci-dessous et le lifecycle qui l'ignore pour ne jamais écraser
# ce que wrangler a déployé.
resource "cloudflare_workers_script" "gw2_guild_api" {
  account_id  = var.cloudflare_account_id
  script_name = "gw2-guild-api-${var.environment}"
  main_module    = "placeholder-worker.js"
  content_file   = "${path.module}/placeholder-worker.js"
  content_sha256 = filesha256("${path.module}/placeholder-worker.js")

  compatibility_date = "2026-08-01"

  # Workers Logs (gratuit : 200k events/jour, rétention 3 jours) — permet de
  # voir les console.log() en direct via le dashboard ou `wrangler tail`.
  observability = {
    enabled = true
    logs = {
      enabled         = true
      invocation_logs = true
    }
    traces = {
      enabled = true
    }
  }

  bindings = [
    {
      name        = "DB"
      type        = "d1"
      database_id = cloudflare_d1_database.gw2_guild_db.id
    },
    {
      name = "ENCRYPTION_KEY"
      type = "secret_text"
      text = var.encryption_key
    }
  ]

  lifecycle {
    ignore_changes = [content, content_sha256, content_file, main_module]
  }

  # Note : `tail_consumers` réapparaît en diff "known after apply" à chaque
  # plan même sans changement réel (quirk connu du provider Cloudflare sur ce
  # champ calculé) — un `apply` dessus est un no-op, sans danger.
}

# Expose le Worker sur *.workers.dev (gratuit, pas de domaine requis)
resource "cloudflare_workers_script_subdomain" "gw2_guild_api_subdomain" {
  account_id  = var.cloudflare_account_id
  script_name = cloudflare_workers_script.gw2_guild_api.script_name
  enabled     = true
}
