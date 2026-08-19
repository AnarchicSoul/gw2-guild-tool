variable "cloudflare_api_token" {
  description = "Cloudflare API token (permissions: Account > D1 > Edit, Account > Workers Scripts > Edit)"
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID (dashboard sidebar, or `wrangler whoami`)"
  type        = string
}

variable "environment" {
  description = "Environment name, used as a suffix for resource names"
  type        = string
  default     = "dev"
}

variable "encryption_key" {
  description = "Clé AES-256 (base64) utilisée par le Worker pour chiffrer les clés API GW2 stockées en base"
  type        = string
  sensitive   = true
}
