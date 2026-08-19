output "d1_database_id" {
  value       = cloudflare_d1_database.gw2_guild_db.id
  description = "À reporter dans api/wrangler.toml (champ database_id)"
}

output "d1_database_name" {
  value = cloudflare_d1_database.gw2_guild_db.name
}

output "worker_script_name" {
  value       = cloudflare_workers_script.gw2_guild_api.script_name
  description = "URL exacte visible dans le dashboard Cloudflare (Workers & Pages) : https://<script_name>.<ton-sous-domaine-workers>.workers.dev"
}
