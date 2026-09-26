output "db_endpoint" {
  description = "RDS Postgres endpoint hostname."
  value       = aws_db_instance.this.address
}

output "db_port" {
  description = "RDS Postgres port."
  value       = aws_db_instance.this.port
}

output "redis_endpoint" {
  description = "ElastiCache primary endpoint hostname."
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "secrets_manager_secret_arn" {
  description = "ARN of the Secrets Manager bundle."
  value       = aws_secretsmanager_secret.app.arn
}

# ---- Sensitive values consumed by the app (Helm) module -------------------

output "database_url" {
  value     = local.role_dsns["weissman_app"]
  sensitive = true
}

output "auth_database_url" {
  value     = local.role_dsns["weissman_auth"]
  sensitive = true
}

output "worker_database_url" {
  value     = local.role_dsns["weissman_worker"]
  sensitive = true
}

output "analytics_database_url" {
  value     = local.role_dsns["weissman_analytics"]
  sensitive = true
}

output "migrate_url" {
  value     = local.migrate_url
  sensitive = true
}

output "redis_url" {
  value     = local.redis_url
  sensitive = true
}

output "jwt_secret" {
  value     = random_password.jwt_secret.result
  sensitive = true
}

output "integrations_vault_key" {
  value     = random_password.integrations_vault_key.result
  sensitive = true
}

output "vault_key" {
  value     = random_bytes.vault_key.hex
  sensitive = true
}

output "rag_provenance_secret" {
  value     = random_bytes.rag_provenance.hex
  sensitive = true
}

output "destructive_confirm_secret" {
  value     = random_password.destructive_confirm.result
  sensitive = true
}

output "job_orchestrator_secret" {
  value     = random_password.job_orchestrator.result
  sensitive = true
}

output "metrics_token" {
  value     = random_password.metrics_token.result
  sensitive = true
}
