output "namespace" {
  description = "Kubernetes namespace the dedicated instance is installed into."
  value       = local.namespace
}

output "release_name" {
  description = "Helm release name."
  value       = local.release_name
}

output "app_url" {
  description = "Public base URL this instance serves."
  value       = "https://${var.domain}"
}

output "helm_release_status" {
  description = "Status of the Helm release."
  value       = module.app.release_status
}

output "db_endpoint" {
  description = "RDS Postgres endpoint hostname."
  value       = module.data_tier.db_endpoint
}

output "db_port" {
  description = "RDS Postgres port."
  value       = module.data_tier.db_port
}

output "redis_endpoint" {
  description = "ElastiCache primary endpoint hostname."
  value       = module.data_tier.redis_endpoint
}

output "secrets_manager_secret_arn" {
  description = "ARN of the Secrets Manager bundle holding this customer's DSNs and at-rest keys."
  value       = module.data_tier.secrets_manager_secret_arn
}
