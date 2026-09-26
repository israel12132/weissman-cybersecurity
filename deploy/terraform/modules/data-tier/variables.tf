variable "customer_name" {
  type        = string
  description = "DNS-label-safe customer id; used to name RDS/ElastiCache/Secrets Manager resources."
}

variable "vpc_id" {
  type        = string
  description = "Existing customer VPC id."
}

variable "db_subnet_ids" {
  type        = list(string)
  description = "Subnet ids for the RDS DB subnet group (>=2 AZs)."
}

variable "redis_subnet_ids" {
  type        = list(string)
  description = "Subnet ids for the ElastiCache subnet group; falls back to db_subnet_ids when empty."
  default     = []
}

variable "app_security_group_ids" {
  type        = list(string)
  description = "Security groups allowed to reach RDS (5432) and Redis (6379)."
  default     = []
}

variable "db_allowed_cidr_blocks" {
  type        = list(string)
  description = "Extra CIDRs allowed to reach RDS (5432) and Redis (6379)."
  default     = []
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class."
}

variable "db_allocated_storage" {
  type        = number
  description = "RDS allocated storage in GiB."
}

variable "db_max_allocated_storage" {
  type        = number
  description = "RDS storage-autoscaling ceiling in GiB; null disables autoscaling."
  default     = null
}

variable "db_engine_version" {
  type        = string
  description = "RDS Postgres engine version."
  default     = "16"
}

variable "db_name" {
  type        = string
  description = "Initial database name."
  default     = "weissman"
}

variable "db_master_username" {
  type        = string
  description = "RDS master/owner username (used for migrate_url and to bootstrap the RLS roles)."
  default     = "wzadmin"
}

variable "db_multi_az" {
  type        = bool
  description = "Provision RDS as Multi-AZ."
  default     = true
}

variable "db_backup_retention_days" {
  type        = number
  description = "RDS automated backup retention in days."
  default     = 14
}

variable "db_deletion_protection" {
  type        = bool
  description = "Enable RDS deletion protection."
  default     = true
}

variable "db_skip_final_snapshot" {
  type        = bool
  description = "Skip the final snapshot on RDS destroy."
  default     = false
}

variable "db_kms_key_id" {
  type        = string
  description = "KMS key for RDS storage encryption; null uses the default aws/rds key."
  default     = null
}

variable "redis_node_type" {
  type        = string
  description = "ElastiCache node type."
}

variable "redis_engine_version" {
  type        = string
  description = "ElastiCache Redis engine version."
  default     = "7.1"
}

variable "redis_num_nodes" {
  type        = number
  description = "Number of Redis nodes (>=2 enables automatic failover + Multi-AZ)."
  default     = 2
}

variable "redis_transit_encryption_enabled" {
  type        = bool
  description = "Enable in-transit TLS + AUTH token on Redis."
  default     = true
}

variable "redis_snapshot_retention_days" {
  type        = number
  description = "ElastiCache snapshot retention in days (0 disables)."
  default     = 7
}

variable "secrets_manager_kms_key_id" {
  type        = string
  description = "KMS key for the Secrets Manager bundle; null uses the default aws/secretsmanager key."
  default     = null
}

variable "secret_recovery_window_days" {
  type        = number
  description = "Secrets Manager recovery window in days."
  default     = 7
}

variable "tags" {
  type        = map(string)
  description = "Additional tags merged onto every AWS resource."
  default     = {}
}
