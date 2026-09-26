# ---------------------------------------------------------------------------
# Weissman — dedicated (single-tenant) provisioning, root variables.
# See docs/adr/0003-dedicated-single-tenant-tier.md and
#     docs/adr/0004-terraform-dedicated-provisioning.md
# ---------------------------------------------------------------------------

variable "aws_region" {
  type        = string
  description = "AWS region the data tier (RDS/ElastiCache/Secrets Manager) and the EKS cluster live in, e.g. eu-west-1."
}

# ---- Customer identity -----------------------------------------------------

variable "customer_name" {
  type        = string
  description = "DNS-label-safe customer id (a-z, 0-9, '-'); used in the namespace, release name, RDS/ElastiCache identifiers and labels."

  # <=24 so that "weissman-<name>" fits the ElastiCache replication_group_id
  # limit of 40 chars (and the RDS identifier limit of 63).
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.customer_name)) && length(var.customer_name) <= 24
    error_message = "customer_name must be a DNS label (lowercase alphanumeric and '-', not starting/ending with '-', 1-24 chars)."
  }
}

variable "domain" {
  type        = string
  description = "Primary FQDN this instance serves; the ingress host and WEISSMAN_PUBLIC_BASE_URL."

  validation {
    condition     = length(var.domain) > 0
    error_message = "domain is required (e.g. acme.weissmancyber.com)."
  }
}

variable "customer_region_label" {
  type        = string
  description = "Inventory region label applied to chart resources; defaults to aws_region when empty. Label only; does not size anything."
  default     = ""
}

variable "sizing" {
  type        = string
  description = "T-shirt size that drives default replica counts, RDS instance class and ElastiCache node type. One of: small | medium | large."
  default     = "medium"

  validation {
    condition     = contains(["small", "medium", "large"], var.sizing)
    error_message = "sizing must be one of: small, medium, large."
  }
}

# ---- Bring-your-own customer VPC ------------------------------------------

variable "vpc_id" {
  type        = string
  description = "Existing customer VPC id the data tier is provisioned into."
}

variable "db_subnet_ids" {
  type        = list(string)
  description = "Private subnet ids (>=2 AZs) for the RDS DB subnet group."

  validation {
    condition     = length(var.db_subnet_ids) >= 2
    error_message = "db_subnet_ids needs at least two subnets in different AZs for RDS."
  }
}

variable "redis_subnet_ids" {
  type        = list(string)
  description = "Private subnet ids for the ElastiCache subnet group; falls back to db_subnet_ids when empty."
  default     = []
}

variable "app_security_group_ids" {
  type        = list(string)
  description = "Security groups (e.g. the EKS node group SGs) allowed to reach RDS (5432) and Redis (6379)."
  default     = []
}

variable "db_allowed_cidr_blocks" {
  type        = list(string)
  description = "Extra CIDR blocks allowed to reach RDS (5432) and Redis (6379); use sparingly (bastion/VPN)."
  default     = []
}

# ---- Bring-your-own EKS cluster -------------------------------------------

variable "eks_cluster_name" {
  type        = string
  description = "Name of the existing EKS cluster the Helm release is installed into (used to configure the kubernetes/helm providers)."
}

# ---- Application image -----------------------------------------------------

variable "image_repository" {
  type        = string
  description = "Backend/worker image repository."
  default     = "ghcr.io/israel12132/weissman-cybersecurity/weissman-backend"
}

variable "image_digest" {
  type        = string
  description = "Immutable, cosign-verified image digest (e.g. sha256:...). Wins over image_tag; strongly preferred in production."
  default     = ""
}

variable "image_tag" {
  type        = string
  description = "Image tag; used only when image_digest is empty. Falls back to the chart appVersion when both are empty."
  default     = ""
}

# ---- RDS Postgres sizing / config -----------------------------------------

variable "db_instance_class" {
  type        = string
  description = "RDS instance class; when null, derived from `sizing`."
  default     = null
}

variable "db_allocated_storage" {
  type        = number
  description = "RDS allocated storage in GiB; when null, derived from `sizing`."
  default     = null
}

variable "db_max_allocated_storage" {
  type        = number
  description = "RDS storage-autoscaling ceiling in GiB; null disables autoscaling."
  default     = null
}

variable "db_engine_version" {
  type        = string
  description = "RDS Postgres engine version (major-only accepted, resolves to the latest supported minor)."
  default     = "16"
}

variable "db_name" {
  type        = string
  description = "Initial database name."
  default     = "weissman"
}

variable "db_master_username" {
  type        = string
  description = "RDS master/owner username used for the migrate_url DSN and to bootstrap the four RLS roles."
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
  description = "Skip the final snapshot on RDS destroy (leave false in production)."
  default     = false
}

variable "db_kms_key_id" {
  type        = string
  description = "KMS key id/ARN for RDS storage encryption; null uses the default aws/rds key."
  default     = null
}

# ---- ElastiCache Redis sizing / config ------------------------------------

variable "redis_node_type" {
  type        = string
  description = "ElastiCache node type; when null, derived from `sizing`."
  default     = null
}

variable "redis_engine_version" {
  type        = string
  description = "ElastiCache Redis engine version."
  default     = "7.1"
}

variable "redis_num_nodes" {
  type        = number
  description = "Number of Redis nodes in the replication group (>=2 enables automatic failover + Multi-AZ)."
  default     = 2

  validation {
    condition     = var.redis_num_nodes >= 1
    error_message = "redis_num_nodes must be >= 1."
  }
}

variable "redis_transit_encryption_enabled" {
  type        = bool
  description = "Enable in-transit TLS + AUTH token on Redis (redis_url becomes rediss://). Disable only if the Redis client cannot do TLS."
  default     = true
}

variable "redis_snapshot_retention_days" {
  type        = number
  description = "ElastiCache snapshot retention in days (0 disables snapshots)."
  default     = 7
}

# ---- Secrets Manager -------------------------------------------------------

variable "secrets_manager_kms_key_id" {
  type        = string
  description = "KMS key id/ARN encrypting the Secrets Manager bundle; null uses the default aws/secretsmanager key."
  default     = null
}

variable "secret_recovery_window_days" {
  type        = number
  description = "Secrets Manager recovery window in days (0 forces immediate deletion; 7-30 otherwise)."
  default     = 7
}

# ---- Helm release / app ----------------------------------------------------

variable "release_name" {
  type        = string
  description = "Helm release name; defaults to weissman-<customer_name>."
  default     = ""
}

variable "namespace_override" {
  type        = string
  description = "Kubernetes namespace; defaults to weissman-<customer_name>. MUST match the chart's computed namespace."
  default     = ""
}

variable "backend_replica_count" {
  type        = number
  description = "Backend replica count; when null, derived from `sizing`."
  default     = null
}

variable "worker_replica_count" {
  type        = number
  description = "Worker replica count; when null, derived from `sizing`."
  default     = null
}

variable "ingress_enabled" {
  type        = bool
  description = "Render the chart Ingress."
  default     = true
}

variable "ingress_class_name" {
  type        = string
  description = "Ingress class name."
  default     = "nginx"
}

variable "ingress_cluster_issuer" {
  type        = string
  description = "cert-manager ClusterIssuer for the TLS certificate."
  default     = "letsencrypt-prod"
}

variable "helm_atomic" {
  type        = bool
  description = "Roll back the Helm release on a failed install/upgrade."
  default     = true
}

variable "helm_timeout" {
  type        = number
  description = "Helm release timeout in seconds."
  default     = 900
}

# ---- Optional bootstrap admin ---------------------------------------------

variable "enable_admin_bootstrap" {
  type        = bool
  description = "Wire the optional bootstrap admin (admin_email/admin_password) into the chart Secret."
  default     = false
}

variable "admin_email" {
  type        = string
  description = "Bootstrap admin email; only used when enable_admin_bootstrap is true."
  default     = ""
}

variable "admin_password" {
  type        = string
  description = "Bootstrap admin password; only used when enable_admin_bootstrap is true."
  default     = ""
  sensitive   = true
}

# ---- Tags ------------------------------------------------------------------

variable "tags" {
  type        = map(string)
  description = "Additional tags merged onto every AWS resource."
  default     = {}
}
