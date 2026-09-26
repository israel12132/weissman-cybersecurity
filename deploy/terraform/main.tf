# ---------------------------------------------------------------------------
# Weissman — dedicated (single-tenant) instance in a customer VPC.
#
# Composition (see docs/adr/0004-terraform-dedicated-provisioning.md):
#   module.data_tier  — thin AWS module: RDS Postgres + ElastiCache Redis +
#                        the per-customer JWT/vault key material, all recorded
#                        in AWS Secrets Manager.
#   module.app        — installs the existing Helm chart deploy/helm/weissman
#                        into a dedicated namespace with postgres/redis
#                        provisioning turned off, pointed at the data tier.
#
# This stack is bring-your-own customer VPC + EKS cluster (both pre-exist); it
# does NOT create the VPC or the cluster. See the README for the two-stage
# apply and the mandatory Postgres role/RLS bootstrap.
# ---------------------------------------------------------------------------

provider "aws" {
  region = var.aws_region
}

data "aws_eks_cluster" "this" {
  name = var.eks_cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = var.eks_cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

locals {
  sizing_profiles = {
    small = {
      backend_replicas     = 2
      worker_replicas      = 1
      db_instance_class    = "db.t4g.medium"
      db_allocated_storage = 50
      redis_node_type      = "cache.t4g.small"
    }
    medium = {
      backend_replicas     = 2
      worker_replicas      = 2
      db_instance_class    = "db.r7g.large"
      db_allocated_storage = 100
      redis_node_type      = "cache.r7g.large"
    }
    large = {
      backend_replicas     = 4
      worker_replicas      = 4
      db_instance_class    = "db.r7g.2xlarge"
      db_allocated_storage = 250
      redis_node_type      = "cache.r7g.xlarge"
    }
  }

  profile = local.sizing_profiles[var.sizing]

  namespace    = var.namespace_override != "" ? var.namespace_override : "weissman-${var.customer_name}"
  release_name = var.release_name != "" ? var.release_name : "weissman-${var.customer_name}"
  region_label = var.customer_region_label != "" ? var.customer_region_label : var.aws_region

  db_instance_class    = var.db_instance_class != null ? var.db_instance_class : local.profile.db_instance_class
  db_allocated_storage = var.db_allocated_storage != null ? var.db_allocated_storage : local.profile.db_allocated_storage
  redis_node_type      = var.redis_node_type != null ? var.redis_node_type : local.profile.redis_node_type

  backend_replica_count = var.backend_replica_count != null ? var.backend_replica_count : local.profile.backend_replicas
  worker_replica_count  = var.worker_replica_count != null ? var.worker_replica_count : local.profile.worker_replicas

  # deploy/terraform -> ../helm/weissman
  chart_path = "${path.module}/../helm/weissman"
}

module "data_tier" {
  source = "./modules/data-tier"

  customer_name = var.customer_name

  vpc_id                 = var.vpc_id
  db_subnet_ids          = var.db_subnet_ids
  redis_subnet_ids       = var.redis_subnet_ids
  app_security_group_ids = var.app_security_group_ids
  db_allowed_cidr_blocks = var.db_allowed_cidr_blocks

  db_instance_class        = local.db_instance_class
  db_allocated_storage     = local.db_allocated_storage
  db_max_allocated_storage = var.db_max_allocated_storage
  db_engine_version        = var.db_engine_version
  db_name                  = var.db_name
  db_master_username       = var.db_master_username
  db_multi_az              = var.db_multi_az
  db_backup_retention_days = var.db_backup_retention_days
  db_deletion_protection   = var.db_deletion_protection
  db_skip_final_snapshot   = var.db_skip_final_snapshot
  db_kms_key_id            = var.db_kms_key_id

  redis_node_type                  = local.redis_node_type
  redis_engine_version             = var.redis_engine_version
  redis_num_nodes                  = var.redis_num_nodes
  redis_transit_encryption_enabled = var.redis_transit_encryption_enabled
  redis_snapshot_retention_days    = var.redis_snapshot_retention_days

  secrets_manager_kms_key_id  = var.secrets_manager_kms_key_id
  secret_recovery_window_days = var.secret_recovery_window_days

  tags = var.tags
}

module "app" {
  source = "./modules/app"

  chart_path   = local.chart_path
  release_name = local.release_name
  namespace    = local.namespace

  customer_name = var.customer_name
  domain        = var.domain
  region_label  = local.region_label
  sizing_label  = var.sizing

  image_repository = var.image_repository
  image_digest     = var.image_digest
  image_tag        = var.image_tag

  backend_replica_count = local.backend_replica_count
  worker_replica_count  = local.worker_replica_count

  ingress_enabled        = var.ingress_enabled
  ingress_class_name     = var.ingress_class_name
  ingress_cluster_issuer = var.ingress_cluster_issuer

  atomic  = var.helm_atomic
  timeout = var.helm_timeout

  database_url               = module.data_tier.database_url
  auth_database_url          = module.data_tier.auth_database_url
  worker_database_url        = module.data_tier.worker_database_url
  analytics_database_url     = module.data_tier.analytics_database_url
  migrate_url                = module.data_tier.migrate_url
  redis_url                  = module.data_tier.redis_url
  jwt_secret                 = module.data_tier.jwt_secret
  integrations_vault_key     = module.data_tier.integrations_vault_key
  vault_key                  = module.data_tier.vault_key
  rag_provenance_secret      = module.data_tier.rag_provenance_secret
  destructive_confirm_secret = module.data_tier.destructive_confirm_secret
  job_orchestrator_secret    = module.data_tier.job_orchestrator_secret
  metrics_token              = module.data_tier.metrics_token

  enable_admin_bootstrap = var.enable_admin_bootstrap
  admin_email            = var.admin_email
  admin_password         = var.admin_password
}
