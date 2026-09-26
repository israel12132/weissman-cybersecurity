# ---------------------------------------------------------------------------
# Weissman dedicated data tier — RDS Postgres, ElastiCache Redis, per-customer
# JWT/vault key material, and the Secrets Manager bundle that records it all.
#
# NOTE: this module creates the RDS instance and its master/owner user only.
# The four NOBYPASSRLS application roles (weissman_app/auth/worker/analytics)
# and the `vector` extension MUST be bootstrapped out-of-band with the master
# credentials before the application pods can connect (ADR 0001). The generated
# per-role passwords are written to the Secrets Manager bundle for that step.
# ---------------------------------------------------------------------------

locals {
  name = "weissman-${var.customer_name}"

  role_users = ["weissman_app", "weissman_auth", "weissman_worker", "weissman_analytics"]

  redis_subnet_ids = length(var.redis_subnet_ids) > 0 ? var.redis_subnet_ids : var.db_subnet_ids

  pg_host = aws_db_instance.this.address
  pg_port = aws_db_instance.this.port

  role_dsns = {
    for u in local.role_users :
    u => "postgresql://${u}:${random_password.role[u].result}@${local.pg_host}:${local.pg_port}/${var.db_name}?sslmode=require"
  }

  migrate_url = "postgresql://${var.db_master_username}:${random_password.db_master.result}@${local.pg_host}:${local.pg_port}/${var.db_name}?sslmode=require"

  redis_host = aws_elasticache_replication_group.this.primary_endpoint_address

  redis_url = var.redis_transit_encryption_enabled ? "rediss://:${random_password.redis_auth[0].result}@${local.redis_host}:6379/0" : "redis://${local.redis_host}:6379/0"

  tags = merge(var.tags, {
    "weissman.io/tier"     = "dedicated"
    "weissman.io/customer" = var.customer_name
    "ManagedBy"            = "terraform"
  })
}

# ---- Generated secret material --------------------------------------------

resource "random_password" "db_master" {
  length  = 32
  special = false
}

resource "random_password" "role" {
  for_each = toset(local.role_users)
  length   = 32
  special  = false
}

resource "random_password" "redis_auth" {
  count   = var.redis_transit_encryption_enabled ? 1 : 0
  length  = 48
  special = false
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

resource "random_password" "integrations_vault_key" {
  length  = 48
  special = false
}

resource "random_password" "destructive_confirm" {
  length  = 48
  special = false
}

resource "random_password" "job_orchestrator" {
  length  = 48
  special = false
}

resource "random_password" "metrics_token" {
  length  = 48
  special = false
}

# 64 hex chars (32 bytes) — matches the app's vault_key / rag_provenance format.
resource "random_bytes" "vault_key" {
  length = 32
}

resource "random_bytes" "rag_provenance" {
  length = 32
}

# ---- RDS Postgres ----------------------------------------------------------

resource "aws_db_subnet_group" "this" {
  name       = "${local.name}-db"
  subnet_ids = var.db_subnet_ids
  tags       = local.tags
}

# The data tier is reached only from inside the VPC and never needs to talk to the internet:
# RDS and ElastiCache are managed services with no outbound dependencies of their own, so
# their security groups allow egress only within the VPC CIDR (Trivy AVD-AWS-0104 blocks
# 0.0.0.0/0 egress at CRITICAL in CI).
data "aws_vpc" "this" {
  id = var.vpc_id
}

resource "aws_security_group" "db" {
  name_prefix = "${local.name}-db-"
  description = "Weissman ${var.customer_name} RDS Postgres access"
  vpc_id      = var.vpc_id
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_sg" {
  for_each                     = toset(var.app_security_group_ids)
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Postgres from app security group"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_cidr" {
  for_each          = toset(var.db_allowed_cidr_blocks)
  security_group_id = aws_security_group.db.id
  cidr_ipv4         = each.value
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
  description       = "Postgres from allowed CIDR"
}

resource "aws_vpc_security_group_egress_rule" "db_vpc" {
  security_group_id = aws_security_group.db.id
  cidr_ipv4         = data.aws_vpc.this.cidr_block
  ip_protocol       = "-1"
  description       = "Egress within the VPC only (managed Postgres has no internet dependency)"
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${local.name}-pg16-"
  family      = "postgres16"
  description = "Weissman ${var.customer_name} — force SSL"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.tags
}

resource "aws_db_instance" "this" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.db_kms_key_id

  db_name  = var.db_name
  username = var.db_master_username
  password = random_password.db_master.result

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false

  backup_retention_period   = var.db_backup_retention_days
  copy_tags_to_snapshot     = true
  deletion_protection       = var.db_deletion_protection
  skip_final_snapshot       = var.db_skip_final_snapshot
  final_snapshot_identifier = var.db_skip_final_snapshot ? null : "${local.name}-final"

  auto_minor_version_upgrade   = true
  performance_insights_enabled = true
  apply_immediately            = false

  tags = local.tags
}

# ---- ElastiCache Redis -----------------------------------------------------

resource "aws_elasticache_subnet_group" "this" {
  name       = "${local.name}-redis"
  subnet_ids = local.redis_subnet_ids
  tags       = local.tags
}

resource "aws_security_group" "redis" {
  name_prefix = "${local.name}-redis-"
  description = "Weissman ${var.customer_name} ElastiCache Redis access"
  vpc_id      = var.vpc_id
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_sg" {
  for_each                     = toset(var.app_security_group_ids)
  security_group_id            = aws_security_group.redis.id
  referenced_security_group_id = each.value
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  description                  = "Redis from app security group"
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_cidr" {
  for_each          = toset(var.db_allowed_cidr_blocks)
  security_group_id = aws_security_group.redis.id
  cidr_ipv4         = each.value
  from_port         = 6379
  to_port           = 6379
  ip_protocol       = "tcp"
  description       = "Redis from allowed CIDR"
}

resource "aws_vpc_security_group_egress_rule" "redis_vpc" {
  security_group_id = aws_security_group.redis.id
  cidr_ipv4         = data.aws_vpc.this.cidr_block
  ip_protocol       = "-1"
  description       = "Egress within the VPC only (managed Redis has no internet dependency)"
}

resource "aws_elasticache_parameter_group" "this" {
  name_prefix = "${local.name}-redis7-"
  family      = "redis7"
  description = "Weissman ${var.customer_name} — allkeys-lru"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.tags
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = local.name
  description          = "Weissman ${var.customer_name} dedicated Redis"

  engine         = "redis"
  engine_version = var.redis_engine_version
  node_type      = var.redis_node_type
  port           = 6379

  num_cache_clusters         = var.redis_num_nodes
  automatic_failover_enabled = var.redis_num_nodes > 1
  multi_az_enabled           = var.redis_num_nodes > 1

  subnet_group_name    = aws_elasticache_subnet_group.this.name
  security_group_ids   = [aws_security_group.redis.id]
  parameter_group_name = aws_elasticache_parameter_group.this.name

  at_rest_encryption_enabled = true
  transit_encryption_enabled = var.redis_transit_encryption_enabled
  auth_token                 = var.redis_transit_encryption_enabled ? random_password.redis_auth[0].result : null

  snapshot_retention_limit = var.redis_snapshot_retention_days
  apply_immediately        = false

  tags = local.tags
}

# ---- Secrets Manager bundle -----------------------------------------------

resource "aws_secretsmanager_secret" "app" {
  name                    = "weissman/${var.customer_name}/app"
  description             = "Weissman ${var.customer_name} dedicated instance — DSNs and at-rest keys (ADR 0002/0003)."
  kms_key_id              = var.secrets_manager_kms_key_id
  recovery_window_in_days = var.secret_recovery_window_days
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id

  secret_string = jsonencode({
    database_url               = local.role_dsns["weissman_app"]
    auth_database_url          = local.role_dsns["weissman_auth"]
    worker_database_url        = local.role_dsns["weissman_worker"]
    analytics_database_url     = local.role_dsns["weissman_analytics"]
    migrate_url                = local.migrate_url
    redis_url                  = local.redis_url
    jwt_secret                 = random_password.jwt_secret.result
    integrations_vault_key     = random_password.integrations_vault_key.result
    vault_key                  = random_bytes.vault_key.hex
    rag_provenance_secret      = random_bytes.rag_provenance.hex
    destructive_confirm_secret = random_password.destructive_confirm.result
    job_orchestrator_secret    = random_password.job_orchestrator.result
    metrics_token              = random_password.metrics_token.result
    db_master_username         = var.db_master_username
    db_master_password         = random_password.db_master.result
    role_passwords             = { for u in local.role_users : u => random_password.role[u].result }
  })
}
