# ---------------------------------------------------------------------------
# Installs the existing deploy/helm/weissman chart for one dedicated customer.
# postgres/redis provisioning is disabled; DSNs and at-rest keys come from the
# data-tier module and are injected as sensitive Helm --set values so they are
# never rendered into the plan's non-sensitive values document.
# ---------------------------------------------------------------------------

locals {
  # Non-secret chart values. Every `secrets.*` key is injected via set_sensitive.
  chart_values = {
    customer = {
      name   = var.customer_name
      domain = var.domain
      region = var.region_label
      sizing = var.sizing_label
    }
    nameOverride = ""
    namespace = {
      create = false
      name   = var.namespace
    }
    image = {
      repository = var.image_repository
      digest     = var.image_digest
      tag        = var.image_tag
      pullPolicy = "IfNotPresent"
    }
    config = {
      env           = "production"
      publicBaseUrl = "https://${var.domain}"
    }
    secrets = {
      create = true
    }
    postgres = {
      provision = false
    }
    redis = {
      provision = false
    }
    backend = {
      replicaCount = var.backend_replica_count
    }
    worker = {
      replicaCount = var.worker_replica_count
    }
    ingress = {
      enabled        = var.ingress_enabled
      className      = var.ingress_class_name
      clusterIssuer  = var.ingress_cluster_issuer
      tlsSecretName  = "weissman-tls"
      backendService = "backend"
      backendPort    = 8000
    }
  }
}

resource "helm_release" "weissman" {
  name             = var.release_name
  chart            = var.chart_path
  namespace        = var.namespace
  create_namespace = true
  atomic           = var.atomic
  wait             = true
  timeout          = var.timeout

  values = [yamlencode(local.chart_values)]

  set_sensitive {
    name  = "secrets.databaseUrl"
    type  = "string"
    value = var.database_url
  }

  set_sensitive {
    name  = "secrets.authDatabaseUrl"
    type  = "string"
    value = var.auth_database_url
  }

  set_sensitive {
    name  = "secrets.workerDatabaseUrl"
    type  = "string"
    value = var.worker_database_url
  }

  set_sensitive {
    name  = "secrets.analyticsDatabaseUrl"
    type  = "string"
    value = var.analytics_database_url
  }

  set_sensitive {
    name  = "secrets.migrateUrl"
    type  = "string"
    value = var.migrate_url
  }

  set_sensitive {
    name  = "secrets.jwtSecret"
    type  = "string"
    value = var.jwt_secret
  }

  set_sensitive {
    name  = "secrets.redisUrl"
    type  = "string"
    value = var.redis_url
  }

  set_sensitive {
    name  = "secrets.destructiveConfirmSecret"
    type  = "string"
    value = var.destructive_confirm_secret
  }

  set_sensitive {
    name  = "secrets.jobOrchestratorSecret"
    type  = "string"
    value = var.job_orchestrator_secret
  }

  set_sensitive {
    name  = "secrets.metricsToken"
    type  = "string"
    value = var.metrics_token
  }

  set_sensitive {
    name  = "secrets.ragProvenanceSecret"
    type  = "string"
    value = var.rag_provenance_secret
  }

  set_sensitive {
    name  = "secrets.integrationsVaultKey"
    type  = "string"
    value = var.integrations_vault_key
  }

  set_sensitive {
    name  = "secrets.vaultKey"
    type  = "string"
    value = var.vault_key
  }

  dynamic "set_sensitive" {
    for_each = var.enable_admin_bootstrap ? [1] : []
    content {
      name  = "secrets.adminEmail"
      type  = "string"
      value = var.admin_email
    }
  }

  dynamic "set_sensitive" {
    for_each = var.enable_admin_bootstrap ? [1] : []
    content {
      name  = "secrets.adminPassword"
      type  = "string"
      value = var.admin_password
    }
  }
}
