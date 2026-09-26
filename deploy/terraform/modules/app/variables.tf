variable "chart_path" {
  type        = string
  description = "Filesystem path to the deploy/helm/weissman chart."
}

variable "release_name" {
  type        = string
  description = "Helm release name."
}

variable "namespace" {
  type        = string
  description = "Kubernetes namespace; must equal the chart's computed namespace."
}

variable "customer_name" {
  type        = string
  description = "DNS-label-safe customer id."
}

variable "domain" {
  type        = string
  description = "Primary FQDN this instance serves."
}

variable "region_label" {
  type        = string
  description = "Inventory region label."
  default     = ""
}

variable "sizing_label" {
  type        = string
  description = "Inventory sizing label."
  default     = ""
}

variable "image_repository" {
  type        = string
  description = "Backend/worker image repository."
}

variable "image_digest" {
  type        = string
  description = "Immutable image digest; wins over image_tag."
  default     = ""
}

variable "image_tag" {
  type        = string
  description = "Image tag; used only when image_digest is empty."
  default     = ""
}

variable "backend_replica_count" {
  type        = number
  description = "Backend replica count."
}

variable "worker_replica_count" {
  type        = number
  description = "Worker replica count."
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
  description = "cert-manager ClusterIssuer."
  default     = "letsencrypt-prod"
}

variable "atomic" {
  type        = bool
  description = "Roll back on a failed install/upgrade."
  default     = true
}

variable "timeout" {
  type        = number
  description = "Helm release timeout in seconds."
  default     = 900
}

# ---- Secret material (from the data-tier module) --------------------------

variable "database_url" {
  type      = string
  sensitive = true
}

variable "auth_database_url" {
  type      = string
  sensitive = true
}

variable "worker_database_url" {
  type      = string
  sensitive = true
}

variable "analytics_database_url" {
  type      = string
  sensitive = true
}

variable "migrate_url" {
  type      = string
  sensitive = true
}

variable "redis_url" {
  type      = string
  sensitive = true
}

variable "jwt_secret" {
  type      = string
  sensitive = true
}

variable "integrations_vault_key" {
  type      = string
  sensitive = true
}

variable "vault_key" {
  type      = string
  sensitive = true
}

variable "rag_provenance_secret" {
  type      = string
  sensitive = true
}

variable "destructive_confirm_secret" {
  type      = string
  sensitive = true
}

variable "job_orchestrator_secret" {
  type      = string
  sensitive = true
}

variable "metrics_token" {
  type      = string
  sensitive = true
}

# ---- Optional bootstrap admin ---------------------------------------------

variable "enable_admin_bootstrap" {
  type        = bool
  description = "Wire the optional bootstrap admin into the chart Secret."
  default     = false
}

variable "admin_email" {
  type        = string
  description = "Bootstrap admin email."
  default     = ""
}

variable "admin_password" {
  type        = string
  description = "Bootstrap admin password."
  default     = ""
  sensitive   = true
}
