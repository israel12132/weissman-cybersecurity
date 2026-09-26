output "release_status" {
  description = "Status of the Helm release."
  value       = helm_release.weissman.status
}

output "namespace" {
  description = "Namespace the release is installed into."
  value       = helm_release.weissman.namespace
}
