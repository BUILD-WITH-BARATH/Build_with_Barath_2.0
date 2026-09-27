output "tenant_id" {
  description = "The tenant_id in use - either newly created or the existing_tenant_id you passed in."
  value       = local.tenant_id
}

output "tenant_api_key" {
  description = <<-EOT
    Only populated when this module created a NEW tenant (var.tenant_name set).
    The backend shows this value exactly once at creation time; it is persisted
    in plaintext at .generated/tenant_create_response.json purely so Terraform
    can read it back on later applies (see README's "Secrets handling" section)
    - copy it into your own secrets manager and treat that file as sensitive.
  EOT
  value       = local.creating_tenant ? try(local.created_tenant.api_key, null) : null
  sensitive   = true
}
