module "cyberaccess_tenant" {
  source = "../.."

  base_url   = "https://cyberaccess.your-company.com"
  signup_key = var.cyberaccess_signup_key
  admin_jwt  = var.cyberaccess_admin_jwt

  tenant_name = "acme-corp"

  quota = {
    requests_per_minute  = 5000
    risk_threshold_block = 90
    risk_threshold_warn  = 70
  }

  alert_channels = [
    {
      channel_type   = "slack"
      channel_config = { url = "https://hooks.slack.com/services/REPLACE/ME/WITH_YOUR_WEBHOOK" }
    },
    {
      channel_type   = "email"
      channel_config = { address = "security-team@acme-corp.example.com" }
    },
  ]
}

variable "cyberaccess_signup_key" {
  type      = string
  sensitive = true
}

variable "cyberaccess_admin_jwt" {
  type      = string
  sensitive = true
}

output "tenant_id" {
  value = module.cyberaccess_tenant.tenant_id
}

output "tenant_api_key" {
  value     = module.cyberaccess_tenant.tenant_api_key
  sensitive = true
}
