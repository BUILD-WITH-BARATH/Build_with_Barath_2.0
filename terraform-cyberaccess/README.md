# terraform-cyberaccess

Provision a CyberAccess tenant, its quota, and its alert channels declaratively.

## What this is (and isn't)

CyberAccess doesn't ship a native Go-based Terraform provider (that's a substantial
separate project - provider scaffolding, a Terraform Registry publish, acceptance
tests). This module instead wraps the existing REST API with `null_resource` +
`local-exec` (`curl`), using only official HashiCorp providers (`null`, `http`,
`local`) - no custom binary to build or trust.

Because of that, be aware of two real constraints:

1. **`curl` must be on the machine running `terraform apply`** (present by default
   on macOS, Linux, and modern Windows).
2. **Not every resource here is truly idempotent**, because the underlying API
   isn't: `POST /v1/tenants` and `POST /tenants/{id}/alert-channels` each mint a
   new random ID on every call rather than upserting by name. This module works
   around that with `triggers` so a normal `terraform apply` won't create
   duplicates, but changing an alert channel's config creates a **new** channel
   rather than updating the old one in place - see `variables.tf`'s
   `alert_channels` description. Quota (`POST /tenants/{id}/quota`) *is* a genuine
   upsert and re-applies safely.

## Secrets handling

A newly created tenant's `api_key` is shown by the API exactly once. To make it
available as a Terraform output across future `plan`/`apply` runs (not just the
one that created it), this module persists the raw API response - including that
key - in plaintext at `.generated/tenant_create_response.json` inside the module
directory. That path is already in `.gitignore`, but you are responsible for:

- treating `.generated/` as sensitive on disk (it's equivalent to a secrets file),
- copying `tenant_api_key` into your real secrets manager promptly, and
- not committing Terraform state (`terraform.tfstate`) anywhere it can leak -
  outputs marked `sensitive` are still stored in plaintext in state.

## Usage

```hcl
module "acme_tenant" {
  source = "github.com/BUILD-WITH-BARATH/Build_with_Barath_2.0//terraform-cyberaccess"

  base_url   = "https://cyberaccess.your-company.com"
  signup_key = var.cyberaccess_signup_key   # TENANT_SIGNUP_KEY on the backend
  admin_jwt  = var.cyberaccess_admin_jwt    # a security_admin JWT, generated out-of-band

  tenant_name = "acme-corp"

  quota = {
    requests_per_minute  = 5000
    risk_threshold_block = 90
  }

  alert_channels = [
    { channel_type = "slack", channel_config = { url = "https://hooks.slack.com/services/..." } },
  ]
}
```

To manage an **existing** tenant instead of creating a new one, set
`existing_tenant_id` and leave `tenant_name` empty - `signup_key` is then unused.

See `examples/basic/` for a complete, runnable example.

## Development

No test suite - this module has no logic to unit test beyond what Terraform's own
`validate` covers. If you have the Terraform CLI installed:

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

This was authored without a local Terraform CLI available to run those commands
against; if `validate` surfaces anything, please open an issue.
