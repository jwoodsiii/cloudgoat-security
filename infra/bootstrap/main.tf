module "state_backend" {
  source = "jwoodsiii/state-backend/aws"

  bucket_name = var.tf_state_bucket
  table_name  = var.tf_lock_table
}

module "github_oidc" {
  source  = "jwoodsiii/github-oidc/aws"
  version = "1.1.1"

  project              = "cloudgoat"
  github_org           = var.github_org
  github_repo          = var.github_repo
  state_bucket_arn     = module.state_backend.bucket_arn
  table_arn            = module.state_backend.table_arn
  create_oidc_provider = false
  # managed: ReadOnlyAccess
  # inline:  pass scan_inline_policy_arns with per-service read policies instead.
  scan_policy_mode = "managed"
  # admin: AdministratorAccess
  # inline: pass apply_inline_policy_arns with per-service write policies instead.
  apply_policy_mode = "admin"
}
