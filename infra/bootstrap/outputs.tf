# These outputs are the handoff between bootstrap and everything else.
# After first apply, copy the role ARNs into your GHA workflow files.

output "scan_role_arn" {
  description = "Paste into .github/workflows/scan.yml → role-to-assume"
  value       = module.github_oidc.scan_role_arn
}

output "apply_role_arn" {
  description = "Paste into .github/workflows/apply.yml → role-to-assume"
  value       = module.github_oidc.apply_role_arn
}

output "tf_state_bucket" {
  description = "Use in backend blocks for all other stacks"
  value       = module.state_backend.bucket_name
}

output "tf_lock_table" {
  description = "Use in backend blocks for all other stacks"
  value       = module.state_backend.table_name
}
