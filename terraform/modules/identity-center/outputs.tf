################################################################################
# Identity Center - Outputs
################################################################################

output "instance_arn" {
  value       = local.instance_arn
  description = "Identity Center instance ARN"
}

output "identity_store_id" {
  value       = local.identity_store_id
  description = "Identity Store ID"
}

output "permission_set_arns" {
  value       = { for k, v in aws_ssoadmin_permission_set.this : k => v.arn }
  description = "Map of permission set names to ARNs"
}

output "sso_start_url" {
  value       = "https://${local.identity_store_id}.awsapps.com/start"
  description = "SSO portal start URL"
}

output "assignment_count" {
  value       = length(aws_ssoadmin_account_assignment.this)
  description = "Number of account assignments created"
}
