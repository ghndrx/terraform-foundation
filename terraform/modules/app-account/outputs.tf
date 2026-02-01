################################################################################
# App Account - Outputs
################################################################################

output "account_id" {
  value       = aws_organizations_account.this.id
  description = "AWS account ID"
}

output "account_arn" {
  value       = aws_organizations_account.this.arn
  description = "AWS account ARN"
}

output "account_name" {
  value       = aws_organizations_account.this.name
  description = "Account name"
}

output "account_email" {
  value       = aws_organizations_account.this.email
  description = "Account root email"
  sensitive   = true
}

output "admin_role_arn" {
  value       = "arn:aws:iam::${aws_organizations_account.this.id}:role/${var.admin_role_name}"
  description = "Admin role ARN for cross-account access"
}

output "cross_account_readonly_role_arn" {
  value       = var.create_cross_account_roles ? aws_iam_role.cross_account_readonly[0].arn : null
  description = "Cross-account readonly role ARN"
}

output "cross_account_admin_role_arn" {
  value       = var.create_cross_account_roles ? aws_iam_role.cross_account_admin[0].arn : null
  description = "Cross-account admin role ARN"
}

output "budget_id" {
  value       = var.budget_limit > 0 ? aws_budgets_budget.this[0].id : null
  description = "Budget ID"
}

output "account_tags" {
  value       = local.account_tags
  description = "Account tags"
}
