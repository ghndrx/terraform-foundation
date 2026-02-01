################################################################################
# Tenant Baseline - Outputs
################################################################################

# IAM Outputs
output "permissions_boundary_arn" {
  value       = module.tenant_iam.permissions_boundary_arn
  description = "Permissions boundary ARN"
}

output "admin_role_arn" {
  value       = module.tenant_iam.admin_role_arn
  description = "Tenant admin role ARN"
}

output "developer_role_arn" {
  value       = module.tenant_iam.developer_role_arn
  description = "Tenant developer role ARN"
}

output "readonly_role_arn" {
  value       = module.tenant_iam.readonly_role_arn
  description = "Tenant readonly role ARN"
}

output "all_role_arns" {
  value       = module.tenant_iam.all_role_arns
  description = "Map of all tenant role ARNs"
}

# Budget Outputs
output "budget_id" {
  value       = module.tenant_budget.budget_id
  description = "Budget ID"
}

output "budget_sns_topic_arn" {
  value       = module.tenant_budget.sns_topic_arn
  description = "Budget alerts SNS topic ARN"
}

# VPC Outputs
output "vpc_id" {
  value       = var.create_vpc ? module.tenant_vpc[0].vpc_id : null
  description = "VPC ID (if created)"
}

output "vpc_cidr" {
  value       = var.create_vpc ? module.tenant_vpc[0].vpc_cidr : null
  description = "VPC CIDR (if created)"
}

output "private_subnet_ids" {
  value       = var.create_vpc ? module.tenant_vpc[0].private_subnet_ids : []
  description = "Private subnet IDs"
}

output "public_subnet_ids" {
  value       = var.create_vpc ? module.tenant_vpc[0].public_subnet_ids : []
  description = "Public subnet IDs"
}

# Summary
output "tenant_tags" {
  value       = local.tenant_tags
  description = "Standard tenant tags"
}

output "resource_prefix" {
  value       = module.tenant_iam.resource_prefix
  description = "Tenant resource prefix"
}
