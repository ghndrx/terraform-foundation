################################################################################
# Tenant IAM - Outputs
################################################################################

output "permissions_boundary_arn" {
  value       = var.create_permissions_boundary ? aws_iam_policy.boundary[0].arn : var.permissions_boundary_arn
  description = "Permissions boundary policy ARN"
}

output "admin_role_arn" {
  value       = try(aws_iam_role.admin[0].arn, null)
  description = "Tenant admin role ARN"
}

output "admin_role_name" {
  value       = try(aws_iam_role.admin[0].name, null)
  description = "Tenant admin role name"
}

output "developer_role_arn" {
  value       = try(aws_iam_role.developer[0].arn, null)
  description = "Tenant developer role ARN"
}

output "developer_role_name" {
  value       = try(aws_iam_role.developer[0].name, null)
  description = "Tenant developer role name"
}

output "readonly_role_arn" {
  value       = try(aws_iam_role.readonly[0].arn, null)
  description = "Tenant readonly role ARN"
}

output "readonly_role_name" {
  value       = try(aws_iam_role.readonly[0].name, null)
  description = "Tenant readonly role name"
}

output "all_role_arns" {
  value = {
    admin     = try(aws_iam_role.admin[0].arn, null)
    developer = try(aws_iam_role.developer[0].arn, null)
    readonly  = try(aws_iam_role.readonly[0].arn, null)
  }
  description = "Map of all tenant role ARNs"
}

output "resource_prefix" {
  value       = local.resource_prefix
  description = "Resource prefix for tenant naming"
}
