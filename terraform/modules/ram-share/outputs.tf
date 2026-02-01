################################################################################
# RAM Share - Outputs
################################################################################

output "share_arn" {
  value       = aws_ram_resource_share.this.arn
  description = "Resource share ARN"
}

output "share_id" {
  value       = aws_ram_resource_share.this.id
  description = "Resource share ID"
}

output "resource_associations" {
  value       = { for k, v in aws_ram_resource_association.this : k => v.id }
  description = "Map of resource associations"
}

output "principal_count" {
  value = (
    (var.share_with_organization ? 1 : 0) +
    length(var.principal_ous) +
    length(var.principal_accounts)
  )
  description = "Number of principals shared with"
}
