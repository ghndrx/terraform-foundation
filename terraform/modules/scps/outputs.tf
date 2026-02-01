################################################################################
# SCPs - Outputs
################################################################################

output "policy_ids" {
  value       = { for k, v in aws_organizations_policy.this : k => v.id }
  description = "Map of SCP names to policy IDs"
}

output "policy_arns" {
  value       = { for k, v in aws_organizations_policy.this : k => v.arn }
  description = "Map of SCP names to policy ARNs"
}

output "enabled_policies" {
  value       = keys(local.scps)
  description = "List of enabled SCP policy names"
}

output "attachment_count" {
  value = {
    ous      = length(var.target_ous)
    accounts = length(var.target_accounts)
  }
  description = "Count of SCP attachments"
}
