################################################################################
# Account Baseline - Outputs
################################################################################

output "ebs_encryption_enabled" {
  value       = var.enable_ebs_encryption
  description = "Whether EBS encryption is enabled"
}

output "s3_block_public_enabled" {
  value       = var.enable_s3_block_public
  description = "Whether S3 public block is enabled"
}

output "access_analyzer_arn" {
  value       = try(aws_accessanalyzer_analyzer.this[0].arn, null)
  description = "Access Analyzer ARN"
}

output "securityhub_enabled" {
  value       = var.enable_securityhub
  description = "Whether Security Hub is enabled"
}

output "guardduty_detector_id" {
  value       = try(aws_guardduty_detector.this[0].id, null)
  description = "GuardDuty detector ID"
}

output "config_recorder_id" {
  value       = try(aws_config_configuration_recorder.this[0].id, null)
  description = "Config recorder ID"
}

output "admin_role_arn" {
  value       = try(aws_iam_role.admin[0].arn, null)
  description = "Admin IAM role ARN"
}

output "readonly_role_arn" {
  value       = try(aws_iam_role.readonly[0].arn, null)
  description = "Readonly IAM role ARN"
}

output "baseline_status" {
  value = {
    ebs_encryption   = var.enable_ebs_encryption
    s3_block_public  = var.enable_s3_block_public
    password_policy  = var.enable_password_policy
    access_analyzer  = var.enable_access_analyzer
    securityhub      = var.enable_securityhub
    guardduty        = var.enable_guardduty
    config           = var.enable_config
  }
  description = "Summary of baseline status"
}
