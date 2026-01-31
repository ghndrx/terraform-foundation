################################################################################
# AWS Backup Module
#
# Centralized backup management:
# - Daily backups with configurable retention
# - Cross-region copy for DR (optional)
# - Tag-based resource selection
#
# Compliance: Meets HIPAA, SOC 2 backup requirements
#
# Note: Cross-region DR requires passing a provider alias for the DR region:
#
#   provider "aws" {
#     alias  = "dr"
#     region = "us-west-2"
#   }
#
#   module "backup" {
#     source = "../modules/backup-plan"
#     providers = {
#       aws    = aws
#       aws.dr = aws.dr
#     }
#     enable_cross_region_copy = true
#     dr_region = "us-west-2"
#     ...
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.0"
      configuration_aliases = [aws.dr]
    }
  }
}

variable "name" {
  type        = string
  description = "Backup plan name"
}

variable "tenant" {
  type        = string
  description = "Tenant name for resource selection"
  default     = null
}

variable "backup_tag_key" {
  type        = string
  default     = "Backup"
  description = "Tag key to select resources for backup"
}

variable "backup_tag_value" {
  type        = string
  default     = "true"
  description = "Tag value to select resources for backup"
}

# Retention settings
variable "daily_retention_days" {
  type    = number
  default = 35 # 5 weeks
}

variable "weekly_retention_days" {
  type    = number
  default = 90 # ~3 months
}

variable "monthly_retention_days" {
  type    = number
  default = 365 # 1 year
}

variable "enable_continuous_backup" {
  type        = bool
  default     = false
  description = "Enable continuous backup for point-in-time recovery (RDS, S3)"
}

# Cross-region DR
variable "enable_cross_region_copy" {
  type    = bool
  default = false
}

variable "dr_region" {
  type        = string
  default     = "us-west-2"
  description = "DR region for cross-region backup copy"
}

variable "dr_retention_days" {
  type    = number
  default = 30
}

# KMS
variable "kms_key_arn" {
  type        = string
  default     = null
  description = "KMS key ARN for backup encryption (uses AWS managed key if null)"
}

################################################################################
# Backup Vault
################################################################################

resource "aws_backup_vault" "main" {
  name        = var.name
  kms_key_arn = var.kms_key_arn

  tags = { Name = var.name }
}

# Vault lock for compliance (prevents deletion)
resource "aws_backup_vault_lock_configuration" "main" {
  backup_vault_name   = aws_backup_vault.main.name
  min_retention_days  = 7
  max_retention_days  = 365
  changeable_for_days = 3 # Grace period before lock becomes immutable
}

################################################################################
# DR Vault (Cross-Region)
################################################################################

resource "aws_backup_vault" "dr" {
  count    = var.enable_cross_region_copy ? 1 : 0
  provider = aws.dr

  name        = "${var.name}-dr"
  kms_key_arn = var.kms_key_arn

  tags = { Name = "${var.name}-dr" }
}

################################################################################
# IAM Role
################################################################################

resource "aws_iam_role" "backup" {
  name = "${var.name}-backup"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "backup.amazonaws.com" }
    }]
  })

  tags = { Name = "${var.name}-backup" }
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_iam_role_policy_attachment" "s3_backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup"
}

resource "aws_iam_role_policy_attachment" "s3_restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore"
}

################################################################################
# Backup Plan
################################################################################

resource "aws_backup_plan" "main" {
  name = var.name

  # Daily backup at 3 AM UTC
  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 3 * * ? *)"
    start_window      = 60  # 1 hour
    completion_window = 180 # 3 hours

    lifecycle {
      delete_after = var.daily_retention_days
    }

    dynamic "copy_action" {
      for_each = var.enable_cross_region_copy ? [1] : []
      content {
        destination_vault_arn = aws_backup_vault.dr[0].arn
        lifecycle {
          delete_after = var.dr_retention_days
        }
      }
    }
  }

  # Weekly backup (Sunday 2 AM UTC)
  rule {
    rule_name         = "weekly"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 2 ? * SUN *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = var.weekly_retention_days
    }
  }

  # Monthly backup (1st of month, 1 AM UTC)
  rule {
    rule_name         = "monthly"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 1 1 * ? *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after       = var.monthly_retention_days
      cold_storage_after = 90 # Move to cold storage after 90 days
    }
  }

  # Continuous backup (point-in-time recovery)
  dynamic "rule" {
    for_each = var.enable_continuous_backup ? [1] : []
    content {
      rule_name                = "continuous"
      target_vault_name        = aws_backup_vault.main.name
      enable_continuous_backup = true

      lifecycle {
        delete_after = 35 # Max for continuous backup
      }
    }
  }

  tags = { Name = var.name }
}

################################################################################
# Resource Selection
################################################################################

resource "aws_backup_selection" "tagged" {
  name         = "${var.name}-tagged"
  plan_id      = aws_backup_plan.main.id
  iam_role_arn = aws_iam_role.backup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = var.backup_tag_key
    value = var.backup_tag_value
  }

  # If tenant is specified, also match tenant tag
  dynamic "selection_tag" {
    for_each = var.tenant != null ? [1] : []
    content {
      type  = "STRINGEQUALS"
      key   = "Tenant"
      value = var.tenant
    }
  }
}

################################################################################
# Outputs
################################################################################

output "vault_arn" {
  value = aws_backup_vault.main.arn
}

output "vault_name" {
  value = aws_backup_vault.main.name
}

output "plan_id" {
  value = aws_backup_plan.main.id
}

output "plan_arn" {
  value = aws_backup_plan.main.arn
}

output "role_arn" {
  value = aws_iam_role.backup.arn
}
