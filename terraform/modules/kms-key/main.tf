################################################################################
# KMS Key Module
#
# Customer-managed KMS keys for encryption:
# - Automatic key rotation
# - Cross-account access
# - Service-specific grants
# - Alias management
# - Key policies
#
# Usage:
#   module "kms" {
#     source = "../modules/kms-key"
#     
#     name        = "myapp-encryption"
#     description = "Encryption key for myapp"
#     
#     service_principals = ["logs.amazonaws.com", "s3.amazonaws.com"]
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "name" {
  type        = string
  description = "Key name (used for alias)"
}

variable "description" {
  type        = string
  default     = ""
  description = "Key description"
}

variable "deletion_window_in_days" {
  type        = number
  default     = 30
  description = "Waiting period before key deletion (7-30 days)"

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "Must be between 7 and 30 days"
  }
}

variable "enable_key_rotation" {
  type        = bool
  default     = true
  description = "Enable automatic key rotation (annual)"
}

variable "multi_region" {
  type        = bool
  default     = false
  description = "Create a multi-region key"
}

variable "key_usage" {
  type        = string
  default     = "ENCRYPT_DECRYPT"
  description = "Key usage: ENCRYPT_DECRYPT or SIGN_VERIFY"

  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY", "GENERATE_VERIFY_MAC"], var.key_usage)
    error_message = "Must be ENCRYPT_DECRYPT, SIGN_VERIFY, or GENERATE_VERIFY_MAC"
  }
}

variable "key_spec" {
  type        = string
  default     = "SYMMETRIC_DEFAULT"
  description = "Key spec (SYMMETRIC_DEFAULT, RSA_2048, ECC_NIST_P256, etc.)"
}

variable "admin_principals" {
  type        = list(string)
  default     = []
  description = "IAM ARNs with full admin access to the key"
}

variable "user_principals" {
  type        = list(string)
  default     = []
  description = "IAM ARNs with encrypt/decrypt access"
}

variable "service_principals" {
  type        = list(string)
  default     = []
  description = "AWS service principals that can use the key (e.g., logs.amazonaws.com)"
}

variable "grant_accounts" {
  type        = list(string)
  default     = []
  description = "Account IDs with cross-account access"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# KMS Key
################################################################################

resource "aws_kms_key" "main" {
  description              = var.description != "" ? var.description : "KMS key for ${var.name}"
  deletion_window_in_days  = var.deletion_window_in_days
  enable_key_rotation      = var.key_spec == "SYMMETRIC_DEFAULT" ? var.enable_key_rotation : false
  multi_region             = var.multi_region
  key_usage                = var.key_usage
  customer_master_key_spec = var.key_spec

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Root account access (required)
      [{
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }],

      # Admin principals
      length(var.admin_principals) > 0 ? [{
        Sid    = "KeyAdministrators"
        Effect = "Allow"
        Principal = {
          AWS = var.admin_principals
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      }] : [],

      # User principals
      length(var.user_principals) > 0 ? [{
        Sid    = "KeyUsers"
        Effect = "Allow"
        Principal = {
          AWS = var.user_principals
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }] : [],

      # Service principals
      length(var.service_principals) > 0 ? [{
        Sid    = "AllowServices"
        Effect = "Allow"
        Principal = {
          Service = var.service_principals
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }] : [],

      # Cross-account access
      length(var.grant_accounts) > 0 ? [{
        Sid    = "CrossAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = [for acct in var.grant_accounts : "arn:aws:iam::${acct}:root"]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }] : [],

      # Allow grants (needed for some AWS services)
      [{
        Sid    = "AllowGrants"
        Effect = "Allow"
        Principal = {
          AWS = concat(
            ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"],
            var.user_principals
          )
        }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }]
    )
  })

  tags = merge(var.tags, { Name = var.name })
}

################################################################################
# Alias
################################################################################

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.main.key_id
}

################################################################################
# Outputs
################################################################################

output "key_id" {
  value       = aws_kms_key.main.key_id
  description = "KMS key ID"
}

output "key_arn" {
  value       = aws_kms_key.main.arn
  description = "KMS key ARN"
}

output "alias_arn" {
  value       = aws_kms_alias.main.arn
  description = "KMS alias ARN"
}

output "alias_name" {
  value       = aws_kms_alias.main.name
  description = "KMS alias name"
}

output "key_policy" {
  value       = aws_kms_key.main.policy
  description = "Key policy document"
}
