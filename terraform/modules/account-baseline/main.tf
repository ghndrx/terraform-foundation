################################################################################
# Account Baseline Module
#
# Applies baseline security configuration to AWS accounts:
# - EBS default encryption
# - S3 account public access block
# - IAM account password policy
# - IAM Access Analyzer
# - Security Hub enrollment (optional)
# - GuardDuty enrollment (optional)
################################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id
}

################################################################################
# EBS Default Encryption
################################################################################

resource "aws_ebs_encryption_by_default" "this" {
  count   = var.enable_ebs_encryption ? 1 : 0
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  count   = var.enable_ebs_encryption && var.ebs_kms_key_arn != null ? 1 : 0
  key_arn = var.ebs_kms_key_arn
}

################################################################################
# S3 Account Public Access Block
################################################################################

resource "aws_s3_account_public_access_block" "this" {
  count = var.enable_s3_block_public ? 1 : 0

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

################################################################################
# IAM Password Policy
################################################################################

resource "aws_iam_account_password_policy" "this" {
  count = var.enable_password_policy ? 1 : 0

  minimum_password_length        = var.password_policy.minimum_length
  require_lowercase_characters   = var.password_policy.require_lowercase
  require_numbers                = var.password_policy.require_numbers
  require_uppercase_characters   = var.password_policy.require_uppercase
  require_symbols                = var.password_policy.require_symbols
  allow_users_to_change_password = var.password_policy.allow_users_to_change
  max_password_age               = var.password_policy.max_age_days
  password_reuse_prevention      = var.password_policy.reuse_prevention_count
  hard_expiry                    = var.password_policy.hard_expiry
}

################################################################################
# IAM Access Analyzer
################################################################################

resource "aws_accessanalyzer_analyzer" "this" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = "${var.name}-access-analyzer"
  type          = var.access_analyzer_type

  tags = merge(var.tags, {
    Name = "${var.name}-access-analyzer"
  })
}

################################################################################
# Security Hub
################################################################################

resource "aws_securityhub_account" "this" {
  count = var.enable_securityhub ? 1 : 0

  enable_default_standards = var.securityhub_enable_default_standards
  auto_enable_controls     = var.securityhub_auto_enable_controls
  control_finding_generator = "SECURITY_CONTROL"
}

resource "aws_securityhub_standards_subscription" "this" {
  for_each = var.enable_securityhub ? toset(var.securityhub_standards) : []

  standards_arn = each.value

  depends_on = [aws_securityhub_account.this]
}

################################################################################
# GuardDuty
################################################################################

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_frequency

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = var.guardduty_kubernetes_audit
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.guardduty_malware_protection
        }
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.name}-guardduty"
  })
}

################################################################################
# AWS Config
################################################################################

resource "aws_config_configuration_recorder" "this" {
  count = var.enable_config ? 1 : 0

  name     = "${var.name}-config-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported = true
    include_global_resource_types = var.config_include_global_resources
  }
}

resource "aws_config_delivery_channel" "this" {
  count = var.enable_config ? 1 : 0

  name           = "${var.name}-config-delivery"
  s3_bucket_name = var.config_s3_bucket
  s3_key_prefix  = var.config_s3_prefix
  sns_topic_arn  = var.config_sns_topic_arn

  snapshot_delivery_properties {
    delivery_frequency = var.config_snapshot_frequency
  }

  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0

  name = "${var.name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, {
    Name = "${var.name}-config-role"
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count = var.enable_config ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_config ? 1 : 0

  name = "config-s3-access"
  role = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "arn:aws:s3:::${var.config_s3_bucket}/${var.config_s3_prefix}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.config_s3_bucket}"
      }
    ]
  })
}

################################################################################
# Standard IAM Roles
################################################################################

resource "aws_iam_role" "admin" {
  count = var.create_admin_role ? 1 : 0

  name = "${var.name}-admin"
  path = var.iam_role_path

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_admin_principals
      }
      Condition = var.require_mfa ? {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      } : {}
    }]
  })

  max_session_duration = var.admin_session_duration

  tags = merge(var.tags, {
    Name = "${var.name}-admin"
    Role = "admin"
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  count = var.create_admin_role ? 1 : 0

  role       = aws_iam_role.admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "readonly" {
  count = var.create_readonly_role ? 1 : 0

  name = "${var.name}-readonly"
  path = var.iam_role_path

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_readonly_principals
      }
    }]
  })

  max_session_duration = var.readonly_session_duration

  tags = merge(var.tags, {
    Name = "${var.name}-readonly"
    Role = "readonly"
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  count = var.create_readonly_role ? 1 : 0

  role       = aws_iam_role.readonly[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
