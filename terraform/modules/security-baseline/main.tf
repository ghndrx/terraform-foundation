################################################################################
# Security Baseline Module
#
# Enables core AWS security services:
# - GuardDuty (threat detection)
# - Security Hub (security posture)
# - AWS Config (configuration compliance)
# - IAM Access Analyzer
#
# For multi-account: Deploy in management account, then enable delegated admin
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
  description = "Name prefix for resources"
}

variable "enable_guardduty" {
  type    = bool
  default = true
}

variable "enable_securityhub" {
  type    = bool
  default = true
}

variable "enable_config" {
  type    = bool
  default = true
}

variable "enable_access_analyzer" {
  type    = bool
  default = true
}

variable "enable_macie" {
  type        = bool
  default     = false
  description = "Macie for S3 data classification (additional cost)"
}

variable "config_bucket_name" {
  type        = string
  description = "S3 bucket for AWS Config recordings"
}

variable "guardduty_finding_publishing_frequency" {
  type    = string
  default = "FIFTEEN_MINUTES"
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_publishing_frequency)
    error_message = "Must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS"
  }
}

variable "securityhub_standards" {
  type = list(string)
  default = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/1.4.0",
  ]
  description = "Security Hub standards to enable"
}

variable "config_rules" {
  type        = list(string)
  default     = []
  description = "Additional AWS Config managed rule identifiers to enable"
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# GuardDuty
################################################################################

resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-guardduty" })
}

################################################################################
# Security Hub
################################################################################

resource "aws_securityhub_account" "main" {
  count = var.enable_securityhub ? 1 : 0

  enable_default_standards = false
  auto_enable_controls     = true

  depends_on = [aws_guardduty_detector.main]
}

resource "aws_securityhub_standards_subscription" "standards" {
  for_each = var.enable_securityhub ? toset(var.securityhub_standards) : []

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/${each.value}"

  depends_on = [aws_securityhub_account.main]
}

################################################################################
# AWS Config
################################################################################

resource "aws_config_configuration_recorder" "main" {
  count = var.enable_config ? 1 : 0

  name     = var.name
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "main" {
  count = var.enable_config ? 1 : 0

  name           = var.name
  s3_bucket_name = var.config_bucket_name
  s3_key_prefix  = "config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# IAM Role for Config
resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0
  name  = "${var.name}-config"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name}-config" })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_config ? 1 : 0
  name  = "s3-delivery"
  role  = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:PutObjectAcl"]
      Resource = "arn:aws:s3:::${var.config_bucket_name}/config/*"
      Condition = {
        StringEquals = {
          "s3:x-amz-acl" = "bucket-owner-full-control"
        }
      }
    }, {
      Effect   = "Allow"
      Action   = ["s3:GetBucketAcl"]
      Resource = "arn:aws:s3:::${var.config_bucket_name}"
    }]
  })
}

################################################################################
# AWS Config Rules - Security Best Practices
################################################################################

locals {
  default_config_rules = [
    "ENCRYPTED_VOLUMES",
    "RDS_STORAGE_ENCRYPTED",
    "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    "S3_BUCKET_SSL_REQUESTS_ONLY",
    "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
    "RESTRICTED_SSH",
    "VPC_DEFAULT_SECURITY_GROUP_CLOSED",
    "VPC_FLOW_LOGS_ENABLED",
    "CLOUD_TRAIL_ENABLED",
    "CLOUD_TRAIL_ENCRYPTION_ENABLED",
    "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED",
    "IAM_ROOT_ACCESS_KEY_CHECK",
    "IAM_USER_MFA_ENABLED",
    "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
    "ROOT_ACCOUNT_MFA_ENABLED",
    "RDS_INSTANCE_PUBLIC_ACCESS_CHECK",
    "GUARDDUTY_ENABLED_CENTRALIZED",
    "SECURITYHUB_ENABLED",
    "EBS_OPTIMIZED_INSTANCE",
    "EC2_IMDSV2_CHECK",
    "EKS_SECRETS_ENCRYPTED",
    "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED",
    "LAMBDA_INSIDE_VPC",
  ]

  all_config_rules = distinct(concat(local.default_config_rules, var.config_rules))
}

resource "aws_config_config_rule" "rules" {
  for_each = var.enable_config ? toset(local.all_config_rules) : []

  name = lower(replace(each.value, "_", "-"))

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = merge(var.tags, { Name = lower(replace(each.value, "_", "-")) })
}

################################################################################
# IAM Access Analyzer
################################################################################

resource "aws_accessanalyzer_analyzer" "main" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = var.name
  type          = "ACCOUNT"

  tags = merge(var.tags, { Name = "${var.name}-access-analyzer" })
}

################################################################################
# Macie (Optional)
################################################################################

resource "aws_macie2_account" "main" {
  count = var.enable_macie ? 1 : 0

  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}

################################################################################
# Outputs
################################################################################

output "guardduty_detector_id" {
  value = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}

output "securityhub_account_id" {
  value = var.enable_securityhub ? aws_securityhub_account.main[0].id : null
}

output "config_recorder_id" {
  value = var.enable_config ? aws_config_configuration_recorder.main[0].id : null
}

output "access_analyzer_arn" {
  value = var.enable_access_analyzer ? aws_accessanalyzer_analyzer.main[0].arn : null
}

output "enabled_services" {
  value = {
    guardduty       = var.enable_guardduty
    securityhub     = var.enable_securityhub
    config          = var.enable_config
    access_analyzer = var.enable_access_analyzer
    macie           = var.enable_macie
  }
}
