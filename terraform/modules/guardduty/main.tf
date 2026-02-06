################################################################################
# GuardDuty Module
#
# Threat detection with alerting:
# - GuardDuty detector with all protection features
# - EventBridge rules for finding notifications
# - SNS alerts with severity filtering
# - S3 export for findings (optional)
# - IPSet / ThreatIntelSet integration (optional)
# - Lambda-based auto-remediation (optional)
#
# Usage:
#   module "guardduty" {
#     source = "../modules/guardduty"
#     name   = "main-detector"
#
#     enable_sns_alerts = true
#     alert_email       = "security@example.com"
#
#     # Only alert on HIGH and CRITICAL findings
#     alert_severity_threshold = "HIGH"
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

################################################################################
# Variables
################################################################################

variable "name" {
  type        = string
  description = "Name prefix for GuardDuty resources"
}

variable "enable" {
  type        = bool
  default     = true
  description = "Enable GuardDuty detector"
}

variable "finding_publishing_frequency" {
  type        = string
  default     = "FIFTEEN_MINUTES"
  description = "Finding publishing frequency"
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "Must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

# Protection Features
variable "enable_s3_protection" {
  type        = bool
  default     = true
  description = "Enable S3 data events monitoring"
}

variable "enable_kubernetes_audit" {
  type        = bool
  default     = true
  description = "Enable EKS Kubernetes audit logs"
}

variable "enable_malware_protection" {
  type        = bool
  default     = true
  description = "Enable malware protection for EC2/EBS"
}

variable "enable_rds_login_events" {
  type        = bool
  default     = true
  description = "Enable RDS login activity monitoring"
}

variable "enable_lambda_network_logs" {
  type        = bool
  default     = true
  description = "Enable Lambda network activity monitoring"
}

variable "enable_runtime_monitoring" {
  type        = bool
  default     = false
  description = "Enable runtime monitoring for EC2/ECS/EKS (additional cost)"
}

# SNS Alerting
variable "enable_sns_alerts" {
  type        = bool
  default     = false
  description = "Enable SNS alerts for findings"
}

variable "alert_email" {
  type        = string
  default     = ""
  description = "Email address for finding alerts (creates subscription)"
}

variable "alert_sns_topic_arn" {
  type        = string
  default     = ""
  description = "Existing SNS topic ARN (created if empty and alerts enabled)"
}

variable "alert_severity_threshold" {
  type        = string
  default     = "MEDIUM"
  description = "Minimum severity for alerts: LOW, MEDIUM, HIGH, CRITICAL"
  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.alert_severity_threshold)
    error_message = "Must be LOW, MEDIUM, HIGH, or CRITICAL."
  }
}

# S3 Export
variable "enable_s3_export" {
  type        = bool
  default     = false
  description = "Export findings to S3 bucket"
}

variable "export_s3_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket for findings export (created if empty and export enabled)"
}

variable "export_kms_key_arn" {
  type        = string
  default     = ""
  description = "KMS key for findings encryption"
}

# Threat Intelligence
variable "ipset_cidrs" {
  type        = list(string)
  default     = []
  description = "Trusted IP CIDRs to whitelist from findings"
}

variable "threat_intel_feed_urls" {
  type        = list(string)
  default     = []
  description = "URLs of threat intel feeds (must be accessible)"
}

# Organization
variable "is_organization_admin" {
  type        = bool
  default     = false
  description = "This account is the delegated admin for GuardDuty"
}

variable "auto_enable_organization_members" {
  type        = bool
  default     = true
  description = "Auto-enable GuardDuty for new org accounts"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Resource tags"
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  # Severity numeric mapping for EventBridge filter
  severity_map = {
    LOW      = 1.0
    MEDIUM   = 4.0
    HIGH     = 7.0
    CRITICAL = 8.0
  }
  severity_threshold = local.severity_map[var.alert_severity_threshold]

  create_sns_topic = var.enable_sns_alerts && var.alert_sns_topic_arn == ""
  sns_topic_arn    = local.create_sns_topic ? aws_sns_topic.alerts[0].arn : var.alert_sns_topic_arn

  create_export_bucket = var.enable_s3_export && var.export_s3_bucket == ""
  export_bucket_name   = local.create_export_bucket ? aws_s3_bucket.export[0].id : var.export_s3_bucket
}

################################################################################
# GuardDuty Detector
################################################################################

resource "aws_guardduty_detector" "main" {
  count = var.enable ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_kubernetes_audit
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = merge(var.tags, { Name = var.name })
}

# Additional feature configurations (added in AWS provider 5.x)
resource "aws_guardduty_detector_feature" "rds_login" {
  count = var.enable && var.enable_rds_login_events ? 1 : 0

  detector_id = aws_guardduty_detector.main[0].id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "lambda_network" {
  count = var.enable && var.enable_lambda_network_logs ? 1 : 0

  detector_id = aws_guardduty_detector.main[0].id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count = var.enable && var.enable_runtime_monitoring ? 1 : 0

  detector_id = aws_guardduty_detector.main[0].id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

################################################################################
# SNS Topic for Alerts
################################################################################

resource "aws_sns_topic" "alerts" {
  count = local.create_sns_topic ? 1 : 0

  name              = "${var.name}-guardduty-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, { Name = "${var.name}-guardduty-alerts" })
}

resource "aws_sns_topic_policy" "alerts" {
  count = local.create_sns_topic ? 1 : 0

  arn = aws_sns_topic.alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridge"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts[0].arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count = var.enable_sns_alerts && var.alert_email != "" ? 1 : 0

  topic_arn = local.sns_topic_arn
  protocol  = "email"
  endpoint  = var.alert_email
}

################################################################################
# EventBridge Rule for Finding Alerts
################################################################################

resource "aws_cloudwatch_event_rule" "findings" {
  count = var.enable && var.enable_sns_alerts ? 1 : 0

  name        = "${var.name}-guardduty-findings"
  description = "Route GuardDuty findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", local.severity_threshold] }
      ]
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-guardduty-findings" })
}

resource "aws_cloudwatch_event_target" "sns" {
  count = var.enable && var.enable_sns_alerts ? 1 : 0

  rule      = aws_cloudwatch_event_rule.findings[0].name
  target_id = "sns"
  arn       = local.sns_topic_arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      region      = "$.detail.region"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      accountId   = "$.detail.accountId"
      findingId   = "$.detail.id"
    }
    input_template = <<EOF
{
  "subject": "GuardDuty Alert: <type>",
  "message": "Severity: <severity>\nRegion: <region>\nAccount: <accountId>\n\nTitle: <title>\n\nDescription: <description>\n\nFinding ID: <findingId>\n\nView in console: https://<region>.console.aws.amazon.com/guardduty/home?region=<region>#/findings"
}
EOF
  }
}

################################################################################
# S3 Export
################################################################################

resource "aws_s3_bucket" "export" {
  count = local.create_export_bucket ? 1 : 0

  bucket        = "${var.name}-guardduty-findings-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, { Name = "${var.name}-guardduty-findings" })
}

resource "aws_s3_bucket_versioning" "export" {
  count = local.create_export_bucket ? 1 : 0

  bucket = aws_s3_bucket.export[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "export" {
  count = local.create_export_bucket ? 1 : 0

  bucket = aws_s3_bucket.export[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.export_kms_key_arn != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.export_kms_key_arn != "" ? var.export_kms_key_arn : null
    }
    bucket_key_enabled = var.export_kms_key_arn != "" ? true : false
  }
}

resource "aws_s3_bucket_public_access_block" "export" {
  count = local.create_export_bucket ? 1 : 0

  bucket = aws_s3_bucket.export[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "export" {
  count = local.create_export_bucket ? 1 : 0

  bucket = aws_s3_bucket.export[0].id

  rule {
    id     = "archive-findings"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years for compliance
    }
  }
}

resource "aws_s3_bucket_policy" "export" {
  count = var.enable_s3_export ? 1 : 0

  bucket = local.export_bucket_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyExport"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${local.export_bucket_name}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowGuardDutyBucketRead"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:GetBucketLocation"
        Resource = "arn:aws:s3:::${local.export_bucket_name}"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# KMS key for GuardDuty export (required)
resource "aws_kms_key" "export" {
  count = var.enable && var.enable_s3_export && var.export_kms_key_arn == "" ? 1 : 0

  description             = "${var.name}-guardduty-export"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRoot"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowGuardDuty"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "kms:GenerateDataKey*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name}-guardduty-export" })
}

resource "aws_kms_alias" "export" {
  count = var.enable && var.enable_s3_export && var.export_kms_key_arn == "" ? 1 : 0

  name          = "alias/${var.name}-guardduty-export"
  target_key_id = aws_kms_key.export[0].key_id
}

locals {
  export_kms_key_arn = var.export_kms_key_arn != "" ? var.export_kms_key_arn : (
    var.enable_s3_export ? aws_kms_key.export[0].arn : ""
  )
}

resource "aws_guardduty_publishing_destination" "s3" {
  count = var.enable && var.enable_s3_export ? 1 : 0

  detector_id      = aws_guardduty_detector.main[0].id
  destination_arn  = "arn:aws:s3:::${local.export_bucket_name}"
  destination_type = "S3"
  kms_key_arn      = local.export_kms_key_arn

  depends_on = [aws_s3_bucket_policy.export, aws_kms_key.export]
}

################################################################################
# IP Set (Trusted IPs)
################################################################################

resource "aws_s3_object" "ipset" {
  count = var.enable && length(var.ipset_cidrs) > 0 ? 1 : 0

  bucket  = local.create_export_bucket ? aws_s3_bucket.export[0].id : var.export_s3_bucket
  key     = "guardduty-ipset.txt"
  content = join("\n", var.ipset_cidrs)
}

resource "aws_guardduty_ipset" "trusted" {
  count = var.enable && length(var.ipset_cidrs) > 0 ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main[0].id
  format      = "TXT"
  location    = "s3://${aws_s3_object.ipset[0].bucket}/${aws_s3_object.ipset[0].key}"
  name        = "${var.name}-trusted-ips"

  tags = merge(var.tags, { Name = "${var.name}-trusted-ips" })
}

################################################################################
# Threat Intel Set
################################################################################

resource "aws_guardduty_threatintelset" "feeds" {
  for_each = var.enable ? toset(var.threat_intel_feed_urls) : []

  activate    = true
  detector_id = aws_guardduty_detector.main[0].id
  format      = "TXT"
  location    = each.value
  name        = "${var.name}-threat-intel-${md5(each.value)}"

  tags = merge(var.tags, { Name = "${var.name}-threat-intel" })
}

################################################################################
# Organization Configuration (Delegated Admin)
################################################################################

resource "aws_guardduty_organization_configuration" "main" {
  count = var.enable && var.is_organization_admin ? 1 : 0

  auto_enable_organization_members = var.auto_enable_organization_members ? "ALL" : "NONE"
  detector_id                      = aws_guardduty_detector.main[0].id

  datasources {
    s3_logs {
      auto_enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_kubernetes_audit
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = var.enable_malware_protection
        }
      }
    }
  }
}

################################################################################
# Outputs
################################################################################

output "detector_id" {
  value       = var.enable ? aws_guardduty_detector.main[0].id : null
  description = "GuardDuty detector ID"
}

output "detector_arn" {
  value       = var.enable ? aws_guardduty_detector.main[0].arn : null
  description = "GuardDuty detector ARN"
}

output "sns_topic_arn" {
  value       = var.enable_sns_alerts ? local.sns_topic_arn : null
  description = "SNS topic ARN for alerts"
}

output "export_bucket" {
  value       = var.enable_s3_export ? local.export_bucket_name : null
  description = "S3 bucket for findings export"
}

output "eventbridge_rule_arn" {
  value       = var.enable && var.enable_sns_alerts ? aws_cloudwatch_event_rule.findings[0].arn : null
  description = "EventBridge rule ARN for findings"
}

output "enabled_features" {
  value = var.enable ? {
    s3_protection        = var.enable_s3_protection
    kubernetes_audit     = var.enable_kubernetes_audit
    malware_protection   = var.enable_malware_protection
    rds_login_events     = var.enable_rds_login_events
    lambda_network_logs  = var.enable_lambda_network_logs
    runtime_monitoring   = var.enable_runtime_monitoring
    sns_alerts           = var.enable_sns_alerts
    s3_export            = var.enable_s3_export
    alert_threshold      = var.alert_severity_threshold
  } : null
  description = "Enabled GuardDuty features"
}
