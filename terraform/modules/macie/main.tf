################################################################################
# AWS Macie Module
#
# Sensitive data discovery and classification:
# - Automated S3 bucket scanning
# - Custom data identifiers (PII, secrets, custom patterns)
# - Findings export and alerts
# - Classification job scheduling
# - Organization-wide deployment
#
# Usage:
#   module "macie" {
#     source = "../modules/macie"
#     name   = "data-discovery"
#
#     enable_auto_discovery = true
#     auto_discovery_buckets = ["my-data-bucket", "another-bucket"]
#
#     enable_sns_alerts = true
#     alert_email       = "security@example.com"
#
#     # Custom data identifiers
#     custom_data_identifiers = {
#       api_key = {
#         regex       = "(api[_-]?key|apikey)[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9]{20,}"
#         keywords    = ["api_key", "apikey", "api-key"]
#         description = "API key patterns"
#       }
#     }
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
  description = "Name prefix for Macie resources"
}

variable "enable" {
  type        = bool
  default     = true
  description = "Enable Macie"
}

variable "finding_publishing_frequency" {
  type        = string
  default     = "FIFTEEN_MINUTES"
  description = "Findings publishing frequency"
  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "Must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "status" {
  type        = string
  default     = "ENABLED"
  description = "Macie account status"
  validation {
    condition     = contains(["ENABLED", "PAUSED"], var.status)
    error_message = "Must be ENABLED or PAUSED."
  }
}

# Auto-Discovery
variable "enable_auto_discovery" {
  type        = bool
  default     = false
  description = "Enable automated sensitive data discovery"
}

variable "auto_discovery_buckets" {
  type        = list(string)
  default     = []
  description = "S3 bucket names for auto-discovery (empty = all buckets)"
}

variable "exclude_buckets" {
  type        = list(string)
  default     = []
  description = "S3 bucket names to exclude from scanning"
}

# Classification Jobs
variable "classification_jobs" {
  type = map(object({
    description     = optional(string, "")
    bucket_names    = list(string)
    schedule        = optional(string, "")  # cron expression, empty = one-time
    sampling_percentage = optional(number, 100)
    initial_run     = optional(bool, true)
    tags            = optional(map(string), {})
  }))
  default     = {}
  description = "Classification jobs configuration"
}

# Custom Data Identifiers
variable "custom_data_identifiers" {
  type = map(object({
    regex                = string
    keywords             = optional(list(string), [])
    ignore_words         = optional(list(string), [])
    description          = optional(string, "")
    maximum_match_distance = optional(number, 50)
  }))
  default     = {}
  description = "Custom data identifiers (regex patterns)"
}

# Findings Filter
variable "findings_filters" {
  type = map(object({
    action      = string  # ARCHIVE or NOOP
    description = optional(string, "")
    criteria    = map(any)  # Filter criteria
  }))
  default     = {}
  description = "Findings filter rules"
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
  description = "Email address for finding alerts"
}

variable "alert_sns_topic_arn" {
  type        = string
  default     = ""
  description = "Existing SNS topic ARN (created if empty and alerts enabled)"
}

variable "alert_severity_threshold" {
  type        = string
  default     = "MEDIUM"
  description = "Minimum severity for alerts: LOW, MEDIUM, HIGH"
  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH"], var.alert_severity_threshold)
    error_message = "Must be LOW, MEDIUM, or HIGH."
  }
}

# S3 Export
variable "enable_s3_export" {
  type        = bool
  default     = false
  description = "Export findings to S3"
}

variable "export_s3_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket for findings export (created if empty and export enabled)"
}

variable "export_kms_key_arn" {
  type        = string
  default     = ""
  description = "KMS key for export encryption"
}

# Organization
variable "is_organization_admin" {
  type        = bool
  default     = false
  description = "This account is the delegated admin for Macie"
}

variable "auto_enable_organization_members" {
  type        = bool
  default     = true
  description = "Auto-enable Macie for new org accounts"
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
  severity_map = {
    LOW    = 1
    MEDIUM = 2
    HIGH   = 3
  }
  severity_threshold = local.severity_map[var.alert_severity_threshold]

  create_sns_topic = var.enable_sns_alerts && var.alert_sns_topic_arn == ""
  sns_topic_arn    = local.create_sns_topic ? aws_sns_topic.alerts[0].arn : var.alert_sns_topic_arn

  create_export_bucket = var.enable_s3_export && var.export_s3_bucket == ""
  export_bucket_name   = local.create_export_bucket ? aws_s3_bucket.export[0].id : var.export_s3_bucket
}

################################################################################
# Macie Account
################################################################################

resource "aws_macie2_account" "main" {
  count = var.enable ? 1 : 0

  finding_publishing_frequency = var.finding_publishing_frequency
  status                       = var.status
}

################################################################################
# Auto-Discovery Configuration
################################################################################

resource "aws_macie2_classification_export_configuration" "main" {
  count = var.enable && var.enable_s3_export ? 1 : 0

  depends_on = [aws_macie2_account.main]

  s3_destination {
    bucket_name = local.export_bucket_name
    key_prefix  = "macie-findings/"
    kms_key_arn = local.export_kms_key_arn
  }
}

################################################################################
# Custom Data Identifiers
################################################################################

resource "aws_macie2_custom_data_identifier" "identifiers" {
  for_each = var.enable ? var.custom_data_identifiers : {}

  name                   = "${var.name}-${each.key}"
  regex                  = each.value.regex
  keywords               = length(each.value.keywords) > 0 ? each.value.keywords : null
  ignore_words           = length(each.value.ignore_words) > 0 ? each.value.ignore_words : null
  description            = each.value.description != "" ? each.value.description : "Custom identifier: ${each.key}"
  maximum_match_distance = each.value.maximum_match_distance

  tags = merge(var.tags, { Name = "${var.name}-${each.key}" })

  depends_on = [aws_macie2_account.main]
}

################################################################################
# Classification Jobs
################################################################################

resource "aws_macie2_classification_job" "jobs" {
  for_each = var.enable ? var.classification_jobs : {}

  name        = "${var.name}-${each.key}"
  description = each.value.description != "" ? each.value.description : "Classification job: ${each.key}"
  job_type    = each.value.schedule != "" ? "SCHEDULED" : "ONE_TIME"
  initial_run = each.value.initial_run

  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.current.account_id
      buckets    = each.value.bucket_names
    }

    dynamic "scoping" {
      for_each = each.value.sampling_percentage < 100 ? [1] : []
      content {
        includes {
          and {
            simple_scope_term {
              comparator = "EQ"
              key        = "OBJECT_EXTENSION"
              values     = ["*"]
            }
          }
        }
      }
    }
  }

  sampling_percentage = each.value.sampling_percentage

  dynamic "schedule_frequency" {
    for_each = each.value.schedule != "" ? [1] : []
    content {
      # Daily at midnight UTC by default
      daily_schedule = true
    }
  }

  # Include custom data identifiers
  custom_data_identifier_ids = [
    for k, v in aws_macie2_custom_data_identifier.identifiers : v.id
  ]

  tags = merge(var.tags, each.value.tags, { Name = "${var.name}-${each.key}" })

  depends_on = [aws_macie2_account.main, aws_macie2_custom_data_identifier.identifiers]
}

################################################################################
# Findings Filters
################################################################################

resource "aws_macie2_findings_filter" "filters" {
  for_each = var.enable ? var.findings_filters : {}

  name        = "${var.name}-${each.key}"
  description = each.value.description != "" ? each.value.description : "Filter: ${each.key}"
  action      = each.value.action
  position    = 1

  finding_criteria {
    criterion {
      field = "severity.description"
      eq    = lookup(each.value.criteria, "severity", null) != null ? [each.value.criteria.severity] : null
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-${each.key}" })

  depends_on = [aws_macie2_account.main]
}

################################################################################
# SNS Topic for Alerts
################################################################################

resource "aws_sns_topic" "alerts" {
  count = local.create_sns_topic ? 1 : 0

  name              = "${var.name}-macie-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, { Name = "${var.name}-macie-alerts" })
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

  name        = "${var.name}-macie-findings"
  description = "Route Macie findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.macie"]
    detail-type = ["Macie Finding"]
    detail = {
      severity = {
        description = var.alert_severity_threshold == "LOW" ? ["Low", "Medium", "High"] : (
          var.alert_severity_threshold == "MEDIUM" ? ["Medium", "High"] : ["High"]
        )
      }
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-macie-findings" })
}

resource "aws_cloudwatch_event_target" "sns" {
  count = var.enable && var.enable_sns_alerts ? 1 : 0

  rule      = aws_cloudwatch_event_rule.findings[0].name
  target_id = "sns"
  arn       = local.sns_topic_arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity.description"
      type        = "$.detail.type"
      bucket      = "$.detail.resourcesAffected.s3Bucket.name"
      object      = "$.detail.resourcesAffected.s3Object.key"
      category    = "$.detail.category"
      description = "$.detail.description"
      findingId   = "$.detail.id"
      region      = "$.detail.region"
    }
    input_template = <<EOF
{
  "subject": "Macie Alert: Sensitive Data Found in S3",
  "message": "Severity: <severity>\nCategory: <category>\nType: <type>\n\nBucket: <bucket>\nObject: <object>\n\nDescription: <description>\n\nFinding ID: <findingId>\nRegion: <region>\n\nView in console: https://<region>.console.aws.amazon.com/macie/home?region=<region>#/findings"
}
EOF
  }
}

################################################################################
# S3 Export Bucket
################################################################################

resource "aws_s3_bucket" "export" {
  count = local.create_export_bucket ? 1 : 0

  bucket        = "${var.name}-macie-findings-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, { Name = "${var.name}-macie-findings" })
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
        Sid    = "AllowMacieExport"
        Effect = "Allow"
        Principal = {
          Service = "macie.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "arn:aws:s3:::${local.export_bucket_name}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowMacieBucketRead"
        Effect = "Allow"
        Principal = {
          Service = "macie.amazonaws.com"
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

# KMS key for Macie export
resource "aws_kms_key" "export" {
  count = var.enable && var.enable_s3_export && var.export_kms_key_arn == "" ? 1 : 0

  description             = "${var.name}-macie-export"
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
        Sid    = "AllowMacie"
        Effect = "Allow"
        Principal = {
          Service = "macie.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name}-macie-export" })
}

resource "aws_kms_alias" "export" {
  count = var.enable && var.enable_s3_export && var.export_kms_key_arn == "" ? 1 : 0

  name          = "alias/${var.name}-macie-export"
  target_key_id = aws_kms_key.export[0].key_id
}

locals {
  export_kms_key_arn = var.export_kms_key_arn != "" ? var.export_kms_key_arn : (
    var.enable_s3_export ? aws_kms_key.export[0].arn : ""
  )
}

################################################################################
# Organization Configuration (Delegated Admin)
################################################################################

resource "aws_macie2_organization_admin_account" "main" {
  count = var.enable && var.is_organization_admin ? 1 : 0

  admin_account_id = data.aws_caller_identity.current.account_id

  depends_on = [aws_macie2_account.main]
}

################################################################################
# Outputs
################################################################################

output "account_id" {
  value       = var.enable ? aws_macie2_account.main[0].id : null
  description = "Macie account ID"
}

output "account_status" {
  value       = var.enable ? aws_macie2_account.main[0].status : null
  description = "Macie account status"
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

output "custom_data_identifiers" {
  value = var.enable ? {
    for k, v in aws_macie2_custom_data_identifier.identifiers : k => {
      id   = v.id
      arn  = v.arn
      name = v.name
    }
  } : null
  description = "Custom data identifier details"
}

output "classification_jobs" {
  value = var.enable ? {
    for k, v in aws_macie2_classification_job.jobs : k => {
      id        = v.id
      job_arn   = v.job_arn
      job_type  = v.job_type
      job_status = v.job_status
    }
  } : null
  description = "Classification job details"
}

output "enabled_features" {
  value = var.enable ? {
    auto_discovery = var.enable_auto_discovery
    sns_alerts     = var.enable_sns_alerts
    s3_export      = var.enable_s3_export
    alert_threshold = var.alert_severity_threshold
    custom_identifiers = length(var.custom_data_identifiers)
    classification_jobs = length(var.classification_jobs)
  } : null
  description = "Enabled Macie features"
}
