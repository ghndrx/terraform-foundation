################################################################################
# Amazon Inspector Module
#
# Automated vulnerability scanning for:
# - EC2 instances (OS and package vulnerabilities)
# - ECR container images (before and after deployment)
# - Lambda functions (package dependencies)
#
# Integrations:
# - Security Hub findings export (automatic)
# - EventBridge for custom alerting
# - S3 export for compliance archival
#
# Usage:
#   module "inspector" {
#     source = "../modules/inspector"
#     name   = "main"
#
#     enable_ec2_scanning    = true
#     enable_ecr_scanning    = true
#     enable_lambda_scanning = true
#
#     enable_sns_alerts = true
#     alert_email       = "security@example.com"
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
  description = "Name prefix for Inspector resources"
}

variable "enable" {
  type        = bool
  default     = true
  description = "Enable Amazon Inspector"
}

# Scanning Types
variable "enable_ec2_scanning" {
  type        = bool
  default     = true
  description = "Enable EC2 instance vulnerability scanning"
}

variable "enable_ecr_scanning" {
  type        = bool
  default     = true
  description = "Enable ECR container image scanning"
}

variable "enable_lambda_scanning" {
  type        = bool
  default     = true
  description = "Enable Lambda function code scanning"
}

variable "enable_lambda_code_scanning" {
  type        = bool
  default     = false
  description = "Enable Lambda code vulnerability scanning (additional cost)"
}

# ECR Configuration
variable "ecr_scan_on_push" {
  type        = bool
  default     = true
  description = "Automatically scan images when pushed to ECR"
}

variable "ecr_continuous_scan" {
  type        = bool
  default     = true
  description = "Continuously rescan images for new vulnerabilities"
}

variable "ecr_rescan_duration" {
  type        = string
  default     = "LIFETIME"
  description = "Duration to rescan ECR images: DAYS_30, DAYS_60, DAYS_90, DAYS_180, LIFETIME"
  validation {
    condition     = contains(["DAYS_30", "DAYS_60", "DAYS_90", "DAYS_180", "LIFETIME"], var.ecr_rescan_duration)
    error_message = "Must be DAYS_30, DAYS_60, DAYS_90, DAYS_180, or LIFETIME."
  }
}

variable "ecr_filter_repositories" {
  type        = list(string)
  default     = []
  description = "ECR repository names to scan (empty = all repositories)"
}

# EC2 Configuration
variable "ec2_scan_mode" {
  type        = string
  default     = "EC2_SSM_AGENT_BASED"
  description = "EC2 scanning mode: EC2_SSM_AGENT_BASED or EC2_AGENTLESS"
  validation {
    condition     = contains(["EC2_SSM_AGENT_BASED", "EC2_AGENTLESS"], var.ec2_scan_mode)
    error_message = "Must be EC2_SSM_AGENT_BASED or EC2_AGENTLESS."
  }
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

variable "alert_severity" {
  type        = list(string)
  default     = ["CRITICAL", "HIGH"]
  description = "Finding severities to alert on"
}

# Suppression Rules
variable "suppression_rules" {
  type = list(object({
    name        = string
    description = string
    filter = object({
      comparison = string
      value      = string
    })
  }))
  default     = []
  description = "Suppression rules for known/accepted findings"
}

# Organization
variable "is_delegated_admin" {
  type        = bool
  default     = false
  description = "This account is the delegated admin for Inspector"
}

variable "auto_enable_org_members" {
  type        = bool
  default     = true
  description = "Auto-enable Inspector for new organization member accounts"
}

# S3 Export
variable "enable_findings_export" {
  type        = bool
  default     = false
  description = "Export findings to S3 for compliance/archival"
}

variable "findings_export_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket for findings export (created if empty)"
}

variable "findings_export_kms_key_arn" {
  type        = string
  default     = ""
  description = "KMS key for findings encryption"
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
  create_sns_topic = var.enable_sns_alerts && var.alert_sns_topic_arn == ""
  sns_topic_arn    = local.create_sns_topic ? aws_sns_topic.alerts[0].arn : var.alert_sns_topic_arn

  create_export_bucket = var.enable_findings_export && var.findings_export_bucket == ""
  export_bucket_name   = local.create_export_bucket ? aws_s3_bucket.findings[0].id : var.findings_export_bucket
}

################################################################################
# Inspector Enablement
################################################################################

resource "aws_inspector2_enabler" "main" {
  count = var.enable ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = compact([
    var.enable_ec2_scanning ? "EC2" : "",
    var.enable_ecr_scanning ? "ECR" : "",
    var.enable_lambda_scanning ? "LAMBDA" : "",
    var.enable_lambda_code_scanning ? "LAMBDA_CODE" : "",
  ])
}

################################################################################
# Organization Configuration (Delegated Admin)
################################################################################

resource "aws_inspector2_organization_configuration" "main" {
  count = var.enable && var.is_delegated_admin ? 1 : 0

  auto_enable {
    ec2         = var.auto_enable_org_members && var.enable_ec2_scanning
    ecr         = var.auto_enable_org_members && var.enable_ecr_scanning
    lambda      = var.auto_enable_org_members && var.enable_lambda_scanning
    lambda_code = var.auto_enable_org_members && var.enable_lambda_code_scanning
  }

  depends_on = [aws_inspector2_enabler.main]
}

################################################################################
# ECR Scanning Configuration
################################################################################

resource "aws_inspector2_member_association" "ecr_config" {
  count = var.enable && var.enable_ecr_scanning ? 1 : 0

  account_id = data.aws_caller_identity.current.account_id

  depends_on = [aws_inspector2_enabler.main]
}

# Note: ECR enhanced scanning is configured at the registry level
# This sets up the scanning configuration
resource "aws_ecr_registry_scanning_configuration" "main" {
  count = var.enable && var.enable_ecr_scanning ? 1 : 0

  scan_type = "ENHANCED"

  rule {
    scan_frequency = var.ecr_continuous_scan ? "CONTINUOUS_SCAN" : "SCAN_ON_PUSH"

    repository_filter {
      filter      = length(var.ecr_filter_repositories) > 0 ? join(",", var.ecr_filter_repositories) : "*"
      filter_type = length(var.ecr_filter_repositories) > 0 ? "REPOSITORY" : "WILDCARD"
    }
  }
}

################################################################################
# SNS Topic for Alerts
################################################################################

resource "aws_sns_topic" "alerts" {
  count = local.create_sns_topic ? 1 : 0

  name              = "${var.name}-inspector-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, { Name = "${var.name}-inspector-alerts" })
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

  name        = "${var.name}-inspector-findings"
  description = "Route Inspector findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Finding"]
    detail = {
      severity = var.alert_severity
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-inspector-findings" })
}

resource "aws_cloudwatch_event_target" "sns" {
  count = var.enable && var.enable_sns_alerts ? 1 : 0

  rule      = aws_cloudwatch_event_rule.findings[0].name
  target_id = "sns"
  arn       = local.sns_topic_arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      title       = "$.detail.title"
      description = "$.detail.description"
      accountId   = "$.detail.awsAccountId"
      resourceId  = "$.detail.resources[0].id"
      resourceType = "$.detail.resources[0].type"
      findingArn  = "$.detail.findingArn"
      cve         = "$.detail.packageVulnerabilityDetails.vulnerabilityId"
    }
    input_template = <<EOF
{
  "subject": "Inspector Alert [<severity>]: <title>",
  "message": "Severity: <severity>\nAccount: <accountId>\n\nTitle: <title>\n\nDescription: <description>\n\nResource: <resourceType> - <resourceId>\n\nCVE: <cve>\n\nFinding ARN: <findingArn>\n\nView in console: https://console.aws.amazon.com/inspector/v2/home#/findings"
}
EOF
  }
}

################################################################################
# EventBridge Rule for Coverage Changes
################################################################################

resource "aws_cloudwatch_event_rule" "coverage" {
  count = var.enable && var.enable_sns_alerts ? 1 : 0

  name        = "${var.name}-inspector-coverage"
  description = "Alert on Inspector coverage changes"

  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Coverage"]
    detail = {
      "scan-status" = ["INACTIVE"]
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-inspector-coverage" })
}

resource "aws_cloudwatch_event_target" "coverage_sns" {
  count = var.enable && var.enable_sns_alerts ? 1 : 0

  rule      = aws_cloudwatch_event_rule.coverage[0].name
  target_id = "sns"
  arn       = local.sns_topic_arn

  input_transformer {
    input_paths = {
      accountId    = "$.detail.account-id"
      resourceId   = "$.detail.resource-id"
      resourceType = "$.detail.resource-type"
      scanStatus   = "$.detail.scan-status"
      reason       = "$.detail.scan-status-reason"
    }
    input_template = <<EOF
{
  "subject": "Inspector Coverage Alert: Resource Not Scanned",
  "message": "Account: <accountId>\n\nResource: <resourceType> - <resourceId>\n\nStatus: <scanStatus>\nReason: <reason>\n\nAction Required: Ensure SSM agent is installed and running, or check IAM permissions."
}
EOF
  }
}

################################################################################
# S3 Bucket for Findings Export
################################################################################

resource "aws_s3_bucket" "findings" {
  count = local.create_export_bucket ? 1 : 0

  bucket        = "${var.name}-inspector-findings-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, { Name = "${var.name}-inspector-findings" })
}

resource "aws_s3_bucket_versioning" "findings" {
  count = local.create_export_bucket ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  count = local.create_export_bucket ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.findings_export_kms_key_arn != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.findings_export_kms_key_arn != "" ? var.findings_export_kms_key_arn : null
    }
    bucket_key_enabled = var.findings_export_kms_key_arn != "" ? true : false
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  count = local.create_export_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.findings[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  count = local.create_export_bucket ? 1 : 0

  bucket = aws_s3_bucket.findings[0].id

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

################################################################################
# KMS Key for Export (if not provided)
################################################################################

resource "aws_kms_key" "findings" {
  count = var.enable && var.enable_findings_export && var.findings_export_kms_key_arn == "" ? 1 : 0

  description             = "${var.name}-inspector-findings"
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
        Sid    = "AllowInspector"
        Effect = "Allow"
        Principal = {
          Service = "inspector2.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Encrypt"
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

  tags = merge(var.tags, { Name = "${var.name}-inspector-findings" })
}

resource "aws_kms_alias" "findings" {
  count = var.enable && var.enable_findings_export && var.findings_export_kms_key_arn == "" ? 1 : 0

  name          = "alias/${var.name}-inspector-findings"
  target_key_id = aws_kms_key.findings[0].key_id
}

################################################################################
# Suppression Rules
################################################################################

resource "aws_inspector2_filter" "suppression" {
  for_each = var.enable ? { for rule in var.suppression_rules : rule.name => rule } : {}

  name   = each.value.name
  action = "SUPPRESS"

  filter_criteria {
    finding_status {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Dynamic filter based on provided criteria
    dynamic "title" {
      for_each = each.value.filter.comparison == "TITLE" ? [1] : []
      content {
        comparison = "EQUALS"
        value      = each.value.filter.value
      }
    }

    dynamic "vulnerability_id" {
      for_each = each.value.filter.comparison == "CVE" ? [1] : []
      content {
        comparison = "EQUALS"
        value      = each.value.filter.value
      }
    }
  }

  description = each.value.description

  depends_on = [aws_inspector2_enabler.main]
}

################################################################################
# Outputs
################################################################################

output "enabled" {
  value       = var.enable
  description = "Whether Inspector is enabled"
}

output "enabled_resource_types" {
  value = var.enable ? compact([
    var.enable_ec2_scanning ? "EC2" : "",
    var.enable_ecr_scanning ? "ECR" : "",
    var.enable_lambda_scanning ? "LAMBDA" : "",
    var.enable_lambda_code_scanning ? "LAMBDA_CODE" : "",
  ]) : []
  description = "Enabled resource types for scanning"
}

output "sns_topic_arn" {
  value       = var.enable_sns_alerts ? local.sns_topic_arn : null
  description = "SNS topic ARN for alerts"
}

output "eventbridge_rule_arn" {
  value       = var.enable && var.enable_sns_alerts ? aws_cloudwatch_event_rule.findings[0].arn : null
  description = "EventBridge rule ARN for finding alerts"
}

output "findings_bucket" {
  value       = var.enable_findings_export ? local.export_bucket_name : null
  description = "S3 bucket for findings export"
}

output "findings_kms_key_arn" {
  value       = var.enable && var.enable_findings_export && var.findings_export_kms_key_arn == "" ? aws_kms_key.findings[0].arn : var.findings_export_kms_key_arn
  description = "KMS key ARN for findings encryption"
}

output "scanning_configuration" {
  value = var.enable ? {
    ec2_scanning       = var.enable_ec2_scanning
    ec2_scan_mode      = var.ec2_scan_mode
    ecr_scanning       = var.enable_ecr_scanning
    ecr_scan_on_push   = var.ecr_scan_on_push
    ecr_continuous     = var.ecr_continuous_scan
    ecr_rescan_duration = var.ecr_rescan_duration
    lambda_scanning    = var.enable_lambda_scanning
    lambda_code_scanning = var.enable_lambda_code_scanning
  } : null
  description = "Inspector scanning configuration"
}
