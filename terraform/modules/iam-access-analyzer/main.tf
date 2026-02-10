################################################################################
# IAM Access Analyzer Module
#
# Analyzes resource policies to identify unintended external access:
# - S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues
# - Findings for public/cross-account access
# - Archive rules for known-good patterns
# - SNS notifications for new findings
# - Unused access analysis (optional)
#
# Usage:
#   module "access_analyzer" {
#     source = "../modules/iam-access-analyzer"
#     
#     name = "organization-analyzer"
#     type = "ORGANIZATION"  # or "ACCOUNT"
#     
#     enable_unused_access = true
#     unused_access_age    = 90
#     
#     archive_rules = {
#       trusted_org = {
#         filter_type  = "AWS::IAM::Role"
#         principal_org_id = "o-xxxxxxxxxx"
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

variable "name" {
  type        = string
  default     = "default-analyzer"
  description = "Access Analyzer name"
}

variable "type" {
  type        = string
  default     = "ACCOUNT"
  description = "Analyzer type: ACCOUNT or ORGANIZATION (org requires delegated admin)"
  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION", "ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"], var.type)
    error_message = "Type must be ACCOUNT, ORGANIZATION, ACCOUNT_UNUSED_ACCESS, or ORGANIZATION_UNUSED_ACCESS"
  }
}

variable "enable_unused_access" {
  type        = bool
  default     = false
  description = "Enable unused access analyzer (identifies unused permissions)"
}

variable "unused_access_age_days" {
  type        = number
  default     = 90
  description = "Days of inactivity before flagging unused access"
}

variable "enable_sns_notifications" {
  type        = bool
  default     = false
  description = "Create SNS topic for Access Analyzer findings"
}

variable "sns_topic_arn" {
  type        = string
  default     = ""
  description = "Existing SNS topic ARN for notifications (creates one if empty and enabled)"
}

variable "notification_emails" {
  type        = list(string)
  default     = []
  description = "Email addresses to notify for new findings"
}

variable "archive_rules" {
  type = map(object({
    description   = optional(string, "")
    filter_criteria = list(object({
      criterion = string
      values    = list(string)
      exists    = optional(bool)
      eq        = optional(list(string))
      neq       = optional(list(string))
      contains  = optional(list(string))
    }))
  }))
  default     = {}
  description = "Archive rules for known-good access patterns"
}

# Pre-built archive rule templates
variable "archive_trusted_organization" {
  type        = string
  default     = ""
  description = "Organization ID to trust (auto-creates archive rule)"
}

variable "archive_trusted_accounts" {
  type        = list(string)
  default     = []
  description = "Account IDs to trust (auto-creates archive rule)"
}

variable "archive_trusted_principals" {
  type        = list(string)
  default     = []
  description = "Principal ARNs to trust (auto-creates archive rule)"
}

variable "enable_eventbridge" {
  type        = bool
  default     = false
  description = "Enable EventBridge rule for findings"
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
data "aws_partition" "current" {}

################################################################################
# Access Analyzer
################################################################################

resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = var.name
  type          = var.type

  tags = merge(var.tags, { Name = var.name })
}

# Unused Access Analyzer (separate analyzer with different type)
resource "aws_accessanalyzer_analyzer" "unused_access" {
  count = var.enable_unused_access ? 1 : 0

  analyzer_name = "${var.name}-unused-access"
  type          = var.type == "ORGANIZATION" ? "ORGANIZATION_UNUSED_ACCESS" : "ACCOUNT_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-unused-access" })
}

################################################################################
# Archive Rules
################################################################################

# Archive rule for trusted organization
resource "aws_accessanalyzer_archive_rule" "trusted_org" {
  count = var.archive_trusted_organization != "" ? 1 : 0

  analyzer_name = aws_accessanalyzer_analyzer.main.analyzer_name
  rule_name     = "trusted-organization"

  filter {
    criteria = "principal.AWS"
    contains = ["arn:${data.aws_partition.current.partition}:iam::*:root"]
  }

  filter {
    criteria = "condition.aws:PrincipalOrgID"
    eq       = [var.archive_trusted_organization]
  }
}

# Archive rules for trusted accounts
resource "aws_accessanalyzer_archive_rule" "trusted_accounts" {
  count = length(var.archive_trusted_accounts) > 0 ? 1 : 0

  analyzer_name = aws_accessanalyzer_analyzer.main.analyzer_name
  rule_name     = "trusted-accounts"

  filter {
    criteria = "principal.AWS"
    contains = [for acc in var.archive_trusted_accounts : "arn:${data.aws_partition.current.partition}:iam::${acc}:root"]
  }
}

# Archive rules for trusted principals
resource "aws_accessanalyzer_archive_rule" "trusted_principals" {
  count = length(var.archive_trusted_principals) > 0 ? 1 : 0

  analyzer_name = aws_accessanalyzer_analyzer.main.analyzer_name
  rule_name     = "trusted-principals"

  filter {
    criteria = "principal.AWS"
    eq       = var.archive_trusted_principals
  }
}

# Custom archive rules
resource "aws_accessanalyzer_archive_rule" "custom" {
  for_each = var.archive_rules

  analyzer_name = aws_accessanalyzer_analyzer.main.analyzer_name
  rule_name     = each.key

  dynamic "filter" {
    for_each = each.value.filter_criteria
    content {
      criteria = filter.value.criterion
      eq       = lookup(filter.value, "eq", null)
      neq      = lookup(filter.value, "neq", null)
      contains = lookup(filter.value, "contains", null)
      exists   = lookup(filter.value, "exists", null)
    }
  }
}

################################################################################
# SNS Topic for Notifications
################################################################################

resource "aws_sns_topic" "findings" {
  count = var.enable_sns_notifications && var.sns_topic_arn == "" ? 1 : 0

  name = "${var.name}-access-analyzer-findings"

  tags = merge(var.tags, { Name = "${var.name}-access-analyzer-findings" })
}

resource "aws_sns_topic_policy" "findings" {
  count = var.enable_sns_notifications && var.sns_topic_arn == "" ? 1 : 0

  arn = aws_sns_topic.findings[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.findings[0].arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count = var.enable_sns_notifications && var.sns_topic_arn == "" ? length(var.notification_emails) : 0

  topic_arn = aws_sns_topic.findings[0].arn
  protocol  = "email"
  endpoint  = var.notification_emails[count.index]
}

locals {
  sns_topic_arn = var.enable_sns_notifications ? (var.sns_topic_arn != "" ? var.sns_topic_arn : aws_sns_topic.findings[0].arn) : ""
}

################################################################################
# EventBridge Rule for Findings
################################################################################

resource "aws_cloudwatch_event_rule" "findings" {
  count = var.enable_eventbridge || var.enable_sns_notifications ? 1 : 0

  name        = "${var.name}-access-analyzer-findings"
  description = "Capture IAM Access Analyzer findings"

  event_pattern = jsonencode({
    source      = ["aws.access-analyzer"]
    detail-type = ["Access Analyzer Finding"]
    detail = {
      status = ["ACTIVE"]
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-access-analyzer-findings" })
}

resource "aws_cloudwatch_event_target" "sns" {
  count = var.enable_sns_notifications ? 1 : 0

  rule      = aws_cloudwatch_event_rule.findings[0].name
  target_id = "sns-notification"
  arn       = local.sns_topic_arn

  input_transformer {
    input_paths = {
      finding_id   = "$.detail.id"
      resource     = "$.detail.resource"
      resource_type = "$.detail.resourceType"
      principal    = "$.detail.principal"
      action       = "$.detail.action"
      condition    = "$.detail.condition"
      finding_type = "$.detail.findingType"
      status       = "$.detail.status"
      account      = "$.account"
      region       = "$.region"
    }
    input_template = <<-EOF
      {
        "summary": "IAM Access Analyzer Finding",
        "finding_id": "<finding_id>",
        "resource": "<resource>",
        "resource_type": "<resource_type>",
        "principal": "<principal>",
        "actions": "<action>",
        "condition": "<condition>",
        "finding_type": "<finding_type>",
        "status": "<status>",
        "account": "<account>",
        "region": "<region>"
      }
    EOF
  }
}

################################################################################
# CloudWatch Metrics (optional)
################################################################################

resource "aws_cloudwatch_metric_alarm" "new_findings" {
  count = var.enable_sns_notifications ? 1 : 0

  alarm_name          = "${var.name}-access-analyzer-new-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ActiveFindings"
  namespace           = "Custom/AccessAnalyzer"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Alert when new IAM Access Analyzer findings are detected"
  treat_missing_data  = "notBreaching"

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = []

  tags = merge(var.tags, { Name = "${var.name}-access-analyzer-alarm" })
}

################################################################################
# Outputs
################################################################################

output "analyzer_arn" {
  value       = aws_accessanalyzer_analyzer.main.arn
  description = "Access Analyzer ARN"
}

output "analyzer_id" {
  value       = aws_accessanalyzer_analyzer.main.id
  description = "Access Analyzer ID"
}

output "analyzer_name" {
  value       = aws_accessanalyzer_analyzer.main.analyzer_name
  description = "Access Analyzer name"
}

output "unused_access_analyzer_arn" {
  value       = var.enable_unused_access ? aws_accessanalyzer_analyzer.unused_access[0].arn : null
  description = "Unused Access Analyzer ARN"
}

output "sns_topic_arn" {
  value       = local.sns_topic_arn != "" ? local.sns_topic_arn : null
  description = "SNS topic ARN for findings notifications"
}

output "eventbridge_rule_arn" {
  value       = var.enable_eventbridge || var.enable_sns_notifications ? aws_cloudwatch_event_rule.findings[0].arn : null
  description = "EventBridge rule ARN for findings"
}

output "archive_rules" {
  value = {
    trusted_org       = var.archive_trusted_organization != "" ? "trusted-organization" : null
    trusted_accounts  = length(var.archive_trusted_accounts) > 0 ? "trusted-accounts" : null
    trusted_principals = length(var.archive_trusted_principals) > 0 ? "trusted-principals" : null
    custom            = keys(var.archive_rules)
  }
  description = "Created archive rules"
}
