################################################################################
# Security Hub Module
#
# Centralized security posture management:
# - Security Hub with standards subscriptions
# - Finding aggregation (cross-region)
# - SNS alerts for critical findings
# - Custom actions for remediation workflows
# - Product integrations
# - Insight configuration
#
# Usage:
#   module "security_hub" {
#     source = "../modules/security-hub"
#     name   = "main"
#
#     enable_cis_benchmark = true
#     enable_aws_foundational = true
#     enable_pci_dss = true
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
  description = "Name prefix for Security Hub resources"
}

variable "enable" {
  type        = bool
  default     = true
  description = "Enable Security Hub"
}

variable "auto_enable_controls" {
  type        = bool
  default     = true
  description = "Auto-enable new controls in standards"
}

variable "control_finding_generator" {
  type        = string
  default     = "SECURITY_CONTROL"
  description = "Control finding generator: SECURITY_CONTROL or STANDARD_CONTROL"
  validation {
    condition     = contains(["SECURITY_CONTROL", "STANDARD_CONTROL"], var.control_finding_generator)
    error_message = "Must be SECURITY_CONTROL or STANDARD_CONTROL."
  }
}

# Standards
variable "enable_aws_foundational" {
  type        = bool
  default     = true
  description = "Enable AWS Foundational Security Best Practices"
}

variable "enable_cis_benchmark" {
  type        = bool
  default     = false
  description = "Enable CIS AWS Foundations Benchmark v1.4"
}

variable "enable_cis_benchmark_v3" {
  type        = bool
  default     = false
  description = "Enable CIS AWS Foundations Benchmark v3.0"
}

variable "enable_pci_dss" {
  type        = bool
  default     = false
  description = "Enable PCI DSS v3.2.1"
}

variable "enable_nist_800_53" {
  type        = bool
  default     = false
  description = "Enable NIST 800-53 Rev. 5"
}

# Disabled Controls
variable "disabled_controls" {
  type        = list(string)
  default     = []
  description = "Control IDs to disable (e.g., 'EC2.19', 'IAM.6')"
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
  description = "Email for finding alerts"
}

variable "alert_sns_topic_arn" {
  type        = string
  default     = ""
  description = "Existing SNS topic ARN (created if empty)"
}

variable "alert_severity" {
  type        = list(string)
  default     = ["CRITICAL", "HIGH"]
  description = "Severities to alert on"
}

# Cross-Region Aggregation
variable "enable_finding_aggregator" {
  type        = bool
  default     = false
  description = "Enable cross-region finding aggregation (run in aggregation region)"
}

variable "aggregation_regions" {
  type        = list(string)
  default     = []
  description = "Regions to aggregate (empty = all linked regions)"
}

# Organization
variable "is_organization_admin" {
  type        = bool
  default     = false
  description = "This account is the delegated admin"
}

variable "auto_enable_organization_members" {
  type        = bool
  default     = true
  description = "Auto-enable Security Hub for new org accounts"
}

# Custom Actions
variable "custom_actions" {
  type = list(object({
    name        = string
    description = string
    identifier  = string
  }))
  default     = []
  description = "Custom actions for finding workflows"
}

# Product Integrations
variable "enable_inspector" {
  type        = bool
  default     = false
  description = "Enable Amazon Inspector integration"
}

variable "enable_macie" {
  type        = bool
  default     = false
  description = "Enable Amazon Macie integration"
}

variable "enable_detective" {
  type        = bool
  default     = false
  description = "Enable Amazon Detective integration"
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

  # Standard ARNs
  standards = {
    aws_foundational = "arn:aws:securityhub:${data.aws_region.current.id}::standards/aws-foundational-security-best-practices/v/1.0.0"
    cis_benchmark    = "arn:aws:securityhub:${data.aws_region.current.id}::standards/cis-aws-foundations-benchmark/v/1.4.0"
    cis_benchmark_v3 = "arn:aws:securityhub:${data.aws_region.current.id}::standards/cis-aws-foundations-benchmark/v/3.0.0"
    pci_dss          = "arn:aws:securityhub:${data.aws_region.current.id}::standards/pci-dss/v/3.2.1"
    nist_800_53      = "arn:aws:securityhub:${data.aws_region.current.id}::standards/nist-800-53/v/5.0.0"
  }

  enabled_standards = compact([
    var.enable_aws_foundational ? local.standards.aws_foundational : "",
    var.enable_cis_benchmark ? local.standards.cis_benchmark : "",
    var.enable_cis_benchmark_v3 ? local.standards.cis_benchmark_v3 : "",
    var.enable_pci_dss ? local.standards.pci_dss : "",
    var.enable_nist_800_53 ? local.standards.nist_800_53 : "",
  ])
}

################################################################################
# Security Hub Account
################################################################################

resource "aws_securityhub_account" "main" {
  count = var.enable ? 1 : 0

  enable_default_standards  = false
  auto_enable_controls      = var.auto_enable_controls
  control_finding_generator = var.control_finding_generator
}

################################################################################
# Standards Subscriptions
################################################################################

resource "aws_securityhub_standards_subscription" "standards" {
  for_each = var.enable ? toset(local.enabled_standards) : []

  standards_arn = each.value

  depends_on = [aws_securityhub_account.main]
}

################################################################################
# Disabled Controls
################################################################################

resource "aws_securityhub_standards_control" "disabled" {
  for_each = var.enable ? toset(var.disabled_controls) : []

  standards_control_arn = "arn:aws:securityhub:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:control/${each.value}"
  control_status        = "DISABLED"
  disabled_reason       = "Disabled via Terraform"

  depends_on = [aws_securityhub_standards_subscription.standards]
}

################################################################################
# SNS Topic for Alerts
################################################################################

resource "aws_sns_topic" "alerts" {
  count = local.create_sns_topic ? 1 : 0

  name              = "${var.name}-securityhub-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, { Name = "${var.name}-securityhub-alerts" })
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

  name        = "${var.name}-securityhub-findings"
  description = "Route Security Hub findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = var.alert_severity
        }
        Workflow = {
          Status = ["NEW"]
        }
        RecordState = ["ACTIVE"]
      }
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-securityhub-findings" })
}

resource "aws_cloudwatch_event_target" "sns" {
  count = var.enable && var.enable_sns_alerts ? 1 : 0

  rule      = aws_cloudwatch_event_rule.findings[0].name
  target_id = "sns"
  arn       = local.sns_topic_arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.findings[0].Severity.Label"
      title       = "$.detail.findings[0].Title"
      description = "$.detail.findings[0].Description"
      accountId   = "$.detail.findings[0].AwsAccountId"
      region      = "$.detail.findings[0].Region"
      resourceId  = "$.detail.findings[0].Resources[0].Id"
      standard    = "$.detail.findings[0].GeneratorId"
    }
    input_template = <<EOF
{
  "subject": "Security Hub [<severity>]: <title>",
  "message": "Severity: <severity>\nAccount: <accountId>\nRegion: <region>\n\nTitle: <title>\n\nDescription: <description>\n\nResource: <resourceId>\n\nStandard: <standard>\n\nView in console: https://<region>.console.aws.amazon.com/securityhub/home?region=<region>#/findings"
}
EOF
  }
}

################################################################################
# Finding Aggregator (Cross-Region)
################################################################################

resource "aws_securityhub_finding_aggregator" "main" {
  count = var.enable && var.enable_finding_aggregator ? 1 : 0

  linking_mode      = length(var.aggregation_regions) > 0 ? "SPECIFIED_REGIONS" : "ALL_REGIONS"
  specified_regions = length(var.aggregation_regions) > 0 ? var.aggregation_regions : null

  depends_on = [aws_securityhub_account.main]
}

################################################################################
# Organization Configuration
################################################################################

resource "aws_securityhub_organization_configuration" "main" {
  count = var.enable && var.is_organization_admin ? 1 : 0

  auto_enable           = var.auto_enable_organization_members
  auto_enable_standards = var.auto_enable_organization_members ? "DEFAULT" : "NONE"

  depends_on = [aws_securityhub_account.main]
}

resource "aws_securityhub_organization_admin_account" "main" {
  count = var.enable && var.is_organization_admin ? 1 : 0

  admin_account_id = data.aws_caller_identity.current.account_id

  depends_on = [aws_securityhub_account.main]
}

################################################################################
# Custom Actions
################################################################################

resource "aws_securityhub_action_target" "custom" {
  for_each = var.enable ? { for a in var.custom_actions : a.identifier => a } : {}

  name        = each.value.name
  identifier  = each.value.identifier
  description = each.value.description

  depends_on = [aws_securityhub_account.main]
}

################################################################################
# Product Integrations
################################################################################

resource "aws_securityhub_product_subscription" "inspector" {
  count = var.enable && var.enable_inspector ? 1 : 0

  product_arn = "arn:aws:securityhub:${data.aws_region.current.id}::product/aws/inspector"

  depends_on = [aws_securityhub_account.main]
}

resource "aws_securityhub_product_subscription" "macie" {
  count = var.enable && var.enable_macie ? 1 : 0

  product_arn = "arn:aws:securityhub:${data.aws_region.current.id}::product/aws/macie"

  depends_on = [aws_securityhub_account.main]
}

################################################################################
# Insights (Custom Finding Queries)
################################################################################

resource "aws_securityhub_insight" "critical_findings" {
  count = var.enable ? 1 : 0

  name = "${var.name}-critical-findings"

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceType"

  depends_on = [aws_securityhub_account.main]
}

resource "aws_securityhub_insight" "failed_resources" {
  count = var.enable ? 1 : 0

  name = "${var.name}-failed-resources"

  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceId"

  depends_on = [aws_securityhub_account.main]
}

resource "aws_securityhub_insight" "findings_by_account" {
  count = var.enable ? 1 : 0

  name = "${var.name}-findings-by-account"

  filters {
    severity_label {
      comparison = "NOT_EQUALS"
      value      = "INFORMATIONAL"
    }
    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "AwsAccountId"

  depends_on = [aws_securityhub_account.main]
}

################################################################################
# Outputs
################################################################################

output "hub_arn" {
  value       = var.enable ? aws_securityhub_account.main[0].arn : null
  description = "Security Hub account ARN"
}

output "sns_topic_arn" {
  value       = var.enable_sns_alerts ? local.sns_topic_arn : null
  description = "SNS topic for alerts"
}

output "enabled_standards" {
  value       = local.enabled_standards
  description = "List of enabled standards ARNs"
}

output "finding_aggregator_id" {
  value       = var.enable && var.enable_finding_aggregator ? aws_securityhub_finding_aggregator.main[0].id : null
  description = "Finding aggregator ID"
}

output "custom_action_arns" {
  value = var.enable ? {
    for k, v in aws_securityhub_action_target.custom : k => v.arn
  } : {}
  description = "Custom action ARNs"
}

output "insight_arns" {
  value = var.enable ? {
    critical_findings = aws_securityhub_insight.critical_findings[0].arn
    failed_resources  = aws_securityhub_insight.failed_resources[0].arn
    by_account        = aws_securityhub_insight.findings_by_account[0].arn
  } : null
  description = "Security Hub insight ARNs"
}

output "enabled_features" {
  value = var.enable ? {
    aws_foundational   = var.enable_aws_foundational
    cis_benchmark      = var.enable_cis_benchmark
    cis_benchmark_v3   = var.enable_cis_benchmark_v3
    pci_dss            = var.enable_pci_dss
    nist_800_53        = var.enable_nist_800_53
    sns_alerts         = var.enable_sns_alerts
    finding_aggregator = var.enable_finding_aggregator
    inspector          = var.enable_inspector
    macie              = var.enable_macie
    detective          = var.enable_detective
  } : null
  description = "Enabled Security Hub features"
}
