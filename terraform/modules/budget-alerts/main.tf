################################################################################
# Budget Alerts Module
#
# AWS Budgets for cost monitoring:
# - Monthly spend budgets
# - Service-specific budgets
# - Forecasted spend alerts
# - Cost anomaly detection
# - SNS/email notifications
#
# Usage:
#   module "budgets" {
#     source = "../modules/budget-alerts"
#     
#     monthly_budget = 1000
#     alert_emails   = ["finance@example.com"]
#     
#     service_budgets = {
#       ec2 = 500
#       rds = 200
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

variable "name_prefix" {
  type        = string
  default     = "account"
  description = "Prefix for budget names"
}

variable "monthly_budget" {
  type        = number
  description = "Monthly budget amount in USD"
}

variable "currency" {
  type        = string
  default     = "USD"
  description = "Budget currency"
}

variable "alert_emails" {
  type        = list(string)
  default     = []
  description = "Email addresses for budget alerts"
}

variable "alert_sns_topic_arn" {
  type        = string
  default     = ""
  description = "SNS topic ARN for alerts (creates one if empty)"
}

variable "alert_thresholds" {
  type        = list(number)
  default     = [50, 75, 90, 100, 110]
  description = "Alert thresholds as percentage of budget"
}

variable "forecast_alert_threshold" {
  type        = number
  default     = 100
  description = "Alert when forecasted spend exceeds this percentage"
}

variable "service_budgets" {
  type        = map(number)
  default     = {}
  description = "Per-service budgets (service name -> monthly amount)"
}

variable "enable_anomaly_detection" {
  type        = bool
  default     = true
  description = "Enable AWS Cost Anomaly Detection"
}

variable "anomaly_threshold_percentage" {
  type        = number
  default     = 10
  description = "Anomaly alert threshold as percentage above expected"
}

variable "anomaly_threshold_absolute" {
  type        = number
  default     = 100
  description = "Minimum absolute dollar amount for anomaly alerts"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}

################################################################################
# SNS Topic for Alerts
################################################################################

resource "aws_sns_topic" "budget_alerts" {
  count = var.alert_sns_topic_arn == "" ? 1 : 0
  name  = "${var.name_prefix}-budget-alerts"

  tags = merge(var.tags, { Name = "${var.name_prefix}-budget-alerts" })
}

resource "aws_sns_topic_policy" "budget_alerts" {
  count = var.alert_sns_topic_arn == "" ? 1 : 0
  arn   = aws_sns_topic.budget_alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBudgets"
        Effect = "Allow"
        Principal = {
          Service = "budgets.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.budget_alerts[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowCostAnomaly"
        Effect = "Allow"
        Principal = {
          Service = "costalerts.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.budget_alerts[0].arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  for_each = var.alert_sns_topic_arn == "" ? toset(var.alert_emails) : []

  topic_arn = aws_sns_topic.budget_alerts[0].arn
  protocol  = "email"
  endpoint  = each.value
}

locals {
  sns_topic_arn = var.alert_sns_topic_arn != "" ? var.alert_sns_topic_arn : aws_sns_topic.budget_alerts[0].arn
}

################################################################################
# Monthly Account Budget
################################################################################

resource "aws_budgets_budget" "monthly" {
  name              = "${var.name_prefix}-monthly-budget"
  budget_type       = "COST"
  limit_amount      = var.monthly_budget
  limit_unit        = var.currency
  time_unit         = "MONTHLY"
  time_period_start = formatdate("YYYY-MM-01_00:00", timestamp())

  cost_filter {
    name   = "LinkedAccount"
    values = [data.aws_caller_identity.current.account_id]
  }

  # Actual spend alerts
  dynamic "notification" {
    for_each = var.alert_thresholds
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_sns_topic_arns  = [local.sns_topic_arn]
      subscriber_email_addresses = var.alert_sns_topic_arn != "" ? var.alert_emails : []
    }
  }

  # Forecasted spend alert
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = var.forecast_alert_threshold
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_sns_topic_arns  = [local.sns_topic_arn]
    subscriber_email_addresses = var.alert_sns_topic_arn != "" ? var.alert_emails : []
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-monthly" })

  lifecycle {
    ignore_changes = [time_period_start]
  }
}

################################################################################
# Service-Specific Budgets
################################################################################

locals {
  service_filters = {
    ec2         = "Amazon Elastic Compute Cloud - Compute"
    rds         = "Amazon Relational Database Service"
    s3          = "Amazon Simple Storage Service"
    lambda      = "AWS Lambda"
    dynamodb    = "Amazon DynamoDB"
    cloudfront  = "Amazon CloudFront"
    elasticache = "Amazon ElastiCache"
    eks         = "Amazon Elastic Kubernetes Service"
    ecs         = "Amazon Elastic Container Service"
    nat         = "EC2 - Other" # NAT Gateway charges
    data        = "AWS Data Transfer"
  }
}

resource "aws_budgets_budget" "services" {
  for_each = var.service_budgets

  name              = "${var.name_prefix}-${each.key}-budget"
  budget_type       = "COST"
  limit_amount      = each.value
  limit_unit        = var.currency
  time_unit         = "MONTHLY"
  time_period_start = formatdate("YYYY-MM-01_00:00", timestamp())

  cost_filter {
    name   = "Service"
    values = [lookup(local.service_filters, each.key, each.key)]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [local.sns_topic_arn]
    subscriber_email_addresses = var.alert_sns_topic_arn != "" ? var.alert_emails : []
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [local.sns_topic_arn]
    subscriber_email_addresses = var.alert_sns_topic_arn != "" ? var.alert_emails : []
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })

  lifecycle {
    ignore_changes = [time_period_start]
  }
}

################################################################################
# Cost Anomaly Detection
################################################################################

resource "aws_ce_anomaly_monitor" "main" {
  count             = var.enable_anomaly_detection ? 1 : 0
  name              = "${var.name_prefix}-anomaly-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"

  tags = merge(var.tags, { Name = "${var.name_prefix}-anomaly-monitor" })
}

resource "aws_ce_anomaly_subscription" "main" {
  count     = var.enable_anomaly_detection ? 1 : 0
  name      = "${var.name_prefix}-anomaly-alerts"
  frequency = "IMMEDIATE"

  monitor_arn_list = [aws_ce_anomaly_monitor.main[0].arn]

  subscriber {
    type    = "SNS"
    address = local.sns_topic_arn
  }

  dynamic "subscriber" {
    for_each = var.alert_sns_topic_arn != "" ? var.alert_emails : []
    content {
      type    = "EMAIL"
      address = subscriber.value
    }
  }

  threshold_expression {
    and {
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_PERCENTAGE"
        match_options = ["GREATER_THAN_OR_EQUAL"]
        values        = [tostring(var.anomaly_threshold_percentage)]
      }
    }
    and {
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
        match_options = ["GREATER_THAN_OR_EQUAL"]
        values        = [tostring(var.anomaly_threshold_absolute)]
      }
    }
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-anomaly-alerts" })
}

################################################################################
# Outputs
################################################################################

output "monthly_budget_id" {
  value       = aws_budgets_budget.monthly.id
  description = "Monthly budget ID"
}

output "service_budget_ids" {
  value       = { for k, v in aws_budgets_budget.services : k => v.id }
  description = "Service budget IDs"
}

output "sns_topic_arn" {
  value       = local.sns_topic_arn
  description = "SNS topic ARN for alerts"
}

output "anomaly_monitor_arn" {
  value       = var.enable_anomaly_detection ? aws_ce_anomaly_monitor.main[0].arn : null
  description = "Cost Anomaly Monitor ARN"
}

output "budget_summary" {
  value = {
    monthly_limit = "$${var.monthly_budget}/month"
    alert_thresholds = [for t in var.alert_thresholds : "${t}%"]
    service_limits = { for k, v in var.service_budgets : k => "$${v}/month" }
    anomaly_detection = var.enable_anomaly_detection ? "Enabled (>${var.anomaly_threshold_percentage}% and >$${var.anomaly_threshold_absolute})" : "Disabled"
  }
  description = "Budget configuration summary"
}
