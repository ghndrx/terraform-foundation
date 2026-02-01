################################################################################
# Tenant Budget Module
#
# Creates tenant-specific budget with alerts:
# - Monthly budget with configurable limit
# - Multi-threshold alerts
# - Cost allocation tag filtering
# - SNS and email notifications
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

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Build cost filters from tags
  cost_filters = length(var.cost_filter_tags) > 0 ? {
    TagKeyValue = [for k, v in var.cost_filter_tags : "user:${k}$${v}"]
  } : {}
}

################################################################################
# SNS Topic for Budget Alerts
################################################################################

resource "aws_sns_topic" "budget" {
  count = var.create_sns_topic ? 1 : 0

  name = "${var.name}-budget-alerts"

  tags = merge(var.tags, {
    Name = "${var.name}-budget-alerts"
  })
}

resource "aws_sns_topic_policy" "budget" {
  count = var.create_sns_topic ? 1 : 0

  arn = aws_sns_topic.budget[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBudgetsPublish"
        Effect = "Allow"
        Principal = {
          Service = "budgets.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.budget[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  for_each = var.create_sns_topic ? toset(var.notification_emails) : []

  topic_arn = aws_sns_topic.budget[0].arn
  protocol  = "email"
  endpoint  = each.value
}

################################################################################
# Budget
################################################################################

resource "aws_budgets_budget" "this" {
  name         = "${var.name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Optional: Filter by cost allocation tags
  dynamic "cost_filter" {
    for_each = local.cost_filters
    content {
      name   = cost_filter.key
      values = cost_filter.value
    }
  }

  cost_types {
    include_credit             = false
    include_discount           = true
    include_other_subscription = true
    include_recurring          = true
    include_refund             = false
    include_subscription       = true
    include_support            = true
    include_tax                = true
    include_upfront            = true
    use_amortized              = false
    use_blended                = false
  }

  # Actual spend notifications
  dynamic "notification" {
    for_each = var.alert_thresholds
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.create_sns_topic ? [] : var.notification_emails
      subscriber_sns_topic_arns  = var.create_sns_topic ? [aws_sns_topic.budget[0].arn] : (var.sns_topic_arn != null ? [var.sns_topic_arn] : [])
    }
  }

  # Forecasted spend notifications
  dynamic "notification" {
    for_each = var.enable_forecasted_alerts ? var.forecasted_thresholds : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "FORECASTED"
      subscriber_email_addresses = var.create_sns_topic ? [] : var.notification_emails
      subscriber_sns_topic_arns  = var.create_sns_topic ? [aws_sns_topic.budget[0].arn] : (var.sns_topic_arn != null ? [var.sns_topic_arn] : [])
    }
  }

  tags = merge(var.tags, {
    Name   = "${var.name}-monthly-budget"
    Tenant = var.name
  })
}
