################################################################################
# Cost Anomaly Detection Module
#
# AWS Cost Anomaly Detection using ML-powered anomaly monitoring:
# - Account-level or service-level monitors
# - Configurable alerting thresholds (% or absolute)
# - SNS and email subscriptions
# - Multi-account support via Cost Category or Linked Account monitors
#
# Complements budget-alerts by catching unexpected spend patterns
# that don't necessarily breach budget thresholds.
#
# Usage:
#   module "cost_anomaly" {
#     source = "../modules/cost-anomaly-detection"
#     
#     name_prefix    = "prod"
#     alert_emails   = ["finops@example.com"]
#     
#     # Alert when anomaly exceeds 10% OR $100
#     threshold_percentage = 10
#     threshold_absolute   = 100
#   }
################################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# SNS Topic for Anomaly Alerts
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "anomaly_alerts" {
  name              = "${var.name_prefix}-cost-anomaly-alerts"
  kms_master_key_id = var.kms_key_id

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-cost-anomaly-alerts"
    Purpose = "cost-anomaly-detection"
  })
}

resource "aws_sns_topic_policy" "anomaly_alerts" {
  arn    = aws_sns_topic.anomaly_alerts.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

data "aws_iam_policy_document" "sns_policy" {
  statement {
    sid    = "AllowCostExplorerPublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["costalerts.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.anomaly_alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Email Subscriptions
# -----------------------------------------------------------------------------
resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.anomaly_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# -----------------------------------------------------------------------------
# Cost Anomaly Monitor
# -----------------------------------------------------------------------------
resource "aws_ce_anomaly_monitor" "main" {
  name              = "${var.name_prefix}-cost-anomaly-monitor"
  monitor_type      = var.monitor_type
  monitor_dimension = var.monitor_type == "DIMENSIONAL" ? var.monitor_dimension : null

  dynamic "monitor_specification" {
    for_each = var.monitor_type == "CUSTOM" && var.cost_category_name != null ? [1] : []
    content {
      # Custom expression for Cost Category filtering
      and = null
      or  = null
      cost_category {
        key           = var.cost_category_name
        values        = var.cost_category_values
        match_options = ["EQUALS"]
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-cost-anomaly-monitor"
  })
}

# -----------------------------------------------------------------------------
# Anomaly Subscription (Alert Configuration)
# -----------------------------------------------------------------------------
resource "aws_ce_anomaly_subscription" "main" {
  name      = "${var.name_prefix}-cost-anomaly-subscription"
  frequency = var.alert_frequency

  monitor_arn_list = [aws_ce_anomaly_monitor.main.arn]

  subscriber {
    type    = "SNS"
    address = aws_sns_topic.anomaly_alerts.arn
  }

  # Optional: Additional email subscribers directly (bypasses SNS)
  dynamic "subscriber" {
    for_each = var.direct_email_subscribers
    content {
      type    = "EMAIL"
      address = subscriber.value
    }
  }

  # Threshold configuration - alert when EITHER condition is met
  threshold_expression {
    or {
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_PERCENTAGE"
        values        = [tostring(var.threshold_percentage)]
        match_options = ["GREATER_THAN_OR_EQUAL"]
      }
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
        values        = [tostring(var.threshold_absolute)]
        match_options = ["GREATER_THAN_OR_EQUAL"]
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-cost-anomaly-subscription"
  })

  depends_on = [aws_sns_topic_policy.anomaly_alerts]
}

# -----------------------------------------------------------------------------
# Service-Specific Monitors (Optional)
# -----------------------------------------------------------------------------
resource "aws_ce_anomaly_monitor" "service" {
  for_each = var.service_monitors

  name              = "${var.name_prefix}-${each.key}-anomaly-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-${each.key}-anomaly-monitor"
    Service = each.key
  })
}

resource "aws_ce_anomaly_subscription" "service" {
  for_each = var.service_monitors

  name      = "${var.name_prefix}-${each.key}-anomaly-subscription"
  frequency = var.alert_frequency

  monitor_arn_list = [aws_ce_anomaly_monitor.service[each.key].arn]

  subscriber {
    type    = "SNS"
    address = aws_sns_topic.anomaly_alerts.arn
  }

  threshold_expression {
    or {
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_PERCENTAGE"
        values        = [tostring(each.value.threshold_percentage)]
        match_options = ["GREATER_THAN_OR_EQUAL"]
      }
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
        values        = [tostring(each.value.threshold_absolute)]
        match_options = ["GREATER_THAN_OR_EQUAL"]
      }
    }
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-${each.key}-anomaly-subscription"
    Service = each.key
  })

  depends_on = [aws_sns_topic_policy.anomaly_alerts]
}
