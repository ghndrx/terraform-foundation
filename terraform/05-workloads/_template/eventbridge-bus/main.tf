################################################################################
# Workload: EventBridge Event Bus
# 
# Deploys an event-driven architecture component:
# - Custom event bus for tenant isolation
# - Event rules with pattern matching
# - Multiple targets (Lambda, SQS, Step Functions)
# - Dead letter queue for failed events
# - Event archiving for replay
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-events/
#   Update locals and rules
#   terraform init -backend-config=../../00-bootstrap/backend.hcl
#   terraform apply
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  backend "s3" {
    key = "05-workloads/<TENANT>-events/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  name   = "events"
  env    = "prod"
  
  bus_name = "${local.tenant}-${local.name}-${local.env}"

  # Event archiving (for replay capability)
  enable_archive       = true
  archive_retention_days = 30

  # Dead letter queue for failed event delivery
  enable_dlq = true

  # Schema discovery (for event schema registry)
  enable_schema_discovery = false

  # Event rules - define your event routing here
  event_rules = {
    # Example: Route order events to SQS
    # order-created = {
    #   description   = "Route order.created events to processing queue"
    #   event_pattern = {
    #     source      = ["${local.tenant}.orders"]
    #     detail-type = ["order.created"]
    #   }
    #   targets = {
    #     sqs = {
    #       type = "sqs"
    #       arn  = "arn:aws:sqs:us-east-1:123456789012:order-processing"
    #     }
    #   }
    # }
    
    # Example: Route all events to CloudWatch Logs for debugging
    all-events-log = {
      description = "Log all events for debugging"
      event_pattern = {
        source = [{ prefix = "${local.tenant}." }]
      }
      targets = {
        logs = {
          type = "cloudwatch"
        }
      }
    }
  }

  # Cross-account event sources (account IDs that can put events)
  allowed_source_accounts = []

  # Cross-account event targets (account IDs that can receive events)
  allowed_target_accounts = []
}

################################################################################
# Variables
################################################################################

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "state_bucket" {
  type = string
}

################################################################################
# Provider
################################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Tenant      = local.tenant
      App         = local.name
      Environment = local.env
      ManagedBy   = "terraform"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Event Bus
################################################################################

resource "aws_cloudwatch_event_bus" "main" {
  name = local.bus_name

  tags = { Name = local.bus_name }
}

################################################################################
# Event Bus Policy
################################################################################

resource "aws_cloudwatch_event_bus_policy" "main" {
  count          = length(local.allowed_source_accounts) > 0 ? 1 : 0
  event_bus_name = aws_cloudwatch_event_bus.main.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCrossAccountPutEvents"
        Effect = "Allow"
        Principal = {
          AWS = [for account in local.allowed_source_accounts : "arn:aws:iam::${account}:root"]
        }
        Action   = "events:PutEvents"
        Resource = aws_cloudwatch_event_bus.main.arn
      }
    ]
  })
}

################################################################################
# Event Archive
################################################################################

resource "aws_cloudwatch_event_archive" "main" {
  count            = local.enable_archive ? 1 : 0
  name             = local.bus_name
  description      = "Archive for ${local.bus_name}"
  event_source_arn = aws_cloudwatch_event_bus.main.arn
  retention_days   = local.archive_retention_days

  # Archive all events (can be filtered with event_pattern)
}

################################################################################
# Dead Letter Queue
################################################################################

resource "aws_sqs_queue" "dlq" {
  count = local.enable_dlq ? 1 : 0
  name  = "${local.bus_name}-dlq"

  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = "alias/aws/sqs"

  tags = { Name = "${local.bus_name}-dlq" }
}

resource "aws_sqs_queue_policy" "dlq" {
  count     = local.enable_dlq ? 1 : 0
  queue_url = aws_sqs_queue.dlq[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowEventBridge"
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.dlq[0].arn
    }]
  })
}

################################################################################
# CloudWatch Log Group for Event Logging
################################################################################

resource "aws_cloudwatch_log_group" "events" {
  name              = "/aws/events/${local.bus_name}"
  retention_in_days = 30

  tags = { Name = local.bus_name }
}

# Resource policy to allow EventBridge to write logs
resource "aws_cloudwatch_log_resource_policy" "events" {
  policy_name = "${local.bus_name}-events"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
      }
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.events.arn}:*"
    }]
  })
}

################################################################################
# IAM Role for EventBridge Targets
################################################################################

resource "aws_iam_role" "eventbridge" {
  name = "${local.bus_name}-eventbridge"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.bus_name}-eventbridge" }
}

################################################################################
# Event Rules and Targets
################################################################################

resource "aws_cloudwatch_event_rule" "rules" {
  for_each = local.event_rules

  name           = "${local.bus_name}-${each.key}"
  description    = each.value.description
  event_bus_name = aws_cloudwatch_event_bus.main.name
  event_pattern  = jsonencode(each.value.event_pattern)
  state          = "ENABLED"

  tags = { Name = "${local.bus_name}-${each.key}" }
}

# CloudWatch Logs targets
resource "aws_cloudwatch_event_target" "logs" {
  for_each = {
    for k, v in local.event_rules : k => v
    if contains(keys(v.targets), "logs") && v.targets.logs.type == "cloudwatch"
  }

  rule           = aws_cloudwatch_event_rule.rules[each.key].name
  event_bus_name = aws_cloudwatch_event_bus.main.name
  target_id      = "cloudwatch-logs"
  arn            = aws_cloudwatch_log_group.events.arn

  dead_letter_config {
    arn = local.enable_dlq ? aws_sqs_queue.dlq[0].arn : null
  }
}

################################################################################
# Schema Registry (Optional)
################################################################################

resource "aws_schemas_discoverer" "main" {
  count       = local.enable_schema_discovery ? 1 : 0
  source_arn  = aws_cloudwatch_event_bus.main.arn
  description = "Schema discoverer for ${local.bus_name}"

  tags = { Name = local.bus_name }
}

################################################################################
# CloudWatch Alarms
################################################################################

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  count               = local.enable_dlq ? 1 : 0
  alarm_name          = "${local.bus_name}-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Events failing to deliver to targets"

  dimensions = {
    QueueName = aws_sqs_queue.dlq[0].name
  }

  tags = { Name = "${local.bus_name}-dlq-alarm" }
}

resource "aws_cloudwatch_metric_alarm" "failed_invocations" {
  alarm_name          = "${local.bus_name}-failed-invocations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FailedInvocations"
  namespace           = "AWS/Events"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "EventBridge rule invocations failing"

  dimensions = {
    EventBusName = aws_cloudwatch_event_bus.main.name
  }

  tags = { Name = "${local.bus_name}-failed-invocations" }
}

################################################################################
# Outputs
################################################################################

output "event_bus_name" {
  value = aws_cloudwatch_event_bus.main.name
}

output "event_bus_arn" {
  value = aws_cloudwatch_event_bus.main.arn
}

output "archive_arn" {
  value = local.enable_archive ? aws_cloudwatch_event_archive.main[0].arn : null
}

output "dlq_url" {
  value = local.enable_dlq ? aws_sqs_queue.dlq[0].url : null
}

output "dlq_arn" {
  value = local.enable_dlq ? aws_sqs_queue.dlq[0].arn : null
}

output "log_group" {
  value = aws_cloudwatch_log_group.events.name
}

output "rule_arns" {
  value = { for k, v in aws_cloudwatch_event_rule.rules : k => v.arn }
}

output "put_event_example" {
  value = <<-EOF
    aws events put-events --entries '[{
      "EventBusName": "${aws_cloudwatch_event_bus.main.name}",
      "Source": "${local.tenant}.myservice",
      "DetailType": "order.created",
      "Detail": "{\"orderId\": \"12345\", \"amount\": 99.99}"
    }]'
  EOF
  description = "Example command to put an event"
}
