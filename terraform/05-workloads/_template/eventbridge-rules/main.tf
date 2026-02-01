################################################################################
# Workload: EventBridge Rules
# 
# Event-driven automation with:
# - Scheduled rules (cron/rate)
# - Event pattern rules (AWS service events)
# - Multiple targets (Lambda, SQS, SNS, Step Functions)
# - Dead letter queues
# - Input transformations
#
# Use cases: Scheduled jobs, event routing, service integration
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
    key = "05-workloads/<TENANT>-<NAME>-events/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  name   = "<NAME>"
  env    = "prod"
  
  prefix = "${local.tenant}-${local.name}"

  # Use custom event bus (null = default bus)
  event_bus_name = null

  # Scheduled rules
  scheduled_rules = {
    # Daily report at 9 AM UTC
    daily-report = {
      description         = "Generate daily report"
      schedule_expression = "cron(0 9 * * ? *)"
      enabled             = true
      target_type         = "lambda"
      target_arn          = "" # Lambda function ARN
      input = jsonencode({
        report_type = "daily"
        format      = "pdf"
      })
    }

    # Every 5 minutes health check
    health-check = {
      description         = "Periodic health check"
      schedule_expression = "rate(5 minutes)"
      enabled             = true
      target_type         = "lambda"
      target_arn          = "" # Lambda function ARN
    }

    # Monthly cleanup (1st of month at midnight)
    monthly-cleanup = {
      description         = "Monthly data cleanup"
      schedule_expression = "cron(0 0 1 * ? *)"
      enabled             = true
      target_type         = "step-function"
      target_arn          = "" # State machine ARN
      input = jsonencode({
        retention_days = 90
      })
    }
  }

  # Event pattern rules (react to AWS events)
  event_pattern_rules = {
    # EC2 instance state changes
    ec2-state-change = {
      description = "EC2 instance state changes"
      enabled     = true
      event_pattern = jsonencode({
        source      = ["aws.ec2"]
        detail-type = ["EC2 Instance State-change Notification"]
        detail = {
          state = ["stopped", "terminated"]
        }
      })
      target_type = "sns"
      target_arn  = "" # SNS topic ARN
    }

    # S3 object created
    s3-upload = {
      description = "S3 object created in uploads bucket"
      enabled     = true
      event_pattern = jsonencode({
        source      = ["aws.s3"]
        detail-type = ["Object Created"]
        detail = {
          bucket = {
            name = ["my-uploads-bucket"]
          }
        }
      })
      target_type = "lambda"
      target_arn  = "" # Lambda function ARN
      input_transformer = {
        input_paths = {
          bucket = "$.detail.bucket.name"
          key    = "$.detail.object.key"
          size   = "$.detail.object.size"
        }
        input_template = <<-EOF
          {
            "bucket": <bucket>,
            "key": <key>,
            "size": <size>,
            "timestamp": "<aws.events.event.ingestion-time>"
          }
        EOF
      }
    }

    # CodePipeline state change
    pipeline-failed = {
      description = "CodePipeline execution failed"
      enabled     = true
      event_pattern = jsonencode({
        source      = ["aws.codepipeline"]
        detail-type = ["CodePipeline Pipeline Execution State Change"]
        detail = {
          state = ["FAILED"]
        }
      })
      target_type = "sns"
      target_arn  = "" # SNS topic ARN
    }

    # GuardDuty findings
    security-findings = {
      description = "GuardDuty security findings"
      enabled     = false  # Enable when GuardDuty is active
      event_pattern = jsonencode({
        source      = ["aws.guardduty"]
        detail-type = ["GuardDuty Finding"]
        detail = {
          severity = [{ numeric = [">=", 7] }]  # High severity
        }
      })
      target_type = "sns"
      target_arn  = "" # SNS topic ARN
    }
  }

  # Enable DLQ for failed deliveries
  enable_dlq = true
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
# Dead Letter Queue
################################################################################

resource "aws_sqs_queue" "dlq" {
  count = local.enable_dlq ? 1 : 0
  name  = "${local.prefix}-events-dlq"

  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = "alias/aws/sqs"

  tags = { Name = "${local.prefix}-events-dlq" }
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
# IAM Role for EventBridge
################################################################################

resource "aws_iam_role" "eventbridge" {
  name = "${local.prefix}-eventbridge"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.prefix}-eventbridge" }
}

resource "aws_iam_role_policy" "eventbridge" {
  name = "invoke-targets"
  role = aws_iam_role.eventbridge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeStepFunctions"
        Effect = "Allow"
        Action = "states:StartExecution"
        Resource = "*"
      },
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = "*"
      },
      {
        Sid    = "SendToSQS"
        Effect = "Allow"
        Action = "sqs:SendMessage"
        Resource = "*"
      },
      {
        Sid    = "PublishToSNS"
        Effect = "Allow"
        Action = "sns:Publish"
        Resource = "*"
      }
    ]
  })
}

################################################################################
# Scheduled Rules
################################################################################

resource "aws_cloudwatch_event_rule" "scheduled" {
  for_each = { for k, v in local.scheduled_rules : k => v if v.target_arn != "" }

  name                = "${local.prefix}-${each.key}"
  description         = lookup(each.value, "description", "Scheduled rule ${each.key}")
  schedule_expression = each.value.schedule_expression
  event_bus_name      = local.event_bus_name
  state               = each.value.enabled ? "ENABLED" : "DISABLED"

  tags = { Name = "${local.prefix}-${each.key}" }
}

resource "aws_cloudwatch_event_target" "scheduled" {
  for_each = { for k, v in local.scheduled_rules : k => v if v.target_arn != "" }

  rule           = aws_cloudwatch_event_rule.scheduled[each.key].name
  event_bus_name = local.event_bus_name
  target_id      = each.key
  arn            = each.value.target_arn
  role_arn       = each.value.target_type == "step-function" ? aws_iam_role.eventbridge.arn : null
  input          = lookup(each.value, "input", null)

  dynamic "dead_letter_config" {
    for_each = local.enable_dlq ? [1] : []
    content {
      arn = aws_sqs_queue.dlq[0].arn
    }
  }
}

################################################################################
# Event Pattern Rules
################################################################################

resource "aws_cloudwatch_event_rule" "pattern" {
  for_each = { for k, v in local.event_pattern_rules : k => v if v.target_arn != "" }

  name           = "${local.prefix}-${each.key}"
  description    = lookup(each.value, "description", "Event pattern rule ${each.key}")
  event_pattern  = each.value.event_pattern
  event_bus_name = local.event_bus_name
  state          = each.value.enabled ? "ENABLED" : "DISABLED"

  tags = { Name = "${local.prefix}-${each.key}" }
}

resource "aws_cloudwatch_event_target" "pattern" {
  for_each = { for k, v in local.event_pattern_rules : k => v if v.target_arn != "" }

  rule           = aws_cloudwatch_event_rule.pattern[each.key].name
  event_bus_name = local.event_bus_name
  target_id      = each.key
  arn            = each.value.target_arn
  role_arn       = each.value.target_type == "step-function" ? aws_iam_role.eventbridge.arn : null
  input          = lookup(each.value, "input", null)

  dynamic "input_transformer" {
    for_each = lookup(each.value, "input_transformer", null) != null ? [each.value.input_transformer] : []
    content {
      input_paths    = input_transformer.value.input_paths
      input_template = input_transformer.value.input_template
    }
  }

  dynamic "dead_letter_config" {
    for_each = local.enable_dlq ? [1] : []
    content {
      arn = aws_sqs_queue.dlq[0].arn
    }
  }
}

################################################################################
# Lambda Permissions
################################################################################

resource "aws_lambda_permission" "scheduled" {
  for_each = { for k, v in local.scheduled_rules : k => v if v.target_arn != "" && v.target_type == "lambda" }

  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = regex("function:([^:]+)", each.value.target_arn)[0]
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled[each.key].arn
}

resource "aws_lambda_permission" "pattern" {
  for_each = { for k, v in local.event_pattern_rules : k => v if v.target_arn != "" && v.target_type == "lambda" }

  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = regex("function:([^:]+)", each.value.target_arn)[0]
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.pattern[each.key].arn
}

################################################################################
# Outputs
################################################################################

output "scheduled_rule_arns" {
  value       = { for k, v in aws_cloudwatch_event_rule.scheduled : k => v.arn }
  description = "Scheduled rule ARNs"
}

output "pattern_rule_arns" {
  value       = { for k, v in aws_cloudwatch_event_rule.pattern : k => v.arn }
  description = "Event pattern rule ARNs"
}

output "dlq_arn" {
  value       = local.enable_dlq ? aws_sqs_queue.dlq[0].arn : null
  description = "Dead letter queue ARN"
}

output "eventbridge_role_arn" {
  value       = aws_iam_role.eventbridge.arn
  description = "EventBridge execution role ARN"
}

output "cron_examples" {
  value = {
    every_5_min    = "rate(5 minutes)"
    every_hour     = "rate(1 hour)"
    daily_9am_utc  = "cron(0 9 * * ? *)"
    weekdays_8am   = "cron(0 8 ? * MON-FRI *)"
    monthly_1st    = "cron(0 0 1 * ? *)"
    every_monday   = "cron(0 12 ? * MON *)"
  }
  description = "Cron expression examples"
}
