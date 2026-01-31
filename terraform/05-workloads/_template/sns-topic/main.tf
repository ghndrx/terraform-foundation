################################################################################
# Workload: SNS Topic
# 
# Pub/Sub messaging with:
# - Multiple subscription types (Lambda, SQS, HTTP, Email, SMS)
# - Message filtering
# - Dead letter queue
# - KMS encryption
# - Cross-account publishing
# - FIFO topics (ordered, exactly-once)
#
# Use cases: Event fan-out, notifications, decoupling services
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
    key = "05-workloads/<TENANT>-<NAME>-sns/terraform.tfstate"
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
  
  topic_name = "${local.tenant}-${local.name}-${local.env}"

  # FIFO topic (ordered, exactly-once delivery)
  fifo_topic                  = false
  content_based_deduplication = false

  # Encryption
  kms_key_arn = null # null = AWS managed key

  # Message delivery settings
  delivery_policy = {
    http = {
      defaultHealthyRetryPolicy = {
        minDelayTarget     = 20
        maxDelayTarget     = 20
        numRetries         = 3
        numMaxDelayRetries = 0
        numNoDelayRetries  = 0
        numMinDelayRetries = 0
        backoffFunction    = "linear"
      }
      disableSubscriptionOverrides = false
    }
  }

  # Subscriptions
  subscriptions = {
    # Lambda subscription
    # "process-events" = {
    #   protocol = "lambda"
    #   endpoint = "arn:aws:lambda:us-east-1:123456789012:function:process-events"
    #   filter_policy = {
    #     event_type = ["order.created", "order.updated"]
    #   }
    # }

    # SQS subscription
    # "event-queue" = {
    #   protocol = "sqs"
    #   endpoint = "arn:aws:sqs:us-east-1:123456789012:event-queue"
    #   raw_message_delivery = true
    # }

    # Email subscription
    # "alerts" = {
    #   protocol = "email"
    #   endpoint = "alerts@example.com"
    # }

    # HTTP/HTTPS subscription
    # "webhook" = {
    #   protocol = "https"
    #   endpoint = "https://api.example.com/webhook"
    #   filter_policy = {
    #     severity = ["high", "critical"]
    #   }
    # }
  }

  # Cross-account publish access
  publish_accounts = [
    # "123456789012",
  ]

  # Cross-account subscribe access
  subscribe_accounts = [
    # "234567890123",
  ]

  # AWS service publish access
  aws_service_principals = [
    # "events.amazonaws.com",      # EventBridge
    # "cloudwatch.amazonaws.com",  # CloudWatch Alarms
    # "s3.amazonaws.com",          # S3 Event Notifications
    # "ses.amazonaws.com",         # SES Notifications
  ]

  # Dead letter queue for failed deliveries
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
# SNS Topic
################################################################################

resource "aws_sns_topic" "main" {
  name = local.fifo_topic ? "${local.topic_name}.fifo" : local.topic_name

  fifo_topic                  = local.fifo_topic
  content_based_deduplication = local.fifo_topic ? local.content_based_deduplication : null

  kms_master_key_id = local.kms_key_arn != null ? local.kms_key_arn : "alias/aws/sns"

  delivery_policy = jsonencode(local.delivery_policy)

  tags = { Name = local.topic_name }
}

################################################################################
# Dead Letter Queue
################################################################################

resource "aws_sqs_queue" "dlq" {
  count = local.enable_dlq ? 1 : 0
  name  = local.fifo_topic ? "${local.topic_name}-dlq.fifo" : "${local.topic_name}-dlq"

  fifo_queue                  = local.fifo_topic
  content_based_deduplication = local.fifo_topic

  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = "alias/aws/sqs"

  tags = { Name = "${local.topic_name}-dlq" }
}

resource "aws_sqs_queue_policy" "dlq" {
  count     = local.enable_dlq ? 1 : 0
  queue_url = aws_sqs_queue.dlq[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowSNS"
      Effect = "Allow"
      Principal = {
        Service = "sns.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.dlq[0].arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_sns_topic.main.arn
        }
      }
    }]
  })
}

################################################################################
# Topic Policy
################################################################################

resource "aws_sns_topic_policy" "main" {
  arn = aws_sns_topic.main.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Allow account root
      [{
        Sid    = "DefaultPolicy"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "sns:Publish",
          "sns:Subscribe",
          "sns:Receive",
          "sns:ListSubscriptionsByTopic",
          "sns:GetTopicAttributes"
        ]
        Resource = aws_sns_topic.main.arn
      }],

      # Cross-account publish
      length(local.publish_accounts) > 0 ? [{
        Sid    = "CrossAccountPublish"
        Effect = "Allow"
        Principal = {
          AWS = [for acct in local.publish_accounts : "arn:aws:iam::${acct}:root"]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.main.arn
      }] : [],

      # Cross-account subscribe
      length(local.subscribe_accounts) > 0 ? [{
        Sid    = "CrossAccountSubscribe"
        Effect = "Allow"
        Principal = {
          AWS = [for acct in local.subscribe_accounts : "arn:aws:iam::${acct}:root"]
        }
        Action   = "sns:Subscribe"
        Resource = aws_sns_topic.main.arn
      }] : [],

      # AWS service access
      length(local.aws_service_principals) > 0 ? [{
        Sid    = "AWSServicePublish"
        Effect = "Allow"
        Principal = {
          Service = local.aws_service_principals
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.main.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }] : []
    )
  })
}

################################################################################
# Subscriptions
################################################################################

resource "aws_sns_topic_subscription" "subscriptions" {
  for_each = local.subscriptions

  topic_arn = aws_sns_topic.main.arn
  protocol  = each.value.protocol
  endpoint  = each.value.endpoint

  filter_policy        = lookup(each.value, "filter_policy", null) != null ? jsonencode(each.value.filter_policy) : null
  filter_policy_scope  = lookup(each.value, "filter_policy", null) != null ? "MessageAttributes" : null
  raw_message_delivery = lookup(each.value, "raw_message_delivery", false)

  redrive_policy = local.enable_dlq ? jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[0].arn
  }) : null
}

# Lambda permissions for SNS to invoke
resource "aws_lambda_permission" "sns" {
  for_each = { for k, v in local.subscriptions : k => v if v.protocol == "lambda" }

  statement_id  = "AllowSNS-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = regex("function:([^:]+)$", each.value.endpoint)[0]
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.main.arn
}

################################################################################
# IAM Policies
################################################################################

resource "aws_iam_policy" "publish" {
  name        = "${local.topic_name}-sns-publish"
  description = "Publish to ${local.topic_name} SNS topic"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishToTopic"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.main.arn
      },
      {
        Sid    = "DecryptKMS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = local.kms_key_arn != null ? [local.kms_key_arn] : ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/sns"]
      }
    ]
  })

  tags = { Name = "${local.topic_name}-publish" }
}

################################################################################
# Outputs
################################################################################

output "topic_arn" {
  value       = aws_sns_topic.main.arn
  description = "SNS topic ARN"
}

output "topic_name" {
  value       = aws_sns_topic.main.name
  description = "SNS topic name"
}

output "dlq_arn" {
  value       = local.enable_dlq ? aws_sqs_queue.dlq[0].arn : null
  description = "Dead letter queue ARN"
}

output "dlq_url" {
  value       = local.enable_dlq ? aws_sqs_queue.dlq[0].url : null
  description = "Dead letter queue URL"
}

output "publish_policy_arn" {
  value       = aws_iam_policy.publish.arn
  description = "IAM policy ARN for publishing"
}

output "subscription_arns" {
  value       = { for k, v in aws_sns_topic_subscription.subscriptions : k => v.arn }
  description = "Subscription ARNs"
}

output "publish_example" {
  value       = "aws sns publish --topic-arn ${aws_sns_topic.main.arn} --message '{\"event\": \"test\"}' --message-attributes '{\"event_type\": {\"DataType\": \"String\", \"StringValue\": \"test\"}}'"
  description = "Example publish command"
}
