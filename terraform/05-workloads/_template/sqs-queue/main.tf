################################################################################
# Workload: SQS Queue
# 
# Deploys a managed message queue:
# - Main queue with DLQ (dead letter queue)
# - Server-side encryption
# - CloudWatch alarms
# - Optional FIFO support
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<queue-name>-queue/
#   Update locals and variables
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
    key = "05-workloads/<TENANT>-<NAME>-queue/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  name   = "<NAME>"
  env    = "prod" # prod, staging, dev

  # Queue name (will add .fifo suffix if FIFO enabled)
  queue_name = "${local.tenant}-${local.name}-${local.env}"

  # FIFO queue (exactly-once processing, ordered)
  fifo_queue                  = false
  content_based_deduplication = false # Only for FIFO

  # Message settings
  message_retention_seconds = 1209600 # 14 days (max)
  max_message_size          = 262144  # 256 KB (max)
  delay_seconds             = 0       # Delay before message becomes visible
  receive_wait_time_seconds = 20      # Long polling (cost efficient)

  # Visibility timeout (should be > consumer processing time)
  visibility_timeout_seconds = 300 # 5 minutes

  # Dead letter queue settings
  max_receive_count = 3 # Messages go to DLQ after this many failed receives
  dlq_retention_days = 14

  # Alarm thresholds
  alarm_age_threshold      = 300  # 5 minutes - message age alarm
  alarm_messages_threshold = 1000 # Queue depth alarm
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

data "terraform_remote_state" "tenant" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "04-tenants/${local.tenant}/terraform.tfstate"
    region = var.region
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# KMS Key
################################################################################

resource "aws_kms_key" "sqs" {
  description             = "KMS key for ${local.queue_name} SQS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow SQS Service"
        Effect = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow SNS to use this key"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Name = "${local.queue_name}-sqs" }
}

resource "aws_kms_alias" "sqs" {
  name          = "alias/${local.queue_name}-sqs"
  target_key_id = aws_kms_key.sqs.key_id
}

################################################################################
# Dead Letter Queue
################################################################################

resource "aws_sqs_queue" "dlq" {
  name = local.fifo_queue ? "${local.queue_name}-dlq.fifo" : "${local.queue_name}-dlq"

  fifo_queue = local.fifo_queue

  message_retention_seconds = local.dlq_retention_days * 86400
  kms_master_key_id         = aws_kms_key.sqs.id
  kms_data_key_reuse_period_seconds = 86400 # 24 hours

  tags = { Name = "${local.queue_name}-dlq" }
}

################################################################################
# Main Queue
################################################################################

resource "aws_sqs_queue" "main" {
  name = local.fifo_queue ? "${local.queue_name}.fifo" : local.queue_name

  fifo_queue                  = local.fifo_queue
  content_based_deduplication = local.fifo_queue ? local.content_based_deduplication : null

  message_retention_seconds  = local.message_retention_seconds
  max_message_size           = local.max_message_size
  delay_seconds              = local.delay_seconds
  receive_message_wait_time_seconds = local.receive_wait_time_seconds
  visibility_timeout_seconds = local.visibility_timeout_seconds

  # Encryption
  kms_master_key_id                 = aws_kms_key.sqs.id
  kms_data_key_reuse_period_seconds = 86400 # 24 hours

  # Dead letter queue
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = local.max_receive_count
  })

  tags = { Name = local.queue_name }
}

# Allow DLQ redrive
resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.main.arn]
  })
}

################################################################################
# Queue Policy
################################################################################

resource "aws_sqs_queue_policy" "main" {
  queue_url = aws_sqs_queue.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTenantAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl"
        ]
        Resource = aws_sqs_queue.main.arn
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/Tenant" = local.tenant
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action   = "sqs:*"
        Resource = aws_sqs_queue.main.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

################################################################################
# SNS Topic for Alarms
################################################################################

resource "aws_sns_topic" "alarms" {
  name = "${local.queue_name}-alarms"
  
  tags = { Name = "${local.queue_name}-alarms" }
}

################################################################################
# CloudWatch Alarms
################################################################################

# Queue depth alarm
resource "aws_cloudwatch_metric_alarm" "depth" {
  alarm_name          = "${local.queue_name}-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Average"
  threshold           = local.alarm_messages_threshold
  alarm_description   = "Queue depth high - messages may be backing up"

  dimensions = {
    QueueName = aws_sqs_queue.main.name
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  tags = { Name = "${local.queue_name}-depth" }
}

# Message age alarm
resource "aws_cloudwatch_metric_alarm" "age" {
  alarm_name          = "${local.queue_name}-age"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = local.alarm_age_threshold
  alarm_description   = "Oldest message age high - consumers may be failing"

  dimensions = {
    QueueName = aws_sqs_queue.main.name
  }

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  tags = { Name = "${local.queue_name}-age" }
}

# DLQ messages alarm (critical - messages are failing)
resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${local.queue_name}-dlq"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Messages in DLQ - processing failures detected"

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }

  alarm_actions = [aws_sns_topic.alarms.arn]

  tags = { Name = "${local.queue_name}-dlq" }
}

################################################################################
# Outputs
################################################################################

output "queue_url" {
  value = aws_sqs_queue.main.url
}

output "queue_arn" {
  value = aws_sqs_queue.main.arn
}

output "queue_name" {
  value = aws_sqs_queue.main.name
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}

output "dlq_arn" {
  value = aws_sqs_queue.dlq.arn
}

output "kms_key_arn" {
  value = aws_kms_key.sqs.arn
}

output "alarm_topic_arn" {
  value = aws_sns_topic.alarms.arn
}
