################################################################################
# CloudWatch Dashboard Module
#
# Creates CloudWatch dashboards for common AWS services:
# - ECS services
# - RDS databases
# - Lambda functions
# - ALB/NLB
# - API Gateway
#
# Usage:
#   module "dashboard" {
#     source = "../modules/cloudwatch-dashboard"
#     name   = "myapp-prod"
#     
#     ecs_clusters = ["prod-cluster"]
#     ecs_services = ["myapp-api"]
#     rds_instances = ["myapp-db"]
#     lambda_functions = ["myapp-worker"]
#     alb_arns = ["arn:aws:elasticloadbalancing:..."]
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
  description = "Dashboard name"
}

variable "ecs_clusters" {
  type        = list(string)
  default     = []
  description = "ECS cluster names to monitor"
}

variable "ecs_services" {
  type        = list(string)
  default     = []
  description = "ECS service names to monitor"
}

variable "rds_instances" {
  type        = list(string)
  default     = []
  description = "RDS instance identifiers"
}

variable "lambda_functions" {
  type        = list(string)
  default     = []
  description = "Lambda function names"
}

variable "alb_arns" {
  type        = list(string)
  default     = []
  description = "ALB ARN suffixes (app/name/id)"
}

variable "api_gateway_apis" {
  type        = list(string)
  default     = []
  description = "API Gateway API IDs"
}

variable "sqs_queues" {
  type        = list(string)
  default     = []
  description = "SQS queue names"
}

variable "dynamodb_tables" {
  type        = list(string)
  default     = []
  description = "DynamoDB table names"
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_region" "current" {}

locals {
  region = data.aws_region.current.name

  # ECS widgets
  ecs_widgets = length(var.ecs_clusters) > 0 ? [
    {
      type   = "metric"
      x      = 0
      y      = 0
      width  = 12
      height = 6
      properties = {
        title  = "ECS CPU Utilization"
        region = local.region
        metrics = [
          for i, cluster in var.ecs_clusters : [
            "AWS/ECS", "CPUUtilization",
            "ClusterName", cluster,
            "ServiceName", try(var.ecs_services[i], cluster)
          ]
        ]
        stat   = "Average"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 0
      width  = 12
      height = 6
      properties = {
        title  = "ECS Memory Utilization"
        region = local.region
        metrics = [
          for i, cluster in var.ecs_clusters : [
            "AWS/ECS", "MemoryUtilization",
            "ClusterName", cluster,
            "ServiceName", try(var.ecs_services[i], cluster)
          ]
        ]
        stat   = "Average"
        period = 300
      }
    }
  ] : []

  # RDS widgets
  rds_widgets = length(var.rds_instances) > 0 ? [
    {
      type   = "metric"
      x      = 0
      y      = 6
      width  = 8
      height = 6
      properties = {
        title  = "RDS CPU Utilization"
        region = local.region
        metrics = [
          for db in var.rds_instances : [
            "AWS/RDS", "CPUUtilization",
            "DBInstanceIdentifier", db
          ]
        ]
        stat   = "Average"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 8
      y      = 6
      width  = 8
      height = 6
      properties = {
        title  = "RDS Database Connections"
        region = local.region
        metrics = [
          for db in var.rds_instances : [
            "AWS/RDS", "DatabaseConnections",
            "DBInstanceIdentifier", db
          ]
        ]
        stat   = "Average"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 16
      y      = 6
      width  = 8
      height = 6
      properties = {
        title  = "RDS Free Storage"
        region = local.region
        metrics = [
          for db in var.rds_instances : [
            "AWS/RDS", "FreeStorageSpace",
            "DBInstanceIdentifier", db
          ]
        ]
        stat   = "Average"
        period = 300
      }
    }
  ] : []

  # Lambda widgets
  lambda_widgets = length(var.lambda_functions) > 0 ? [
    {
      type   = "metric"
      x      = 0
      y      = 12
      width  = 8
      height = 6
      properties = {
        title  = "Lambda Invocations"
        region = local.region
        metrics = [
          for fn in var.lambda_functions : [
            "AWS/Lambda", "Invocations",
            "FunctionName", fn
          ]
        ]
        stat   = "Sum"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 8
      y      = 12
      width  = 8
      height = 6
      properties = {
        title  = "Lambda Errors"
        region = local.region
        metrics = [
          for fn in var.lambda_functions : [
            "AWS/Lambda", "Errors",
            "FunctionName", fn
          ]
        ]
        stat   = "Sum"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 16
      y      = 12
      width  = 8
      height = 6
      properties = {
        title  = "Lambda Duration"
        region = local.region
        metrics = [
          for fn in var.lambda_functions : [
            "AWS/Lambda", "Duration",
            "FunctionName", fn
          ]
        ]
        stat   = "Average"
        period = 300
      }
    }
  ] : []

  # ALB widgets
  alb_widgets = length(var.alb_arns) > 0 ? [
    {
      type   = "metric"
      x      = 0
      y      = 18
      width  = 8
      height = 6
      properties = {
        title  = "ALB Request Count"
        region = local.region
        metrics = [
          for alb in var.alb_arns : [
            "AWS/ApplicationELB", "RequestCount",
            "LoadBalancer", alb
          ]
        ]
        stat   = "Sum"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 8
      y      = 18
      width  = 8
      height = 6
      properties = {
        title  = "ALB 5xx Errors"
        region = local.region
        metrics = [
          for alb in var.alb_arns : [
            "AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count",
            "LoadBalancer", alb
          ]
        ]
        stat   = "Sum"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 16
      y      = 18
      width  = 8
      height = 6
      properties = {
        title  = "ALB Response Time"
        region = local.region
        metrics = [
          for alb in var.alb_arns : [
            "AWS/ApplicationELB", "TargetResponseTime",
            "LoadBalancer", alb
          ]
        ]
        stat   = "Average"
        period = 300
      }
    }
  ] : []

  # SQS widgets
  sqs_widgets = length(var.sqs_queues) > 0 ? [
    {
      type   = "metric"
      x      = 0
      y      = 24
      width  = 12
      height = 6
      properties = {
        title  = "SQS Messages Visible"
        region = local.region
        metrics = [
          for q in var.sqs_queues : [
            "AWS/SQS", "ApproximateNumberOfMessagesVisible",
            "QueueName", q
          ]
        ]
        stat   = "Average"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 24
      width  = 12
      height = 6
      properties = {
        title  = "SQS Age of Oldest Message"
        region = local.region
        metrics = [
          for q in var.sqs_queues : [
            "AWS/SQS", "ApproximateAgeOfOldestMessage",
            "QueueName", q
          ]
        ]
        stat   = "Maximum"
        period = 300
      }
    }
  ] : []

  # DynamoDB widgets
  dynamodb_widgets = length(var.dynamodb_tables) > 0 ? [
    {
      type   = "metric"
      x      = 0
      y      = 30
      width  = 12
      height = 6
      properties = {
        title  = "DynamoDB Read Capacity"
        region = local.region
        metrics = [
          for t in var.dynamodb_tables : [
            "AWS/DynamoDB", "ConsumedReadCapacityUnits",
            "TableName", t
          ]
        ]
        stat   = "Sum"
        period = 300
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 30
      width  = 12
      height = 6
      properties = {
        title  = "DynamoDB Write Capacity"
        region = local.region
        metrics = [
          for t in var.dynamodb_tables : [
            "AWS/DynamoDB", "ConsumedWriteCapacityUnits",
            "TableName", t
          ]
        ]
        stat   = "Sum"
        period = 300
      }
    }
  ] : []

  all_widgets = concat(
    local.ecs_widgets,
    local.rds_widgets,
    local.lambda_widgets,
    local.alb_widgets,
    local.sqs_widgets,
    local.dynamodb_widgets
  )
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.name

  dashboard_body = jsonencode({
    widgets = local.all_widgets
  })
}

output "dashboard_name" {
  value = aws_cloudwatch_dashboard.main.dashboard_name
}

output "dashboard_arn" {
  value = aws_cloudwatch_dashboard.main.dashboard_arn
}
