################################################################################
# Workload: Step Functions State Machine
# 
# Deploys a serverless workflow:
# - Step Functions state machine
# - IAM role with least-privilege
# - CloudWatch logging
# - X-Ray tracing
# - EventBridge trigger (optional)
# - API Gateway trigger (optional)
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<workflow-name>/
#   Update the state machine definition in definition.json
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
    key = "05-workloads/<TENANT>-<NAME>-workflow/terraform.tfstate"
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
  
  state_machine_name = "${local.tenant}-${local.name}-${local.env}"

  # State machine type: STANDARD or EXPRESS
  # STANDARD: Long-running (up to 1 year), exactly-once execution
  # EXPRESS: Short-duration (up to 5 min), at-least-once, cheaper
  type = "STANDARD"

  # Logging level: OFF, ALL, ERROR, FATAL
  logging_level = "ERROR"

  # X-Ray tracing
  tracing_enabled = true

  # EventBridge trigger (set to null to disable)
  schedule_expression = null  # e.g., "rate(1 hour)" or "cron(0 12 * * ? *)"

  # API Gateway trigger
  enable_api_trigger = false

  # Lambda functions this workflow can invoke (ARNs)
  lambda_arns = [
    # "arn:aws:lambda:us-east-1:123456789012:function:my-function",
  ]

  # DynamoDB tables this workflow can access (ARNs)
  dynamodb_arns = [
    # "arn:aws:dynamodb:us-east-1:123456789012:table/my-table",
  ]

  # SQS queues this workflow can send to (ARNs)
  sqs_arns = [
    # "arn:aws:sqs:us-east-1:123456789012:my-queue",
  ]

  # SNS topics this workflow can publish to (ARNs)
  sns_arns = [
    # "arn:aws:sns:us-east-1:123456789012:my-topic",
  ]

  # S3 buckets this workflow can access (ARNs)
  s3_arns = [
    # "arn:aws:s3:::my-bucket/*",
  ]
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
# CloudWatch Log Group
################################################################################

resource "aws_cloudwatch_log_group" "main" {
  name              = "/aws/states/${local.state_machine_name}"
  retention_in_days = 30

  tags = { Name = local.state_machine_name }
}

################################################################################
# IAM Role
################################################################################

resource "aws_iam_role" "state_machine" {
  name = "${local.state_machine_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.state_machine_name}-role" }
}

# CloudWatch Logs permissions
resource "aws_iam_role_policy" "logs" {
  name = "cloudwatch-logs"
  role = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogDelivery",
        "logs:CreateLogStream",
        "logs:GetLogDelivery",
        "logs:UpdateLogDelivery",
        "logs:DeleteLogDelivery",
        "logs:ListLogDeliveries",
        "logs:PutLogEvents",
        "logs:PutResourcePolicy",
        "logs:DescribeResourcePolicies",
        "logs:DescribeLogGroups"
      ]
      Resource = "*"
    }]
  })
}

# X-Ray permissions
resource "aws_iam_role_policy" "xray" {
  count = local.tracing_enabled ? 1 : 0
  name  = "xray"
  role  = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords",
        "xray:GetSamplingRules",
        "xray:GetSamplingTargets"
      ]
      Resource = "*"
    }]
  })
}

# Lambda invocation permissions
resource "aws_iam_role_policy" "lambda" {
  count = length(local.lambda_arns) > 0 ? 1 : 0
  name  = "lambda"
  role  = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = local.lambda_arns
    }]
  })
}

# DynamoDB permissions
resource "aws_iam_role_policy" "dynamodb" {
  count = length(local.dynamodb_arns) > 0 ? 1 : 0
  name  = "dynamodb"
  role  = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ]
      Resource = local.dynamodb_arns
    }]
  })
}

# SQS permissions
resource "aws_iam_role_policy" "sqs" {
  count = length(local.sqs_arns) > 0 ? 1 : 0
  name  = "sqs"
  role  = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:SendMessage",
        "sqs:GetQueueUrl"
      ]
      Resource = local.sqs_arns
    }]
  })
}

# SNS permissions
resource "aws_iam_role_policy" "sns" {
  count = length(local.sns_arns) > 0 ? 1 : 0
  name  = "sns"
  role  = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = local.sns_arns
    }]
  })
}

# S3 permissions
resource "aws_iam_role_policy" "s3" {
  count = length(local.s3_arns) > 0 ? 1 : 0
  name  = "s3"
  role  = aws_iam_role.state_machine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ]
      Resource = local.s3_arns
    }]
  })
}

################################################################################
# State Machine Definition
################################################################################

# Simple example - replace with your actual workflow
locals {
  state_machine_definition = jsonencode({
    Comment = "Example workflow for ${local.tenant} ${local.name}"
    StartAt = "ProcessInput"
    States = {
      ProcessInput = {
        Type = "Pass"
        Parameters = {
          "input.$"   = "$"
          "timestamp" = "$$.State.EnteredTime"
        }
        Next = "Success"
      }
      Success = {
        Type = "Succeed"
      }
    }
  })
}

################################################################################
# Step Functions State Machine
################################################################################

resource "aws_sfn_state_machine" "main" {
  name     = local.state_machine_name
  role_arn = aws_iam_role.state_machine.arn
  type     = local.type

  definition = local.state_machine_definition

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.main.arn}:*"
    include_execution_data = true
    level                  = local.logging_level
  }

  tracing_configuration {
    enabled = local.tracing_enabled
  }

  tags = { Name = local.state_machine_name }
}

################################################################################
# EventBridge Schedule Trigger
################################################################################

resource "aws_cloudwatch_event_rule" "schedule" {
  count               = local.schedule_expression != null ? 1 : 0
  name                = "${local.state_machine_name}-schedule"
  description         = "Trigger ${local.state_machine_name} on schedule"
  schedule_expression = local.schedule_expression

  tags = { Name = "${local.state_machine_name}-schedule" }
}

resource "aws_cloudwatch_event_target" "schedule" {
  count     = local.schedule_expression != null ? 1 : 0
  rule      = aws_cloudwatch_event_rule.schedule[0].name
  target_id = "StepFunctions"
  arn       = aws_sfn_state_machine.main.arn
  role_arn  = aws_iam_role.eventbridge[0].arn

  input = jsonencode({
    source    = "scheduled"
    timestamp = "$.time"
  })
}

resource "aws_iam_role" "eventbridge" {
  count = local.schedule_expression != null ? 1 : 0
  name  = "${local.state_machine_name}-eventbridge"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.state_machine_name}-eventbridge" }
}

resource "aws_iam_role_policy" "eventbridge" {
  count = local.schedule_expression != null ? 1 : 0
  name  = "start-execution"
  role  = aws_iam_role.eventbridge[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.main.arn
    }]
  })
}

################################################################################
# API Gateway Trigger
################################################################################

resource "aws_apigatewayv2_api" "main" {
  count         = local.enable_api_trigger ? 1 : 0
  name          = local.state_machine_name
  protocol_type = "HTTP"

  tags = { Name = local.state_machine_name }
}

resource "aws_apigatewayv2_stage" "main" {
  count       = local.enable_api_trigger ? 1 : 0
  api_id      = aws_apigatewayv2_api.main[0].id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "main" {
  count              = local.enable_api_trigger ? 1 : 0
  api_id             = aws_apigatewayv2_api.main[0].id
  integration_type   = "AWS_PROXY"
  integration_subtype = "StepFunctions-StartExecution"
  credentials_arn    = aws_iam_role.api[0].arn

  request_parameters = {
    StateMachineArn = aws_sfn_state_machine.main.arn
    Input          = "$request.body"
  }
}

resource "aws_apigatewayv2_route" "main" {
  count     = local.enable_api_trigger ? 1 : 0
  api_id    = aws_apigatewayv2_api.main[0].id
  route_key = "POST /execute"
  target    = "integrations/${aws_apigatewayv2_integration.main[0].id}"
}

resource "aws_iam_role" "api" {
  count = local.enable_api_trigger ? 1 : 0
  name  = "${local.state_machine_name}-api"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "apigateway.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.state_machine_name}-api" }
}

resource "aws_iam_role_policy" "api" {
  count = local.enable_api_trigger ? 1 : 0
  name  = "start-execution"
  role  = aws_iam_role.api[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.main.arn
    }]
  })
}

################################################################################
# Outputs
################################################################################

output "state_machine_arn" {
  value = aws_sfn_state_machine.main.arn
}

output "state_machine_name" {
  value = aws_sfn_state_machine.main.name
}

output "role_arn" {
  value = aws_iam_role.state_machine.arn
}

output "log_group" {
  value = aws_cloudwatch_log_group.main.name
}

output "api_endpoint" {
  value = local.enable_api_trigger ? "${aws_apigatewayv2_api.main[0].api_endpoint}/execute" : null
}

output "execution_command" {
  value = "aws stepfunctions start-execution --state-machine-arn ${aws_sfn_state_machine.main.arn} --input '{\"key\": \"value\"}'"
}
