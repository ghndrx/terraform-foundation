################################################################################
# Workload: Lambda Function
# 
# Deploys a serverless function:
# - Lambda function with VPC access (optional)
# - API Gateway HTTP API (optional)
# - CloudWatch logging & X-Ray tracing
# - EventBridge rules for scheduled invocation (optional)
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<app>/
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
    key = "05-workloads/<TENANT>-<APP>/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  app    = "<APP>"
  env    = "prod" # prod, staging, dev
  name   = "${local.tenant}-${local.app}-${local.env}"

  # Lambda config
  runtime     = "python3.12" # python3.12, nodejs20.x, go1.x, etc.
  handler     = "main.handler"
  memory_size = 256
  timeout     = 30
  
  # Source - provide ONE of these
  source_dir  = null # Path to source directory (will be zipped)
  s3_bucket   = null # S3 bucket containing deployment package
  s3_key      = null # S3 key for deployment package
  image_uri   = null # Container image URI

  # VPC - set to true for database access
  enable_vpc = false

  # API Gateway
  enable_api = true
  api_path   = "/{proxy+}"

  # Scheduled execution (cron or rate expression)
  schedule_expression = null # "rate(5 minutes)" or "cron(0 12 * * ? *)"

  # Environment variables
  environment = {
    APP_ENV   = local.env
    LOG_LEVEL = "INFO"
  }

  # Secrets (ARNs to SSM/Secrets Manager)
  secrets = {}
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
      App         = local.app
      Environment = local.env
      ManagedBy   = "terraform"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "terraform_remote_state" "network" {
  count   = local.enable_vpc ? 1 : 0
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "02-network/terraform.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "tenant" {
  count   = local.enable_vpc ? 1 : 0
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
# CloudWatch Log Group
################################################################################

resource "aws_cloudwatch_log_group" "main" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 30

  tags = { Name = local.name }
}

################################################################################
# IAM Role
################################################################################

resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-lambda" }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  count      = local.enable_vpc ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "lambda_app" {
  name = "app-permissions"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTaggedResources"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "dynamodb:*", "sqs:*", "sns:Publish"]
        Resource = "*"
        Condition = { StringEquals = { "aws:ResourceTag/Tenant" = local.tenant } }
      },
      {
        Sid      = "SecretsAccess"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters"]
        Resource = length(local.secrets) > 0 ? values(local.secrets) : ["arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${local.tenant}/*"]
      }
    ]
  })
}

################################################################################
# Security Group (VPC mode)
################################################################################

resource "aws_security_group" "lambda" {
  count       = local.enable_vpc ? 1 : 0
  name        = "${local.name}-lambda"
  description = "Lambda function ${local.name}"
  vpc_id      = data.terraform_remote_state.network[0].outputs.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-lambda" }
}

################################################################################
# Lambda Function
################################################################################

# Create zip from source directory if provided
data "archive_file" "lambda" {
  count       = local.source_dir != null ? 1 : 0
  type        = "zip"
  source_dir  = local.source_dir
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "main" {
  function_name = local.name
  description   = "${local.tenant} ${local.app} function"
  role          = aws_iam_role.lambda.arn

  # Source - exactly one must be specified
  filename         = local.source_dir != null ? data.archive_file.lambda[0].output_path : null
  source_code_hash = local.source_dir != null ? data.archive_file.lambda[0].output_base64sha256 : null
  s3_bucket        = local.s3_bucket
  s3_key           = local.s3_key
  image_uri        = local.image_uri
  package_type     = local.image_uri != null ? "Image" : "Zip"

  # Only for Zip packages
  runtime = local.image_uri == null ? local.runtime : null
  handler = local.image_uri == null ? local.handler : null

  memory_size = local.memory_size
  timeout     = local.timeout

  environment {
    variables = merge(local.environment, {
      for k, v in local.secrets : k => v
    })
  }

  dynamic "vpc_config" {
    for_each = local.enable_vpc ? [1] : []
    content {
      subnet_ids         = data.terraform_remote_state.network[0].outputs.private_subnet_ids
      security_group_ids = [
        aws_security_group.lambda[0].id,
        data.terraform_remote_state.tenant[0].outputs.security_groups.base
      ]
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.main]

  tags = { Name = local.name }
}

################################################################################
# API Gateway HTTP API
################################################################################

resource "aws_apigatewayv2_api" "main" {
  count         = local.enable_api ? 1 : 0
  name          = local.name
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }

  tags = { Name = local.name }
}

resource "aws_apigatewayv2_stage" "main" {
  count       = local.enable_api ? 1 : 0
  api_id      = aws_apigatewayv2_api.main[0].id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api[0].arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
    })
  }

  tags = { Name = local.name }
}

resource "aws_cloudwatch_log_group" "api" {
  count             = local.enable_api ? 1 : 0
  name              = "/aws/apigateway/${local.name}"
  retention_in_days = 30

  tags = { Name = "${local.name}-api" }
}

resource "aws_apigatewayv2_integration" "main" {
  count                  = local.enable_api ? 1 : 0
  api_id                 = aws_apigatewayv2_api.main[0].id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.main.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "main" {
  count     = local.enable_api ? 1 : 0
  api_id    = aws_apigatewayv2_api.main[0].id
  route_key = "ANY ${local.api_path}"
  target    = "integrations/${aws_apigatewayv2_integration.main[0].id}"
}

resource "aws_lambda_permission" "api" {
  count         = local.enable_api ? 1 : 0
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.main.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main[0].execution_arn}/*/*"
}

################################################################################
# EventBridge Schedule
################################################################################

resource "aws_cloudwatch_event_rule" "schedule" {
  count               = local.schedule_expression != null ? 1 : 0
  name                = "${local.name}-schedule"
  description         = "Schedule for ${local.name}"
  schedule_expression = local.schedule_expression

  tags = { Name = "${local.name}-schedule" }
}

resource "aws_cloudwatch_event_target" "schedule" {
  count     = local.schedule_expression != null ? 1 : 0
  rule      = aws_cloudwatch_event_rule.schedule[0].name
  target_id = "lambda"
  arn       = aws_lambda_function.main.arn
}

resource "aws_lambda_permission" "schedule" {
  count         = local.schedule_expression != null ? 1 : 0
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.main.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule[0].arn
}

################################################################################
# Outputs
################################################################################

output "function_name" {
  value = aws_lambda_function.main.function_name
}

output "function_arn" {
  value = aws_lambda_function.main.arn
}

output "invoke_arn" {
  value = aws_lambda_function.main.invoke_arn
}

output "api_endpoint" {
  value = local.enable_api ? aws_apigatewayv2_api.main[0].api_endpoint : null
}

output "log_group" {
  value = aws_cloudwatch_log_group.main.name
}

output "role_arn" {
  value = aws_iam_role.lambda.arn
}
