################################################################################
# Lambda Function Module
#
# Reusable Lambda deployment with:
# - S3 or local zip deployment
# - VPC access (optional)
# - Environment variables
# - Secrets Manager integration
# - CloudWatch logs
# - X-Ray tracing
# - Provisioned concurrency
# - Function URL (optional)
#
# Usage:
#   module "api_lambda" {
#     source = "../modules/lambda-function"
#     
#     name    = "my-api"
#     runtime = "nodejs20.x"
#     handler = "index.handler"
#     
#     source_dir = "${path.module}/src"
#     
#     environment = {
#       LOG_LEVEL = "info"
#     }
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

variable "name" {
  type        = string
  description = "Function name"
}

variable "description" {
  type        = string
  default     = ""
  description = "Function description"
}

variable "runtime" {
  type        = string
  default     = "nodejs20.x"
  description = "Lambda runtime"
}

variable "handler" {
  type        = string
  default     = "index.handler"
  description = "Function handler"
}

variable "architectures" {
  type        = list(string)
  default     = ["arm64"]
  description = "CPU architecture (arm64 or x86_64)"
}

variable "memory_size" {
  type        = number
  default     = 256
  description = "Memory in MB (128-10240)"
}

variable "timeout" {
  type        = number
  default     = 30
  description = "Timeout in seconds (max 900)"
}

variable "reserved_concurrent_executions" {
  type        = number
  default     = -1
  description = "Reserved concurrency (-1 = unreserved)"
}

# Deployment options
variable "source_dir" {
  type        = string
  default     = ""
  description = "Local source directory to zip"
}

variable "source_file" {
  type        = string
  default     = ""
  description = "Single source file to deploy"
}

variable "s3_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket containing deployment package"
}

variable "s3_key" {
  type        = string
  default     = ""
  description = "S3 key for deployment package"
}

variable "image_uri" {
  type        = string
  default     = ""
  description = "Container image URI"
}

# VPC configuration
variable "vpc_config" {
  type = object({
    subnet_ids         = list(string)
    security_group_ids = list(string)
  })
  default     = null
  description = "VPC configuration for Lambda"
}

# Environment
variable "environment" {
  type        = map(string)
  default     = {}
  description = "Environment variables"
}

variable "secrets" {
  type        = map(string)
  default     = {}
  description = "Secrets Manager ARNs (name -> ARN)"
}

variable "ssm_parameters" {
  type        = map(string)
  default     = {}
  description = "SSM parameter ARNs (name -> ARN)"
}

# Layers
variable "layers" {
  type        = list(string)
  default     = []
  description = "Lambda layer ARNs"
}

# Tracing
variable "tracing_mode" {
  type        = string
  default     = "Active"
  description = "X-Ray tracing mode (Active, PassThrough, or empty)"
}

# Logging
variable "log_retention_days" {
  type        = number
  default     = 14
  description = "CloudWatch log retention in days"
}

variable "log_format" {
  type        = string
  default     = "Text"
  description = "Log format: Text or JSON"
}

# Function URL
variable "function_url" {
  type = object({
    enabled       = bool
    auth_type     = optional(string, "NONE")
    cors_origins  = optional(list(string), ["*"])
    cors_methods  = optional(list(string), ["*"])
    cors_headers  = optional(list(string), ["*"])
    invoke_mode   = optional(string, "BUFFERED")
  })
  default = {
    enabled = false
  }
  description = "Lambda function URL configuration"
}

# Provisioned concurrency
variable "provisioned_concurrency" {
  type        = number
  default     = 0
  description = "Provisioned concurrency (0 = disabled)"
}

# Additional IAM policies
variable "policy_arns" {
  type        = list(string)
  default     = []
  description = "Additional IAM policy ARNs to attach"
}

variable "inline_policy" {
  type        = string
  default     = ""
  description = "Inline IAM policy JSON"
}

# Dead letter queue
variable "dead_letter_arn" {
  type        = string
  default     = ""
  description = "SQS queue or SNS topic ARN for failed invocations"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Archive (if using source_dir)
################################################################################

data "archive_file" "lambda" {
  count = var.source_dir != "" ? 1 : (var.source_file != "" ? 1 : 0)

  type        = "zip"
  output_path = "${path.module}/.terraform/${var.name}.zip"

  source_dir  = var.source_dir != "" ? var.source_dir : null
  source_file = var.source_file != "" ? var.source_file : null
}

################################################################################
# IAM Role
################################################################################

resource "aws_iam_role" "lambda" {
  name = "${var.name}-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name}-lambda" })
}

# Basic execution role
resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# VPC access
resource "aws_iam_role_policy_attachment" "vpc" {
  count      = var.vpc_config != null ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# X-Ray
resource "aws_iam_role_policy_attachment" "xray" {
  count      = var.tracing_mode != "" ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# Secrets Manager access
resource "aws_iam_role_policy" "secrets" {
  count = length(var.secrets) > 0 ? 1 : 0
  name  = "secrets-access"
  role  = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = values(var.secrets)
    }]
  })
}

# SSM Parameter access
resource "aws_iam_role_policy" "ssm" {
  count = length(var.ssm_parameters) > 0 ? 1 : 0
  name  = "ssm-access"
  role  = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameter", "ssm:GetParameters"]
      Resource = values(var.ssm_parameters)
    }]
  })
}

# Additional policies
resource "aws_iam_role_policy_attachment" "additional" {
  for_each   = toset(var.policy_arns)
  role       = aws_iam_role.lambda.name
  policy_arn = each.value
}

# Inline policy
resource "aws_iam_role_policy" "inline" {
  count  = var.inline_policy != "" ? 1 : 0
  name   = "inline"
  role   = aws_iam_role.lambda.id
  policy = var.inline_policy
}

################################################################################
# CloudWatch Log Group
################################################################################

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, { Name = var.name })
}

################################################################################
# Lambda Function
################################################################################

resource "aws_lambda_function" "main" {
  function_name = var.name
  description   = var.description != "" ? var.description : "Lambda function ${var.name}"
  role          = aws_iam_role.lambda.arn

  # Deployment package
  filename         = var.source_dir != "" || var.source_file != "" ? data.archive_file.lambda[0].output_path : null
  source_code_hash = var.source_dir != "" || var.source_file != "" ? data.archive_file.lambda[0].output_base64sha256 : null
  s3_bucket        = var.s3_bucket != "" ? var.s3_bucket : null
  s3_key           = var.s3_key != "" ? var.s3_key : null
  image_uri        = var.image_uri != "" ? var.image_uri : null
  package_type     = var.image_uri != "" ? "Image" : "Zip"

  # Runtime config (not for container images)
  runtime       = var.image_uri == "" ? var.runtime : null
  handler       = var.image_uri == "" ? var.handler : null
  architectures = var.architectures
  layers        = var.image_uri == "" ? var.layers : null

  # Resources
  memory_size = var.memory_size
  timeout     = var.timeout
  reserved_concurrent_executions = var.reserved_concurrent_executions

  # Environment
  dynamic "environment" {
    for_each = length(var.environment) > 0 ? [1] : []
    content {
      variables = var.environment
    }
  }

  # VPC
  dynamic "vpc_config" {
    for_each = var.vpc_config != null ? [var.vpc_config] : []
    content {
      subnet_ids         = vpc_config.value.subnet_ids
      security_group_ids = vpc_config.value.security_group_ids
    }
  }

  # Tracing
  dynamic "tracing_config" {
    for_each = var.tracing_mode != "" ? [1] : []
    content {
      mode = var.tracing_mode
    }
  }

  # Dead letter queue
  dynamic "dead_letter_config" {
    for_each = var.dead_letter_arn != "" ? [1] : []
    content {
      target_arn = var.dead_letter_arn
    }
  }

  # Logging
  logging_config {
    log_format = var.log_format
    log_group  = aws_cloudwatch_log_group.lambda.name
  }

  tags = merge(var.tags, { Name = var.name })

  depends_on = [aws_cloudwatch_log_group.lambda]
}

################################################################################
# Function URL
################################################################################

resource "aws_lambda_function_url" "main" {
  count = var.function_url.enabled ? 1 : 0

  function_name      = aws_lambda_function.main.function_name
  authorization_type = var.function_url.auth_type
  invoke_mode        = var.function_url.invoke_mode

  cors {
    allow_origins  = var.function_url.cors_origins
    allow_methods  = var.function_url.cors_methods
    allow_headers  = var.function_url.cors_headers
    max_age        = 86400
  }
}

################################################################################
# Provisioned Concurrency
################################################################################

resource "aws_lambda_alias" "live" {
  count = var.provisioned_concurrency > 0 ? 1 : 0

  name             = "live"
  function_name    = aws_lambda_function.main.function_name
  function_version = aws_lambda_function.main.version
}

resource "aws_lambda_provisioned_concurrency_config" "main" {
  count = var.provisioned_concurrency > 0 ? 1 : 0

  function_name                     = aws_lambda_function.main.function_name
  provisioned_concurrent_executions = var.provisioned_concurrency
  qualifier                         = aws_lambda_alias.live[0].name
}

################################################################################
# Outputs
################################################################################

output "function_name" {
  value       = aws_lambda_function.main.function_name
  description = "Function name"
}

output "function_arn" {
  value       = aws_lambda_function.main.arn
  description = "Function ARN"
}

output "invoke_arn" {
  value       = aws_lambda_function.main.invoke_arn
  description = "Invoke ARN (for API Gateway)"
}

output "qualified_arn" {
  value       = aws_lambda_function.main.qualified_arn
  description = "Qualified ARN (includes version)"
}

output "role_arn" {
  value       = aws_iam_role.lambda.arn
  description = "IAM role ARN"
}

output "role_name" {
  value       = aws_iam_role.lambda.name
  description = "IAM role name"
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.lambda.name
  description = "CloudWatch log group name"
}

output "function_url" {
  value       = var.function_url.enabled ? aws_lambda_function_url.main[0].function_url : null
  description = "Function URL"
}

output "version" {
  value       = aws_lambda_function.main.version
  description = "Published version"
}
