################################################################################
# Workload: API Gateway REST API
# 
# Deploys a REST API with:
# - API Gateway with stages
# - Lambda or HTTP backend integrations
# - Custom domain with ACM
# - WAF integration (optional)
# - CloudWatch logging
# - Usage plans and API keys
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<api-name>/
#   Update locals
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
    key = "05-workloads/<TENANT>-<NAME>-api/terraform.tfstate"
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
  
  api_name = "${local.tenant}-${local.name}-${local.env}"

  # API Type: REST or HTTP
  api_type = "REST" # REST for full features, HTTP for simpler/cheaper

  # Custom domain (set to null to skip)
  domain_name    = null # e.g., "api.example.com"
  hosted_zone_id = null # Route53 zone ID
  
  # WAF (requires waf-alb module deployed)
  waf_acl_arn = null

  # Stages
  stages = ["prod", "staging"]

  # Throttling defaults
  throttle_burst_limit = 100
  throttle_rate_limit  = 50

  # CloudWatch logging
  logging_level = "INFO" # OFF, ERROR, INFO

  # Lambda integrations (map of path -> lambda ARN)
  lambda_integrations = {
    # "GET /users"     = "arn:aws:lambda:us-east-1:123456789012:function:get-users"
    # "POST /users"    = "arn:aws:lambda:us-east-1:123456789012:function:create-user"
    # "GET /users/{id}" = "arn:aws:lambda:us-east-1:123456789012:function:get-user"
  }

  # HTTP proxy integrations (map of path -> HTTP endpoint)
  http_integrations = {
    # "GET /health" = "https://backend.example.com/health"
  }

  # Mock integrations for static responses
  mock_integrations = {
    "GET /health" = {
      status_code = "200"
      response    = jsonencode({ status = "healthy" })
    }
  }

  # CORS configuration
  cors_enabled = true
  cors_origins = ["*"]
  cors_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  cors_headers = ["Content-Type", "Authorization", "X-Api-Key"]

  # API Keys and Usage Plans
  create_api_key = true
  usage_plans = {
    basic = {
      quota_limit  = 1000
      quota_period = "MONTH"
      throttle_burst = 10
      throttle_rate  = 5
    }
    premium = {
      quota_limit  = 100000
      quota_period = "MONTH"
      throttle_burst = 100
      throttle_rate  = 50
    }
  }
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
# REST API
################################################################################

resource "aws_api_gateway_rest_api" "main" {
  name        = local.api_name
  description = "REST API for ${local.tenant} ${local.name}"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = { Name = local.api_name }
}

################################################################################
# CloudWatch Logging
################################################################################

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/api-gateway/${local.api_name}"
  retention_in_days = 30

  tags = { Name = local.api_name }
}

resource "aws_api_gateway_account" "main" {
  cloudwatch_role_arn = aws_iam_role.api_logging.arn
}

resource "aws_iam_role" "api_logging" {
  name = "${local.api_name}-api-logging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "apigateway.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.api_name}-api-logging" }
}

resource "aws_iam_role_policy_attachment" "api_logging" {
  role       = aws_iam_role.api_logging.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

################################################################################
# Mock Integration - Health Check
################################################################################

resource "aws_api_gateway_resource" "health" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "health_get" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.health.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "health_get" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_get.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_method_response" "health_get" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_get.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
  }
}

resource "aws_api_gateway_integration_response" "health_get" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_get.http_method
  status_code = aws_api_gateway_method_response.health_get.status_code

  response_templates = {
    "application/json" = jsonencode({
      status    = "healthy"
      timestamp = "$context.requestTime"
    })
  }

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = "'*'"
  }

  depends_on = [aws_api_gateway_integration.health_get]
}

################################################################################
# CORS - OPTIONS method for health
################################################################################

resource "aws_api_gateway_method" "health_options" {
  count         = local.cors_enabled ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.health.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "health_options" {
  count       = local.cors_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_options[0].http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_method_response" "health_options" {
  count       = local.cors_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_options[0].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "health_options" {
  count       = local.cors_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_options[0].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'${join(",", local.cors_headers)}'"
    "method.response.header.Access-Control-Allow-Methods" = "'${join(",", local.cors_methods)}'"
    "method.response.header.Access-Control-Allow-Origin"  = "'${join(",", local.cors_origins)}'"
  }

  depends_on = [aws_api_gateway_integration.health_options]
}

################################################################################
# Deployment & Stages
################################################################################

resource "aws_api_gateway_deployment" "main" {
  rest_api_id = aws_api_gateway_rest_api.main.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.health.id,
      aws_api_gateway_method.health_get.id,
      aws_api_gateway_integration.health_get.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.health_get,
    aws_api_gateway_integration_response.health_get,
  ]
}

resource "aws_api_gateway_stage" "stages" {
  for_each = toset(local.stages)

  deployment_id = aws_api_gateway_deployment.main.id
  rest_api_id   = aws_api_gateway_rest_api.main.id
  stage_name    = each.value

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId         = "$context.requestId"
      ip                = "$context.identity.sourceIp"
      caller            = "$context.identity.caller"
      user              = "$context.identity.user"
      requestTime       = "$context.requestTime"
      httpMethod        = "$context.httpMethod"
      resourcePath      = "$context.resourcePath"
      status            = "$context.status"
      protocol          = "$context.protocol"
      responseLength    = "$context.responseLength"
      integrationLatency = "$context.integrationLatency"
    })
  }

  tags = { Name = "${local.api_name}-${each.value}" }
}

resource "aws_api_gateway_method_settings" "stages" {
  for_each = toset(local.stages)

  rest_api_id = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.stages[each.value].stage_name
  method_path = "*/*"

  settings {
    logging_level      = local.logging_level
    data_trace_enabled = local.logging_level != "OFF"
    metrics_enabled    = true

    throttling_burst_limit = local.throttle_burst_limit
    throttling_rate_limit  = local.throttle_rate_limit
  }
}

################################################################################
# WAF Association (Optional)
################################################################################

resource "aws_wafv2_web_acl_association" "api" {
  count        = local.waf_acl_arn != null ? length(local.stages) : 0
  resource_arn = aws_api_gateway_stage.stages[local.stages[count.index]].arn
  web_acl_arn  = local.waf_acl_arn
}

################################################################################
# Custom Domain (Optional)
################################################################################

resource "aws_acm_certificate" "api" {
  count             = local.domain_name != null ? 1 : 0
  domain_name       = local.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = local.domain_name }
}

resource "aws_route53_record" "cert_validation" {
  for_each = local.domain_name != null ? {
    for dvo in aws_acm_certificate.api[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  zone_id = local.hosted_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "api" {
  count                   = local.domain_name != null ? 1 : 0
  certificate_arn         = aws_acm_certificate.api[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

resource "aws_api_gateway_domain_name" "main" {
  count           = local.domain_name != null ? 1 : 0
  domain_name     = local.domain_name
  certificate_arn = aws_acm_certificate_validation.api[0].certificate_arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = { Name = local.domain_name }
}

resource "aws_api_gateway_base_path_mapping" "main" {
  count       = local.domain_name != null ? 1 : 0
  api_id      = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.stages["prod"].stage_name
  domain_name = aws_api_gateway_domain_name.main[0].domain_name
}

resource "aws_route53_record" "api" {
  count   = local.domain_name != null ? 1 : 0
  zone_id = local.hosted_zone_id
  name    = local.domain_name
  type    = "A"

  alias {
    name                   = aws_api_gateway_domain_name.main[0].regional_domain_name
    zone_id                = aws_api_gateway_domain_name.main[0].regional_zone_id
    evaluate_target_health = false
  }
}

################################################################################
# API Keys & Usage Plans
################################################################################

resource "aws_api_gateway_api_key" "main" {
  count   = local.create_api_key ? 1 : 0
  name    = "${local.api_name}-key"
  enabled = true

  tags = { Name = "${local.api_name}-key" }
}

resource "aws_api_gateway_usage_plan" "plans" {
  for_each = local.usage_plans

  name = "${local.api_name}-${each.key}"

  api_stages {
    api_id = aws_api_gateway_rest_api.main.id
    stage  = aws_api_gateway_stage.stages["prod"].stage_name
  }

  quota_settings {
    limit  = each.value.quota_limit
    period = each.value.quota_period
  }

  throttle_settings {
    burst_limit = each.value.throttle_burst
    rate_limit  = each.value.throttle_rate
  }

  tags = { Name = "${local.api_name}-${each.key}" }
}

resource "aws_api_gateway_usage_plan_key" "main" {
  count         = local.create_api_key ? 1 : 0
  key_id        = aws_api_gateway_api_key.main[0].id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.plans["basic"].id
}

################################################################################
# Outputs
################################################################################

output "api_id" {
  value = aws_api_gateway_rest_api.main.id
}

output "api_name" {
  value = aws_api_gateway_rest_api.main.name
}

output "stage_urls" {
  value = { for stage in local.stages : stage => aws_api_gateway_stage.stages[stage].invoke_url }
}

output "custom_domain_url" {
  value = local.domain_name != null ? "https://${local.domain_name}" : null
}

output "api_key" {
  value     = local.create_api_key ? aws_api_gateway_api_key.main[0].value : null
  sensitive = true
}

output "health_endpoint" {
  value = "${aws_api_gateway_stage.stages["prod"].invoke_url}health"
}
