################################################################################
# VPC Endpoints Module
#
# Provides private connectivity to AWS services without NAT Gateway:
# - Gateway endpoints (S3, DynamoDB) - FREE
# - Interface endpoints (ECR, Secrets Manager, etc.) - ~$7/mo each
#
# Cost/Security tradeoff:
# - Gateway endpoints: Always enable (free, faster)
# - Interface endpoints: Enable for high-traffic services or security requirements
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "private_route_table_ids" {
  type = list(string)
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type    = string
  default = "shared"
}

# Gateway endpoints (FREE - always enable)
variable "enable_s3_endpoint" {
  type    = bool
  default = true
}

variable "enable_dynamodb_endpoint" {
  type    = bool
  default = true
}

# Interface endpoints (~$7/mo each + data transfer)
variable "enable_ecr_endpoints" {
  type        = bool
  default     = false
  description = "ECR API + DKR endpoints for container pulls without NAT"
}

variable "enable_secrets_manager_endpoint" {
  type        = bool
  default     = false
  description = "Secrets Manager endpoint for secret retrieval without NAT"
}

variable "enable_ssm_endpoints" {
  type        = bool
  default     = false
  description = "SSM, SSM Messages, EC2 Messages for Session Manager"
}

variable "enable_logs_endpoint" {
  type        = bool
  default     = false
  description = "CloudWatch Logs endpoint"
}

variable "enable_kms_endpoint" {
  type        = bool
  default     = false
  description = "KMS endpoint for encryption operations"
}

variable "enable_sts_endpoint" {
  type        = bool
  default     = false
  description = "STS endpoint for IAM role assumption"
}

variable "enable_eks_endpoint" {
  type        = bool
  default     = false
  description = "EKS endpoint for kubectl without public access"
}

################################################################################
# Security Group for Interface Endpoints
################################################################################

resource "aws_security_group" "endpoints" {
  count       = local.any_interface_endpoint ? 1 : 0
  name        = "${var.name_prefix}-vpc-endpoints"
  description = "VPC Interface Endpoints"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.main.cidr_block]
  }

  tags = { Name = "${var.name_prefix}-vpc-endpoints" }
}

data "aws_vpc" "main" {
  id = var.vpc_id
}

locals {
  any_interface_endpoint = (
    var.enable_ecr_endpoints ||
    var.enable_secrets_manager_endpoint ||
    var.enable_ssm_endpoints ||
    var.enable_logs_endpoint ||
    var.enable_kms_endpoint ||
    var.enable_sts_endpoint ||
    var.enable_eks_endpoint
  )
}

################################################################################
# Gateway Endpoints (FREE)
################################################################################

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_s3_endpoint ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.private_route_table_ids

  tags = { Name = "${var.name_prefix}-s3" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_dynamodb_endpoint ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.private_route_table_ids

  tags = { Name = "${var.name_prefix}-dynamodb" }
}

################################################################################
# ECR Endpoints (for container pulls without NAT)
################################################################################

resource "aws_vpc_endpoint" "ecr_api" {
  count               = var.enable_ecr_endpoints ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-ecr-api" }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  count               = var.enable_ecr_endpoints ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-ecr-dkr" }
}

################################################################################
# Secrets Manager Endpoint
################################################################################

resource "aws_vpc_endpoint" "secretsmanager" {
  count               = var.enable_secrets_manager_endpoint ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-secretsmanager" }
}

################################################################################
# SSM Endpoints (for Session Manager)
################################################################################

resource "aws_vpc_endpoint" "ssm" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-ssm" }
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-ssmmessages" }
}

resource "aws_vpc_endpoint" "ec2messages" {
  count               = var.enable_ssm_endpoints ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-ec2messages" }
}

################################################################################
# CloudWatch Logs Endpoint
################################################################################

resource "aws_vpc_endpoint" "logs" {
  count               = var.enable_logs_endpoint ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-logs" }
}

################################################################################
# KMS Endpoint
################################################################################

resource "aws_vpc_endpoint" "kms" {
  count               = var.enable_kms_endpoint ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-kms" }
}

################################################################################
# STS Endpoint
################################################################################

resource "aws_vpc_endpoint" "sts" {
  count               = var.enable_sts_endpoint ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.sts"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-sts" }
}

################################################################################
# EKS Endpoint
################################################################################

resource "aws_vpc_endpoint" "eks" {
  count               = var.enable_eks_endpoint ? 1 : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.eks"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-eks" }
}

################################################################################
# Outputs
################################################################################

output "s3_endpoint_id" {
  value = var.enable_s3_endpoint ? aws_vpc_endpoint.s3[0].id : null
}

output "dynamodb_endpoint_id" {
  value = var.enable_dynamodb_endpoint ? aws_vpc_endpoint.dynamodb[0].id : null
}

output "endpoints_security_group_id" {
  value = local.any_interface_endpoint ? aws_security_group.endpoints[0].id : null
}

output "enabled_endpoints" {
  value = {
    s3              = var.enable_s3_endpoint
    dynamodb        = var.enable_dynamodb_endpoint
    ecr             = var.enable_ecr_endpoints
    secrets_manager = var.enable_secrets_manager_endpoint
    ssm             = var.enable_ssm_endpoints
    logs            = var.enable_logs_endpoint
    kms             = var.enable_kms_endpoint
    sts             = var.enable_sts_endpoint
    eks             = var.enable_eks_endpoint
  }
}
