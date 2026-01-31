################################################################################
# Layer 02: Network
# 
# Creates shared VPC:
# - Single VPC (cost optimized)
# - Public/Private subnets
# - Single NAT Gateway
# - AWS RAM sharing (multi-account only)
#
# Depends on: 00-bootstrap (single) or 01-organization (multi)
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
    key = "02-network/terraform.tfstate"
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

variable "deployment_mode" {
  type    = string
  default = "single-account"

  validation {
    condition     = contains(["single-account", "multi-account"], var.deployment_mode)
    error_message = "Must be single-account or multi-account"
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "azs" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

variable "enable_nat" {
  type    = bool
  default = true
}

################################################################################
# Data Sources
################################################################################

data "terraform_remote_state" "org" {
  count   = var.deployment_mode == "multi-account" ? 1 : 0
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "01-organization/terraform.tfstate"
    region = var.region
  }
}

################################################################################
# Provider
################################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Layer     = "02-network"
      ManagedBy = "terraform"
    }
  }
}

################################################################################
# VPC
################################################################################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "shared-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "shared-igw" }
}

################################################################################
# Subnets
################################################################################

resource "aws_subnet" "public" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "public-${var.azs[count.index]}", Type = "public" }
}

resource "aws_subnet" "private" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 4)
  availability_zone = var.azs[count.index]

  tags = { Name = "private-${var.azs[count.index]}", Type = "private" }
}

################################################################################
# NAT Gateway
################################################################################

resource "aws_eip" "nat" {
  count  = var.enable_nat ? 1 : 0
  domain = "vpc"
  tags   = { Name = "nat-eip" }
}

resource "aws_nat_gateway" "main" {
  count         = var.enable_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags       = { Name = "shared-nat" }
  depends_on = [aws_internet_gateway.main]
}

################################################################################
# Route Tables
################################################################################

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  dynamic "route" {
    for_each = var.enable_nat ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[0].id
    }
  }

  tags = { Name = "private-rt" }
}

resource "aws_route_table_association" "public" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

################################################################################
# Default SG - Deny All
################################################################################

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "default-deny-all" }
}

################################################################################
# VPC Flow Logs (Audit Trail)
################################################################################

resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60 # 1 minute for better visibility

  tags = { Name = "vpc-flow-logs" }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 90

  tags = { Name = "vpc-flow-logs" }
}

resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })

  tags = { Name = "vpc-flow-logs" }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "vpc-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

################################################################################
# RAM Sharing (multi-account only)
################################################################################

resource "aws_ram_resource_share" "subnets" {
  count                     = var.deployment_mode == "multi-account" ? 1 : 0
  name                      = "shared-subnets"
  allow_external_principals = false
}

resource "aws_ram_resource_association" "private" {
  count              = var.deployment_mode == "multi-account" ? length(var.azs) : 0
  resource_arn       = aws_subnet.private[count.index].arn
  resource_share_arn = aws_ram_resource_share.subnets[0].arn
}

resource "aws_ram_principal_association" "workloads" {
  count              = var.deployment_mode == "multi-account" ? 1 : 0
  principal          = data.terraform_remote_state.org[0].outputs.ou_ids.workloads
  resource_share_arn = aws_ram_resource_share.subnets[0].arn
}

################################################################################
# Outputs
################################################################################

output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "nat_ip" {
  value = var.enable_nat ? aws_eip.nat[0].public_ip : null
}
