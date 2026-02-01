################################################################################
# VPC Lite Module
#
# Cost-optimized VPC for small accounts/dev environments:
# - NO NAT Gateway ($32+/mo savings)
# - VPC Endpoints for AWS service access
# - Optional NAT Instance (t4g.nano ~$3/mo)
# - Public-only or public+private subnets
#
# Tradeoffs:
# - Private subnets can't reach internet (use VPC endpoints)
# - NAT Instance is single-AZ, not HA
# - For production, use standard VPC with NAT Gateway
#
# Usage:
#   module "vpc" {
#     source = "../modules/vpc-lite"
#     name   = "dev-vpc"
#     
#     # Choose one:
#     nat_mode = "none"       # No NAT - use VPC endpoints only
#     nat_mode = "instance"   # NAT Instance (~$3/mo)
#     nat_mode = "gateway"    # NAT Gateway (~$32/mo) - for prod
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
  description = "VPC name prefix"
}

variable "cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "VPC CIDR block"
}

variable "azs" {
  type        = list(string)
  default     = []
  description = "Availability zones (auto-detected if empty)"
}

variable "az_count" {
  type        = number
  default     = 2
  description = "Number of AZs to use (if azs not specified)"
}

variable "nat_mode" {
  type        = string
  default     = "none"
  description = "NAT mode: none, instance, or gateway"

  validation {
    condition     = contains(["none", "instance", "gateway"], var.nat_mode)
    error_message = "Must be none, instance, or gateway"
  }
}

variable "create_private_subnets" {
  type        = bool
  default     = true
  description = "Create private subnets (set false for public-only)"
}

variable "enable_vpc_endpoints" {
  type        = bool
  default     = true
  description = "Create VPC endpoints for AWS services (recommended when nat_mode=none)"
}

variable "vpc_endpoint_services" {
  type        = list(string)
  default     = ["s3", "dynamodb"]
  description = "Gateway endpoints to create (s3, dynamodb)"
}

variable "vpc_endpoint_interfaces" {
  type        = list(string)
  default     = []
  description = "Interface endpoints to create (ecr.api, ecr.dkr, logs, ssm, etc.)"
}

variable "enable_flow_logs" {
  type        = bool
  default     = true
  description = "Enable VPC Flow Logs"
}

variable "flow_log_retention_days" {
  type        = number
  default     = 14
  description = "Flow log retention (shorter = cheaper)"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = length(var.azs) > 0 ? var.azs : slice(data.aws_availability_zones.available.names, 0, var.az_count)
  
  # Cost estimates (us-east-1 pricing)
  cost_estimate = {
    none     = "$0/mo for NAT (use VPC endpoints for AWS services)"
    instance = "~$3/mo (t4g.nano NAT instance, single-AZ)"
    gateway  = "~$32/mo + data transfer (recommended for production)"
  }
}

################################################################################
# VPC
################################################################################

resource "aws_vpc" "main" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name     = var.name
    NatMode  = var.nat_mode
    CostTier = var.nat_mode == "none" ? "minimal" : (var.nat_mode == "instance" ? "low" : "standard")
  })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name}-igw" })
}

################################################################################
# Subnets
################################################################################

resource "aws_subnet" "public" {
  count                   = length(local.azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.cidr, 4, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.name}-public-${local.azs[count.index]}"
    Type = "public"
  })
}

resource "aws_subnet" "private" {
  count             = var.create_private_subnets ? length(local.azs) : 0
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.cidr, 4, count.index + 8)
  availability_zone = local.azs[count.index]

  tags = merge(var.tags, {
    Name = "${var.name}-private-${local.azs[count.index]}"
    Type = "private"
  })
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

  tags = merge(var.tags, { Name = "${var.name}-public-rt" })
}

resource "aws_route_table" "private" {
  count  = var.create_private_subnets ? 1 : 0
  vpc_id = aws_vpc.main.id

  # NAT route added dynamically based on nat_mode
  dynamic "route" {
    for_each = var.nat_mode == "gateway" ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[0].id
    }
  }

  dynamic "route" {
    for_each = var.nat_mode == "instance" ? [1] : []
    content {
      cidr_block           = "0.0.0.0/0"
      network_interface_id = aws_instance.nat[0].primary_network_interface_id
    }
  }

  # No route for nat_mode = "none" - private subnets are isolated

  tags = merge(var.tags, { Name = "${var.name}-private-rt" })
}

resource "aws_route_table_association" "public" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = var.create_private_subnets ? length(local.azs) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

################################################################################
# NAT Gateway (nat_mode = "gateway")
################################################################################

resource "aws_eip" "nat" {
  count  = var.nat_mode == "gateway" ? 1 : 0
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.name}-nat-eip" })
}

resource "aws_nat_gateway" "main" {
  count         = var.nat_mode == "gateway" ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags       = merge(var.tags, { Name = "${var.name}-nat" })
  depends_on = [aws_internet_gateway.main]
}

################################################################################
# NAT Instance (nat_mode = "instance")
# Uses Amazon Linux 2023 with iptables NAT
################################################################################

data "aws_ami" "nat" {
  count       = var.nat_mode == "instance" ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "nat" {
  count       = var.nat_mode == "instance" ? 1 : 0
  name        = "${var.name}-nat-instance"
  description = "NAT instance security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.name}-nat-instance" })
}

resource "aws_instance" "nat" {
  count                = var.nat_mode == "instance" ? 1 : 0
  ami                  = data.aws_ami.nat[0].id
  instance_type        = "t4g.nano" # ~$3/mo
  subnet_id            = aws_subnet.public[0].id
  source_dest_check    = false # Required for NAT

  vpc_security_group_ids = [aws_security_group.nat[0].id]

  user_data = <<-EOF
    #!/bin/bash
    # Enable IP forwarding and NAT
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    
    # Configure iptables NAT
    yum install -y iptables-services
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A FORWARD -i eth0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT
    service iptables save
    systemctl enable iptables
  EOF

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2
    http_put_response_hop_limit = 1
  }

  tags = merge(var.tags, { Name = "${var.name}-nat-instance" })

  lifecycle {
    ignore_changes = [ami]
  }
}

################################################################################
# VPC Endpoints (recommended for nat_mode = "none")
################################################################################

# Gateway Endpoints (free)
resource "aws_vpc_endpoint" "gateway" {
  for_each = var.enable_vpc_endpoints ? toset(var.vpc_endpoint_services) : []

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type = "Gateway"

  route_table_ids = compact([
    aws_route_table.public.id,
    var.create_private_subnets ? aws_route_table.private[0].id : null
  ])

  tags = merge(var.tags, { Name = "${var.name}-${each.value}-endpoint" })
}

# Interface Endpoints (cost per hour + data)
resource "aws_security_group" "endpoints" {
  count       = var.enable_vpc_endpoints && length(var.vpc_endpoint_interfaces) > 0 ? 1 : 0
  name        = "${var.name}-vpc-endpoints"
  description = "VPC Interface Endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }

  tags = merge(var.tags, { Name = "${var.name}-vpc-endpoints" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each = var.enable_vpc_endpoints ? toset(var.vpc_endpoint_interfaces) : []

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = var.create_private_subnets ? aws_subnet.private[*].id : aws_subnet.public[*].id
  security_group_ids = [aws_security_group.endpoints[0].id]

  tags = merge(var.tags, { Name = "${var.name}-${replace(each.value, ".", "-")}-endpoint" })
}

################################################################################
# Default Security Group - Deny All
################################################################################

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name}-default-deny" })
}

################################################################################
# Flow Logs (optional, shorter retention = cheaper)
################################################################################

resource "aws_flow_log" "main" {
  count                    = var.enable_flow_logs ? 1 : 0
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs[0].arn
  iam_role_arn             = aws_iam_role.flow_logs[0].arn
  max_aggregation_interval = 600 # 10 min aggregation (cheaper)

  tags = merge(var.tags, { Name = "${var.name}-flow-logs" })
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = "/aws/vpc/${var.name}/flow-logs"
  retention_in_days = var.flow_log_retention_days

  tags = merge(var.tags, { Name = "${var.name}-flow-logs" })
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  name  = "${var.name}-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name}-flow-logs" })
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  name  = "flow-logs"
  role  = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
    }]
  })
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
  value = var.create_private_subnets ? aws_subnet.private[*].id : []
}

output "nat_mode" {
  value       = var.nat_mode
  description = "NAT mode used"
}

output "nat_ip" {
  value = var.nat_mode == "gateway" ? aws_eip.nat[0].public_ip : (
    var.nat_mode == "instance" ? aws_instance.nat[0].public_ip : null
  )
  description = "NAT public IP (if applicable)"
}

output "cost_estimate" {
  value       = local.cost_estimate[var.nat_mode]
  description = "Estimated monthly cost for NAT"
}

output "internet_access" {
  value = {
    public_subnets  = "Full internet access via IGW"
    private_subnets = var.nat_mode == "none" ? "No internet - use VPC endpoints for AWS services" : "Internet via NAT ${var.nat_mode}"
  }
  description = "Internet access summary"
}

output "vpc_endpoints" {
  value = {
    gateway   = [for k, v in aws_vpc_endpoint.gateway : k]
    interface = [for k, v in aws_vpc_endpoint.interface : k]
  }
  description = "Created VPC endpoints"
}
