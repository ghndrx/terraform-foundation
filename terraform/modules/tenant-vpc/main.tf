################################################################################
# Tenant VPC Module
#
# Creates tenant-isolated VPC with standard networking:
# - Dedicated CIDR block
# - Public/private subnets
# - NAT Gateway or NAT Instance
# - VPC Flow Logs
# - Optional Transit Gateway attachment
################################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  # Calculate subnets if not explicitly provided
  azs = length(var.azs) > 0 ? var.azs : slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Common tags for VPC resources
  vpc_tags = merge(var.tags, {
    Tenant = var.tenant_name
  })
}

data "aws_availability_zones" "available" {
  state = "available"
}

################################################################################
# VPC
################################################################################

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-vpc"
  })
}

################################################################################
# Internet Gateway
################################################################################

resource "aws_internet_gateway" "this" {
  count = length(var.public_subnets) > 0 ? 1 : 0

  vpc_id = aws_vpc.this.id

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-igw"
  })
}

################################################################################
# Subnets
################################################################################

resource "aws_subnet" "public" {
  count = length(var.public_subnets)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = local.azs[count.index % length(local.azs)]
  map_public_ip_on_launch = true

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-public-${local.azs[count.index % length(local.azs)]}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  count = length(var.private_subnets)

  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = local.azs[count.index % length(local.azs)]

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-private-${local.azs[count.index % length(local.azs)]}"
    Tier = "private"
  })
}

################################################################################
# NAT Gateway / Instance
################################################################################

resource "aws_eip" "nat" {
  count = var.enable_nat && var.nat_mode == "gateway" ? 1 : 0

  domain = "vpc"

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-nat-eip"
  })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  count = var.enable_nat && var.nat_mode == "gateway" ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-nat-gateway"
  })

  depends_on = [aws_internet_gateway.this]
}

# NAT Instance (cost-optimized alternative)
data "aws_ami" "nat" {
  count = var.enable_nat && var.nat_mode == "instance" ? 1 : 0

  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-vpc-nat-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_security_group" "nat" {
  count = var.enable_nat && var.nat_mode == "instance" ? 1 : 0

  name_prefix = "${var.tenant_name}-nat-"
  description = "NAT instance security group"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.private_subnets
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-nat-sg"
  })
}

resource "aws_instance" "nat" {
  count = var.enable_nat && var.nat_mode == "instance" ? 1 : 0

  ami                         = data.aws_ami.nat[0].id
  instance_type               = var.nat_instance_type
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.nat[0].id]
  source_dest_check           = false
  associate_public_ip_address = true

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-nat-instance"
  })
}

################################################################################
# Route Tables
################################################################################

resource "aws_route_table" "public" {
  count = length(var.public_subnets) > 0 ? 1 : 0

  vpc_id = aws_vpc.this.id

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-public-rt"
  })
}

resource "aws_route" "public_internet" {
  count = length(var.public_subnets) > 0 ? 1 : 0

  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public" {
  count = length(var.public_subnets)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count = length(var.private_subnets) > 0 ? 1 : 0

  vpc_id = aws_vpc.this.id

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-private-rt"
  })
}

resource "aws_route" "private_nat_gateway" {
  count = var.enable_nat && var.nat_mode == "gateway" && length(var.private_subnets) > 0 ? 1 : 0

  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

resource "aws_route" "private_nat_instance" {
  count = var.enable_nat && var.nat_mode == "instance" && length(var.private_subnets) > 0 ? 1 : 0

  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat[0].primary_network_interface_id
}

resource "aws_route_table_association" "private" {
  count = length(var.private_subnets)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

################################################################################
# Transit Gateway Attachment
################################################################################

resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  count = var.transit_gateway_id != "" ? 1 : 0

  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.this.id
  subnet_ids         = aws_subnet.private[*].id

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-tgw-attachment"
  })
}

################################################################################
# VPC Flow Logs
################################################################################

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/aws/vpc/${var.tenant_name}/flow-logs"
  retention_in_days = var.flow_log_retention_days

  tags = local.vpc_tags
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.tenant_name}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = local.vpc_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "flow-logs-policy"
  role = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs[0].arn
  iam_role_arn             = aws_iam_role.flow_logs[0].arn
  max_aggregation_interval = 60

  tags = merge(local.vpc_tags, {
    Name = "${var.tenant_name}-vpc-flow-log"
  })
}
