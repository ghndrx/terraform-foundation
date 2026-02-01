################################################################################
# Shared VPC Module
# Single VPC shared across all tenants via AWS RAM
# Isolation via: Security Groups, ABAC (tags), optional subnet segmentation
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

################################################################################
# VPC
################################################################################

resource "aws_vpc" "shared" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "shared-vpc"
    Environment = "shared"
    ManagedBy   = "terraform"
  }
}

################################################################################
# Internet Gateway
################################################################################

resource "aws_internet_gateway" "shared" {
  vpc_id = aws_vpc.shared.id

  tags = {
    Name = "shared-igw"
  }
}

################################################################################
# NAT Gateway (Single for cost savings)
################################################################################

resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "shared-nat-eip"
  }
}

resource "aws_nat_gateway" "shared" {
  count = var.enable_nat_gateway ? 1 : 0

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "shared-nat"
  }

  depends_on = [aws_internet_gateway.shared]
}

################################################################################
# Subnets - Public (shared)
################################################################################

resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.shared.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "shared-public-${var.availability_zones[count.index]}"
    Type        = "public"
    Environment = "shared"
  }
}

################################################################################
# Subnets - Private (shared across tenants)
################################################################################

resource "aws_subnet" "private_shared" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.shared.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + length(var.availability_zones))
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "shared-private-${var.availability_zones[count.index]}"
    Type        = "private"
    Environment = "shared"
  }
}

################################################################################
# Subnets - Per-Tenant Private (optional, for stricter isolation)
################################################################################

resource "aws_subnet" "private_tenant" {
  for_each = var.create_tenant_subnets ? {
    for combo in setproduct(var.tenants, range(length(var.availability_zones))) :
    "${combo[0]}-${combo[1]}" => {
      tenant = combo[0]
      az_idx = combo[1]
    }
  } : {}

  vpc_id            = aws_vpc.shared.id
  cidr_block        = cidrsubnet(var.tenant_subnet_cidr, 4, index(var.tenants, each.value.tenant) * length(var.availability_zones) + each.value.az_idx)
  availability_zone = var.availability_zones[each.value.az_idx]

  tags = {
    Name        = "tenant-${each.value.tenant}-private-${var.availability_zones[each.value.az_idx]}"
    Type        = "private"
    Tenant      = each.value.tenant
    Environment = "shared"
  }
}

################################################################################
# Route Tables
################################################################################

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.shared.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.shared.id
  }

  tags = {
    Name = "shared-public-rt"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.shared.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.shared[0].id
    }
  }

  tags = {
    Name = "shared-private-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_shared" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.private_shared[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_tenant" {
  for_each = aws_subnet.private_tenant

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

################################################################################
# AWS RAM - Share VPC Subnets with Organization
################################################################################

resource "aws_ram_resource_share" "vpc_subnets" {
  name                      = "shared-vpc-subnets"
  allow_external_principals = false

  tags = {
    Name = "Shared VPC Subnets"
  }
}

# Share private subnets with the organization
resource "aws_ram_resource_association" "private_shared" {
  count = length(var.availability_zones)

  resource_arn       = aws_subnet.private_shared[count.index].arn
  resource_share_arn = aws_ram_resource_share.vpc_subnets.arn
}

# Share tenant-specific subnets (if created)
resource "aws_ram_resource_association" "private_tenant" {
  for_each = aws_subnet.private_tenant

  resource_arn       = each.value.arn
  resource_share_arn = aws_ram_resource_share.vpc_subnets.arn
}

# Share with specific OUs or entire org
resource "aws_ram_principal_association" "workloads_ou" {
  principal          = var.workloads_ou_arn
  resource_share_arn = aws_ram_resource_share.vpc_subnets.arn
}

################################################################################
# Default Security Group - Deny All (force explicit SGs)
################################################################################

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.shared.id

  # No ingress or egress rules = deny all
  tags = {
    Name        = "default-deny-all"
    Description = "Default SG - no access, use tenant-specific SGs"
  }
}

################################################################################
# Outputs
################################################################################

output "vpc_id" {
  value = aws_vpc.shared.id
}

output "vpc_cidr" {
  value = aws_vpc.shared.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_shared_subnet_ids" {
  value = aws_subnet.private_shared[*].id
}

output "private_tenant_subnet_ids" {
  value = {
    for k, v in aws_subnet.private_tenant : k => v.id
  }
}

output "nat_gateway_ip" {
  value = var.enable_nat_gateway ? aws_eip.nat[0].public_ip : null
}

output "ram_share_arn" {
  value = aws_ram_resource_share.vpc_subnets.arn
}
