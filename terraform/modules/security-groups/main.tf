################################################################################
# Security Groups Module
#
# Creates common security group patterns for multi-tier architectures:
# - Web tier (HTTP/HTTPS from ALB or internet)
# - App tier (from web tier only)
# - Database tier (from app tier only)
# - Bastion host (SSH from allowed CIDRs)
# - VPC endpoints (HTTPS from VPC)
# - EKS patterns (cluster, nodes)
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

data "aws_vpc" "selected" {
  id = var.vpc_id
}

locals {
  vpc_cidr = data.aws_vpc.selected.cidr_block
}

################################################################################
# Web Tier Security Group
################################################################################

resource "aws_security_group" "web" {
  count = var.create_web_tier ? 1 : 0

  name_prefix = "${var.name_prefix}-web-"
  description = "Web tier - HTTP/HTTPS access"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-web"
    Tier = "web"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "web_http" {
  count = var.create_web_tier ? 1 : 0

  security_group_id = aws_security_group.web[0].id
  description       = "HTTP from allowed sources"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = var.web_ingress_cidr

  tags = { Name = "http-ingress" }
}

resource "aws_vpc_security_group_ingress_rule" "web_https" {
  count = var.create_web_tier ? 1 : 0

  security_group_id = aws_security_group.web[0].id
  description       = "HTTPS from allowed sources"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = var.web_ingress_cidr

  tags = { Name = "https-ingress" }
}

resource "aws_vpc_security_group_egress_rule" "web_all" {
  count = var.create_web_tier ? 1 : 0

  security_group_id = aws_security_group.web[0].id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = { Name = "all-egress" }
}

################################################################################
# App Tier Security Group
################################################################################

resource "aws_security_group" "app" {
  count = var.create_app_tier ? 1 : 0

  name_prefix = "${var.name_prefix}-app-"
  description = "App tier - access from web tier"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-app"
    Tier = "app"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_from_web" {
  count = var.create_app_tier && var.create_web_tier ? 1 : 0

  security_group_id            = aws_security_group.app[0].id
  description                  = "App port from web tier"
  from_port                    = var.app_port
  to_port                      = var.app_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.web[0].id

  tags = { Name = "from-web-tier" }
}

resource "aws_vpc_security_group_ingress_rule" "app_from_cidr" {
  count = var.create_app_tier && !var.create_web_tier ? 1 : 0

  security_group_id = aws_security_group.app[0].id
  description       = "App port from VPC"
  from_port         = var.app_port
  to_port           = var.app_port
  ip_protocol       = "tcp"
  cidr_ipv4         = local.vpc_cidr

  tags = { Name = "from-vpc" }
}

resource "aws_vpc_security_group_egress_rule" "app_all" {
  count = var.create_app_tier ? 1 : 0

  security_group_id = aws_security_group.app[0].id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = { Name = "all-egress" }
}

################################################################################
# Database Tier Security Group
################################################################################

resource "aws_security_group" "db" {
  count = var.create_db_tier ? 1 : 0

  name_prefix = "${var.name_prefix}-db-"
  description = "Database tier - access from app tier"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-db"
    Tier = "database"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  count = var.create_db_tier && var.create_app_tier ? 1 : 0

  security_group_id            = aws_security_group.db[0].id
  description                  = "Database port from app tier"
  from_port                    = var.db_port
  to_port                      = var.db_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.app[0].id

  tags = { Name = "from-app-tier" }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_cidr" {
  count = var.create_db_tier && !var.create_app_tier ? 1 : 0

  security_group_id = aws_security_group.db[0].id
  description       = "Database port from VPC"
  from_port         = var.db_port
  to_port           = var.db_port
  ip_protocol       = "tcp"
  cidr_ipv4         = local.vpc_cidr

  tags = { Name = "from-vpc" }
}

resource "aws_vpc_security_group_egress_rule" "db_all" {
  count = var.create_db_tier ? 1 : 0

  security_group_id = aws_security_group.db[0].id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = { Name = "all-egress" }
}

################################################################################
# Bastion Security Group
################################################################################

resource "aws_security_group" "bastion" {
  count = var.create_bastion ? 1 : 0

  name_prefix = "${var.name_prefix}-bastion-"
  description = "Bastion host - SSH from allowed CIDRs"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-bastion"
    Tier = "bastion"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "bastion_ssh" {
  for_each = var.create_bastion ? toset(var.allowed_ssh_cidrs) : []

  security_group_id = aws_security_group.bastion[0].id
  description       = "SSH from ${each.value}"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value

  tags = { Name = "ssh-from-${replace(each.value, "/", "-")}" }
}

resource "aws_vpc_security_group_egress_rule" "bastion_all" {
  count = var.create_bastion ? 1 : 0

  security_group_id = aws_security_group.bastion[0].id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = { Name = "all-egress" }
}

################################################################################
# VPC Endpoints Security Group
################################################################################

resource "aws_security_group" "endpoints" {
  count = var.create_endpoints ? 1 : 0

  name_prefix = "${var.name_prefix}-endpoints-"
  description = "VPC Endpoints - HTTPS from VPC"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-endpoints"
    Tier = "endpoints"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  count = var.create_endpoints ? 1 : 0

  security_group_id = aws_security_group.endpoints[0].id
  description       = "HTTPS from VPC"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = local.vpc_cidr

  tags = { Name = "https-from-vpc" }
}

resource "aws_vpc_security_group_egress_rule" "endpoints_all" {
  count = var.create_endpoints ? 1 : 0

  security_group_id = aws_security_group.endpoints[0].id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = { Name = "all-egress" }
}

################################################################################
# EKS Cluster Security Group
################################################################################

resource "aws_security_group" "eks_cluster" {
  count = var.create_eks ? 1 : 0

  name_prefix = "${var.name_prefix}-eks-cluster-"
  description = "EKS cluster control plane"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-eks-cluster"
    Tier = "eks"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "eks_cluster_https" {
  count = var.create_eks ? 1 : 0

  security_group_id = aws_security_group.eks_cluster[0].id
  description       = "HTTPS from VPC (kubectl)"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = local.vpc_cidr

  tags = { Name = "https-from-vpc" }
}

resource "aws_vpc_security_group_egress_rule" "eks_cluster_all" {
  count = var.create_eks ? 1 : 0

  security_group_id = aws_security_group.eks_cluster[0].id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = { Name = "all-egress" }
}

################################################################################
# EKS Nodes Security Group
################################################################################

resource "aws_security_group" "eks_nodes" {
  count = var.create_eks ? 1 : 0

  name_prefix = "${var.name_prefix}-eks-nodes-"
  description = "EKS worker nodes"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name                                        = "${var.name_prefix}-eks-nodes"
    Tier                                        = "eks"
    "kubernetes.io/cluster/${var.name_prefix}" = "owned"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "eks_nodes_self" {
  count = var.create_eks ? 1 : 0

  security_group_id            = aws_security_group.eks_nodes[0].id
  description                  = "Node to node communication"
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.eks_nodes[0].id

  tags = { Name = "node-to-node" }
}

resource "aws_vpc_security_group_ingress_rule" "eks_nodes_cluster" {
  count = var.create_eks ? 1 : 0

  security_group_id            = aws_security_group.eks_nodes[0].id
  description                  = "From cluster control plane"
  from_port                    = 1025
  to_port                      = 65535
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.eks_cluster[0].id

  tags = { Name = "from-cluster" }
}

resource "aws_vpc_security_group_egress_rule" "eks_nodes_all" {
  count = var.create_eks ? 1 : 0

  security_group_id = aws_security_group.eks_nodes[0].id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = { Name = "all-egress" }
}
