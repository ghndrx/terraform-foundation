################################################################################
# Tenant Security Group Module
# Creates isolated security groups for tenant workloads in shared VPC
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
# Base Tenant Security Group
################################################################################

resource "aws_security_group" "tenant_base" {
  name        = "${var.tenant}-base-sg"
  description = "Base security group for tenant ${var.tenant}"
  vpc_id      = var.vpc_id

  # Allow all traffic within same tenant (same SG)
  ingress {
    description = "Allow intra-tenant traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  # Allow outbound internet
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.tenant}-base-sg"
    Tenant      = var.tenant
    Environment = var.environment
  }
}

################################################################################
# Web Tier Security Group
################################################################################

resource "aws_security_group" "tenant_web" {
  count = var.create_web_sg ? 1 : 0

  name        = "${var.tenant}-web-sg"
  description = "Web tier security group for tenant ${var.tenant}"
  vpc_id      = var.vpc_id

  # HTTPS from anywhere
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP from anywhere (redirect to HTTPS)
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow from tenant base SG
  ingress {
    description     = "Allow from tenant base"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.tenant_base.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.tenant}-web-sg"
    Tenant      = var.tenant
    Environment = var.environment
    Tier        = "web"
  }
}

################################################################################
# App Tier Security Group
################################################################################

resource "aws_security_group" "tenant_app" {
  count = var.create_app_sg ? 1 : 0

  name        = "${var.tenant}-app-sg"
  description = "App tier security group for tenant ${var.tenant}"
  vpc_id      = var.vpc_id

  # Allow from web tier
  ingress {
    description     = "Allow from web tier"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = var.create_web_sg ? [aws_security_group.tenant_web[0].id] : []
  }

  # Allow from tenant base SG
  ingress {
    description     = "Allow from tenant base"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.tenant_base.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.tenant}-app-sg"
    Tenant      = var.tenant
    Environment = var.environment
    Tier        = "app"
  }
}

################################################################################
# Database Tier Security Group
################################################################################

resource "aws_security_group" "tenant_db" {
  count = var.create_db_sg ? 1 : 0

  name        = "${var.tenant}-db-sg"
  description = "Database tier security group for tenant ${var.tenant}"
  vpc_id      = var.vpc_id

  # Allow from app tier only
  ingress {
    description     = "Allow from app tier"
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = var.create_app_sg ? [aws_security_group.tenant_app[0].id] : [aws_security_group.tenant_base.id]
  }

  # No direct outbound (DB shouldn't initiate connections)
  egress {
    description     = "Allow response to app tier"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = var.create_app_sg ? [aws_security_group.tenant_app[0].id] : [aws_security_group.tenant_base.id]
  }

  tags = {
    Name        = "${var.tenant}-db-sg"
    Tenant      = var.tenant
    Environment = var.environment
    Tier        = "database"
  }
}

################################################################################
# Outputs
################################################################################

output "base_sg_id" {
  value = aws_security_group.tenant_base.id
}

output "web_sg_id" {
  value = var.create_web_sg ? aws_security_group.tenant_web[0].id : null
}

output "app_sg_id" {
  value = var.create_app_sg ? aws_security_group.tenant_app[0].id : null
}

output "db_sg_id" {
  value = var.create_db_sg ? aws_security_group.tenant_db[0].id : null
}
