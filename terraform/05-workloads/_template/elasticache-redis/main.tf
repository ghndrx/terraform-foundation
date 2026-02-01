################################################################################
# Workload: ElastiCache Redis
# 
# Deploys a managed Redis cluster:
# - Redis cluster or replication group
# - Encryption at rest and in transit
# - Automatic failover (Multi-AZ)
# - CloudWatch alarms
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-cache/
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
    key = "05-workloads/<TENANT>-cache/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  app    = "cache"
  env    = "prod" # prod, staging, dev
  name   = "${local.tenant}-${local.app}-${local.env}"

  # Redis version
  engine_version = "7.1"
  
  # Node sizing
  # cache.t3.micro  - Dev/test ($0.017/hr)
  # cache.t3.small  - Small prod ($0.034/hr)
  # cache.r6g.large - Production ($0.158/hr)
  node_type = "cache.t3.micro"

  # Cluster configuration
  num_cache_clusters    = local.env == "prod" ? 2 : 1  # 2 for Multi-AZ
  automatic_failover    = local.env == "prod"
  multi_az_enabled      = local.env == "prod"

  # Memory management
  maxmemory_policy = "volatile-lru"  # Evict keys with TTL when memory full

  # Maintenance
  maintenance_window    = "sun:05:00-sun:06:00"
  snapshot_window       = "04:00-05:00"
  snapshot_retention    = local.env == "prod" ? 7 : 1

  # Port
  port = 6379
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
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "02-network/terraform.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "tenant" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "04-tenants/${local.tenant}/terraform.tfstate"
    region = var.region
  }
}

data "aws_caller_identity" "current" {}

################################################################################
# KMS Key
################################################################################

resource "aws_kms_key" "redis" {
  description             = "KMS key for ${local.name} Redis encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${local.name}-redis" }
}

resource "aws_kms_alias" "redis" {
  name          = "alias/${local.name}-redis"
  target_key_id = aws_kms_key.redis.key_id
}

################################################################################
# Subnet Group
################################################################################

resource "aws_elasticache_subnet_group" "main" {
  name        = local.name
  description = "Subnet group for ${local.name}"
  subnet_ids  = data.terraform_remote_state.network.outputs.private_subnet_ids

  tags = { Name = local.name }
}

################################################################################
# Parameter Group
################################################################################

resource "aws_elasticache_parameter_group" "main" {
  name        = local.name
  family      = "redis7"
  description = "Parameter group for ${local.name}"

  parameter {
    name  = "maxmemory-policy"
    value = local.maxmemory_policy
  }

  # Cluster mode disabled settings
  parameter {
    name  = "cluster-enabled"
    value = "no"
  }

  # Slow log for debugging
  parameter {
    name  = "slowlog-log-slower-than"
    value = "10000" # 10ms
  }

  parameter {
    name  = "slowlog-max-len"
    value = "128"
  }

  tags = { Name = local.name }
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "redis" {
  name        = "${local.name}-redis"
  description = "Redis cluster ${local.name}"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  ingress {
    description     = "Redis from tenant"
    from_port       = local.port
    to_port         = local.port
    protocol        = "tcp"
    security_groups = [data.terraform_remote_state.tenant.outputs.security_groups.base]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = { Name = "${local.name}-redis" }
}

################################################################################
# Replication Group (Redis Cluster)
################################################################################

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = local.name
  description          = "Redis cluster for ${local.name}"

  engine               = "redis"
  engine_version       = local.engine_version
  node_type            = local.node_type
  port                 = local.port
  parameter_group_name = aws_elasticache_parameter_group.main.name

  # Cluster configuration
  num_cache_clusters         = local.num_cache_clusters
  automatic_failover_enabled = local.automatic_failover
  multi_az_enabled           = local.multi_az_enabled

  # Network
  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  # Encryption
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.redis.arn
  transit_encryption_enabled = true
  auth_token                 = random_password.auth.result

  # Maintenance
  maintenance_window       = local.maintenance_window
  snapshot_window          = local.snapshot_window
  snapshot_retention_limit = local.snapshot_retention
  auto_minor_version_upgrade = true

  # Notifications
  notification_topic_arn = aws_sns_topic.redis.arn

  # Apply changes immediately in non-prod, during maintenance in prod
  apply_immediately = local.env != "prod"

  tags = { 
    Name   = local.name
    Backup = "true"
  }
}

################################################################################
# Auth Token (Password)
################################################################################

resource "random_password" "auth" {
  length  = 64
  special = false # Redis auth token doesn't support all special chars
}

resource "aws_secretsmanager_secret" "redis" {
  name                    = "${local.name}-redis-auth"
  description             = "Redis auth token for ${local.name}"
  recovery_window_in_days = local.env == "prod" ? 30 : 0

  tags = { Name = "${local.name}-redis-auth" }
}

resource "aws_secretsmanager_secret_version" "redis" {
  secret_id = aws_secretsmanager_secret.redis.id
  secret_string = jsonencode({
    auth_token = random_password.auth.result
    host       = aws_elasticache_replication_group.main.primary_endpoint_address
    port       = local.port
    url        = "rediss://:${random_password.auth.result}@${aws_elasticache_replication_group.main.primary_endpoint_address}:${local.port}"
  })
}

################################################################################
# SNS Topic for Notifications
################################################################################

resource "aws_sns_topic" "redis" {
  name = "${local.name}-redis-events"
  
  tags = { Name = "${local.name}-redis-events" }
}

################################################################################
# CloudWatch Alarms
################################################################################

resource "aws_cloudwatch_metric_alarm" "cpu" {
  alarm_name          = "${local.name}-redis-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 75
  alarm_description   = "Redis CPU utilization high"

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }

  alarm_actions = [aws_sns_topic.redis.arn]

  tags = { Name = "${local.name}-redis-cpu" }
}

resource "aws_cloudwatch_metric_alarm" "memory" {
  alarm_name          = "${local.name}-redis-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Redis memory usage high"

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }

  alarm_actions = [aws_sns_topic.redis.arn]

  tags = { Name = "${local.name}-redis-memory" }
}

resource "aws_cloudwatch_metric_alarm" "connections" {
  alarm_name          = "${local.name}-redis-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CurrConnections"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 1000
  alarm_description   = "Redis connections high"

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }

  alarm_actions = [aws_sns_topic.redis.arn]

  tags = { Name = "${local.name}-redis-connections" }
}

################################################################################
# Outputs
################################################################################

output "primary_endpoint" {
  value = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "reader_endpoint" {
  value = aws_elasticache_replication_group.main.reader_endpoint_address
}

output "port" {
  value = local.port
}

output "secret_arn" {
  value = aws_secretsmanager_secret.redis.arn
}

output "security_group_id" {
  value = aws_security_group.redis.id
}

output "connection_command" {
  value       = "redis-cli -h ${aws_elasticache_replication_group.main.primary_endpoint_address} -p ${local.port} --tls --askpass"
  description = "Command to connect (retrieve password from Secrets Manager)"
}
