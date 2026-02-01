################################################################################
# Workload: Aurora Serverless v2
# 
# Auto-scaling PostgreSQL/MySQL with:
# - Scale to zero (cost savings for dev)
# - Instant scaling (0.5 ACU increments)
# - Multi-AZ by default
# - IAM authentication
# - Data API (HTTP queries)
# - Secrets Manager integration
#
# Cost: ~$0.12/ACU-hour (scales 0.5-128 ACUs)
# Use cases: Variable workloads, dev/test, bursty traffic
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }

  backend "s3" {
    key = "05-workloads/<TENANT>-<NAME>-aurora/terraform.tfstate"
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
  
  cluster_name = "${local.tenant}-${local.name}-${local.env}"

  # Engine
  engine         = "aurora-postgresql"  # aurora-postgresql or aurora-mysql
  engine_version = "15.4"               # PostgreSQL 15.4 / MySQL 8.0
  
  # Serverless v2 capacity
  min_capacity = 0.5   # Minimum ACUs (0.5 = scale to near-zero)
  max_capacity = 16    # Maximum ACUs (adjust based on needs)
  
  # For true scale-to-zero (pauses after idle):
  # Note: Only available in some regions
  enable_pause = false
  pause_after_seconds = 300  # 5 minutes idle

  # Database
  database_name = replace(local.name, "-", "_")
  port          = local.engine == "aurora-postgresql" ? 5432 : 3306
  
  # Master credentials (stored in Secrets Manager)
  master_username = "admin"
  
  # Network (get from remote state or hardcode)
  vpc_id             = "" # data.terraform_remote_state.network.outputs.vpc_id
  private_subnet_ids = [] # data.terraform_remote_state.network.outputs.private_subnet_ids
  
  # Features
  enable_iam_auth      = true
  enable_data_api      = true   # HTTP Data API (for Lambda/serverless)
  enable_performance_insights = true
  performance_insights_retention = 7  # days (7 = free tier)

  # Backup
  backup_retention_period = 7
  preferred_backup_window = "03:00-04:00"
  
  # Maintenance
  preferred_maintenance_window = "sun:04:00-sun:05:00"
  auto_minor_version_upgrade   = true

  # Deletion protection (enable for production)
  deletion_protection = local.env == "prod"
  skip_final_snapshot = local.env != "prod"
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
# Random Password
################################################################################

resource "random_password" "master" {
  length  = 32
  special = false  # Aurora has special char restrictions
}

################################################################################
# Secrets Manager
################################################################################

resource "aws_secretsmanager_secret" "db" {
  name        = "${local.tenant}/${local.env}/${local.name}/aurora"
  description = "Aurora Serverless credentials for ${local.cluster_name}"

  tags = { Name = "${local.cluster_name}-credentials" }
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    username            = local.master_username
    password            = random_password.master.result
    engine              = local.engine
    host                = aws_rds_cluster.main.endpoint
    port                = local.port
    dbname              = local.database_name
    dbClusterIdentifier = aws_rds_cluster.main.id
  })
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "aurora" {
  count  = length(local.vpc_id) > 0 ? 1 : 0
  name   = "${local.cluster_name}-aurora"
  vpc_id = local.vpc_id

  ingress {
    description = "Database from VPC"
    from_port   = local.port
    to_port     = local.port
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Adjust to your VPC CIDR
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.cluster_name}-aurora" }
}

################################################################################
# DB Subnet Group
################################################################################

resource "aws_db_subnet_group" "main" {
  count      = length(local.private_subnet_ids) > 0 ? 1 : 0
  name       = local.cluster_name
  subnet_ids = local.private_subnet_ids

  tags = { Name = local.cluster_name }
}

################################################################################
# Aurora Serverless v2 Cluster
################################################################################

resource "aws_rds_cluster" "main" {
  cluster_identifier = local.cluster_name
  engine             = local.engine
  engine_mode        = "provisioned"  # Required for Serverless v2
  engine_version     = local.engine_version
  
  database_name   = local.database_name
  master_username = local.master_username
  master_password = random_password.master.result
  port            = local.port

  # Serverless v2 scaling
  serverlessv2_scaling_configuration {
    min_capacity = local.min_capacity
    max_capacity = local.max_capacity
  }

  # Network
  db_subnet_group_name   = length(aws_db_subnet_group.main) > 0 ? aws_db_subnet_group.main[0].name : null
  vpc_security_group_ids = length(aws_security_group.aurora) > 0 ? [aws_security_group.aurora[0].id] : []

  # Storage
  storage_encrypted = true
  kms_key_id        = null  # Uses AWS managed key

  # Features
  enable_http_endpoint            = local.enable_data_api
  iam_database_authentication_enabled = local.enable_iam_auth

  # Backup
  backup_retention_period      = local.backup_retention_period
  preferred_backup_window      = local.preferred_backup_window
  copy_tags_to_snapshot        = true
  skip_final_snapshot          = local.skip_final_snapshot
  final_snapshot_identifier    = local.skip_final_snapshot ? null : "${local.cluster_name}-final"

  # Maintenance
  preferred_maintenance_window = local.preferred_maintenance_window
  apply_immediately            = false

  # Protection
  deletion_protection = local.deletion_protection

  tags = { Name = local.cluster_name }

  lifecycle {
    ignore_changes = [
      master_password,  # Managed in Secrets Manager
    ]
  }
}

################################################################################
# Aurora Serverless v2 Instance
################################################################################

resource "aws_rds_cluster_instance" "main" {
  count = 1  # Add more for read replicas

  identifier         = "${local.cluster_name}-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.serverless"  # Required for Serverless v2
  engine             = local.engine
  engine_version     = local.engine_version

  # Performance Insights
  performance_insights_enabled          = local.enable_performance_insights
  performance_insights_retention_period = local.enable_performance_insights ? local.performance_insights_retention : null

  # Maintenance
  auto_minor_version_upgrade = local.auto_minor_version_upgrade

  tags = { Name = "${local.cluster_name}-${count.index + 1}" }
}

################################################################################
# IAM Role for IAM Authentication
################################################################################

resource "aws_iam_policy" "db_connect" {
  count       = local.enable_iam_auth ? 1 : 0
  name        = "${local.cluster_name}-db-connect"
  description = "IAM authentication to ${local.cluster_name}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowDBConnect"
        Effect = "Allow"
        Action = "rds-db:connect"
        Resource = "arn:aws:rds-db:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_rds_cluster.main.cluster_resource_id}/*"
      }
    ]
  })

  tags = { Name = "${local.cluster_name}-db-connect" }
}

################################################################################
# Data API Access Policy
################################################################################

resource "aws_iam_policy" "data_api" {
  count       = local.enable_data_api ? 1 : 0
  name        = "${local.cluster_name}-data-api"
  description = "Data API access to ${local.cluster_name}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ExecuteStatement"
        Effect = "Allow"
        Action = [
          "rds-data:ExecuteStatement",
          "rds-data:BatchExecuteStatement",
          "rds-data:BeginTransaction",
          "rds-data:CommitTransaction",
          "rds-data:RollbackTransaction"
        ]
        Resource = aws_rds_cluster.main.arn
      },
      {
        Sid    = "GetSecret"
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.db.arn
      }
    ]
  })

  tags = { Name = "${local.cluster_name}-data-api" }
}

################################################################################
# CloudWatch Alarms
################################################################################

resource "aws_cloudwatch_metric_alarm" "cpu" {
  alarm_name          = "${local.cluster_name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Aurora CPU > 80%"
  
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main.id
  }

  tags = { Name = "${local.cluster_name}-cpu-high" }
}

resource "aws_cloudwatch_metric_alarm" "connections" {
  alarm_name          = "${local.cluster_name}-connections-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 100
  alarm_description   = "Aurora connections > 100"
  
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main.id
  }

  tags = { Name = "${local.cluster_name}-connections-high" }
}

resource "aws_cloudwatch_metric_alarm" "capacity" {
  alarm_name          = "${local.cluster_name}-acu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "ServerlessDatabaseCapacity"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = local.max_capacity * 0.8
  alarm_description   = "Aurora ACU > 80% of max"
  
  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main.id
  }

  tags = { Name = "${local.cluster_name}-acu-high" }
}

################################################################################
# Outputs
################################################################################

output "cluster_endpoint" {
  value       = aws_rds_cluster.main.endpoint
  description = "Writer endpoint"
}

output "reader_endpoint" {
  value       = aws_rds_cluster.main.reader_endpoint
  description = "Reader endpoint"
}

output "cluster_arn" {
  value       = aws_rds_cluster.main.arn
  description = "Cluster ARN"
}

output "cluster_id" {
  value       = aws_rds_cluster.main.id
  description = "Cluster identifier"
}

output "port" {
  value       = local.port
  description = "Database port"
}

output "database_name" {
  value       = local.database_name
  description = "Database name"
}

output "secret_arn" {
  value       = aws_secretsmanager_secret.db.arn
  description = "Secrets Manager ARN"
}

output "iam_auth_policy_arn" {
  value       = length(aws_iam_policy.db_connect) > 0 ? aws_iam_policy.db_connect[0].arn : null
  description = "IAM policy for database authentication"
}

output "data_api_policy_arn" {
  value       = length(aws_iam_policy.data_api) > 0 ? aws_iam_policy.data_api[0].arn : null
  description = "IAM policy for Data API access"
}

output "connection_string" {
  value       = "${local.engine == "aurora-postgresql" ? "postgresql" : "mysql"}://${local.master_username}:****@${aws_rds_cluster.main.endpoint}:${local.port}/${local.database_name}"
  description = "Connection string template (password in Secrets Manager)"
  sensitive   = false
}

output "data_api_example" {
  value = local.enable_data_api ? <<-EOF
    aws rds-data execute-statement \
      --resource-arn '${aws_rds_cluster.main.arn}' \
      --secret-arn '${aws_secretsmanager_secret.db.arn}' \
      --database '${local.database_name}' \
      --sql 'SELECT NOW()'
  EOF
  : null
  description = "Data API example command"
}

output "cost_estimate" {
  value = {
    acu_hour       = "$0.12/ACU-hour"
    min_idle       = "$${local.min_capacity * 0.12 * 24 * 30}/month (${local.min_capacity} ACU 24/7)"
    storage        = "$0.10/GB-month"
    io             = "$0.20/million requests"
    data_api       = "$0.35/million Data API requests"
  }
  description = "Cost breakdown"
}
