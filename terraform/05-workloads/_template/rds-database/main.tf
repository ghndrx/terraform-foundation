################################################################################
# Workload: RDS Database
# 
# Deploys a managed database:
# - RDS PostgreSQL/MySQL instance or Aurora cluster
# - Subnet group and security group
# - Parameter group with optimized settings
# - Secrets Manager for credentials
# - Optional read replica
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<app>-db/
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
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }

  backend "s3" {
    key = "05-workloads/<TENANT>-<APP>-db/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  app    = "<APP>"
  env    = "prod" # prod, staging, dev
  name   = "${local.tenant}-${local.app}-${local.env}"

  # Engine - "postgres", "mysql", "aurora-postgresql", "aurora-mysql"
  engine         = "postgres"
  engine_version = "16.3"

  # Instance sizing
  instance_class = "db.t3.micro" # db.t3.micro, db.t3.small, db.r6g.large, etc.
  storage_gb     = 20
  max_storage_gb = 100 # Auto-scaling max (set to storage_gb to disable)

  # High availability
  multi_az       = false # true for prod
  read_replica   = false # Create read replica

  # Database config
  database_name = "app"
  port          = 5432 # 5432 for postgres, 3306 for mysql

  # Backup
  backup_retention_days = 7
  backup_window         = "03:00-04:00" # UTC
  maintenance_window    = "sun:04:00-sun:05:00"

  # Deletion protection (disable for dev/test)
  deletion_protection = local.env == "prod"
  skip_final_snapshot = local.env != "prod"

  # Performance Insights (free for 7 days retention)
  performance_insights = true

  # IAM database authentication (recommended for apps)
  iam_auth_enabled = true

  # Enhanced Monitoring interval (0 to disable, 1/5/10/15/30/60 seconds)
  monitoring_interval = local.env == "prod" ? 60 : 0

  # Is this an Aurora cluster?
  is_aurora = startswith(local.engine, "aurora-")
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
data "aws_region" "current" {}

################################################################################
# KMS Key for Encryption
################################################################################

resource "aws_kms_key" "db" {
  description             = "KMS key for ${local.name} database encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${local.name}-db" }
}

resource "aws_kms_alias" "db" {
  name          = "alias/${local.name}-db"
  target_key_id = aws_kms_key.db.key_id
}

################################################################################
# Random Password
################################################################################

resource "random_password" "master" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

################################################################################
# Secrets Manager
################################################################################

resource "aws_secretsmanager_secret" "db" {
  name                    = "${local.name}-db-credentials"
  description             = "Database credentials for ${local.name}"
  recovery_window_in_days = local.env == "prod" ? 30 : 0

  tags = { Name = "${local.name}-db-credentials" }
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = random_password.master.result
    engine   = local.engine
    host     = local.is_aurora ? aws_rds_cluster.main[0].endpoint : aws_db_instance.main[0].address
    port     = local.port
    database = local.database_name
    url      = local.is_aurora ? "postgresql://dbadmin:${random_password.master.result}@${aws_rds_cluster.main[0].endpoint}:${local.port}/${local.database_name}" : "postgresql://dbadmin:${random_password.master.result}@${aws_db_instance.main[0].address}:${local.port}/${local.database_name}"
  })

  depends_on = [aws_db_instance.main, aws_rds_cluster.main]
}

################################################################################
# Subnet Group
################################################################################

resource "aws_db_subnet_group" "main" {
  name        = local.name
  description = "Subnet group for ${local.name}"
  subnet_ids  = data.terraform_remote_state.network.outputs.private_subnet_ids

  tags = { Name = local.name }
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "Database ${local.name}"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  ingress {
    description     = "Database port from tenant"
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
  }

  tags = { Name = "${local.name}-db" }
}

################################################################################
# Parameter Group
################################################################################

resource "aws_db_parameter_group" "main" {
  count  = local.is_aurora ? 0 : 1
  name   = local.name
  family = "${local.engine}${split(".", local.engine_version)[0]}"

  dynamic "parameter" {
    for_each = local.engine == "postgres" ? [
      { name = "log_statement", value = "ddl" },
      { name = "log_min_duration_statement", value = "1000" },
      { name = "shared_preload_libraries", value = "pg_stat_statements", apply = "pending-reboot" }
    ] : [
      { name = "slow_query_log", value = "1" },
      { name = "long_query_time", value = "1" }
    ]
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = lookup(parameter.value, "apply", "immediate")
    }
  }

  tags = { Name = local.name }
}

resource "aws_rds_cluster_parameter_group" "main" {
  count  = local.is_aurora ? 1 : 0
  name   = local.name
  family = local.engine == "aurora-postgresql" ? "aurora-postgresql16" : "aurora-mysql8.0"

  dynamic "parameter" {
    for_each = local.engine == "aurora-postgresql" ? [
      { name = "log_statement", value = "ddl" },
      { name = "log_min_duration_statement", value = "1000" }
    ] : [
      { name = "slow_query_log", value = "1" },
      { name = "long_query_time", value = "1" }
    ]
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = lookup(parameter.value, "apply", "immediate")
    }
  }

  tags = { Name = local.name }
}

################################################################################
# RDS Instance (non-Aurora)
################################################################################

resource "aws_db_instance" "main" {
  count = local.is_aurora ? 0 : 1

  identifier = local.name
  
  engine         = local.engine
  engine_version = local.engine_version
  instance_class = local.instance_class

  allocated_storage     = local.storage_gb
  max_allocated_storage = local.max_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.db.arn

  db_name  = local.database_name
  username = "dbadmin"
  password = random_password.master.result
  port     = local.port

  multi_az               = local.multi_az
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.main[0].name
  publicly_accessible    = false

  # IAM authentication for better security
  iam_database_authentication_enabled = local.iam_auth_enabled

  backup_retention_period = local.backup_retention_days
  backup_window           = local.backup_window
  maintenance_window      = local.maintenance_window
  copy_tags_to_snapshot   = true

  performance_insights_enabled          = local.performance_insights
  performance_insights_retention_period = local.performance_insights ? 7 : null
  performance_insights_kms_key_id       = local.performance_insights ? aws_kms_key.db.arn : null

  # Enhanced monitoring
  monitoring_interval = local.monitoring_interval
  monitoring_role_arn = local.monitoring_interval > 0 ? aws_iam_role.rds_monitoring[0].arn : null

  deletion_protection      = local.deletion_protection
  skip_final_snapshot      = local.skip_final_snapshot
  final_snapshot_identifier = local.skip_final_snapshot ? null : "${local.name}-final"

  enabled_cloudwatch_logs_exports = local.engine == "postgres" ? ["postgresql", "upgrade"] : ["error", "slowquery"]

  # Require TLS connections
  ca_cert_identifier = "rds-ca-rsa2048-g1"

  tags = { Name = local.name }
}

################################################################################
# RDS Read Replica (non-Aurora)
################################################################################

resource "aws_db_instance" "replica" {
  count = !local.is_aurora && local.read_replica ? 1 : 0

  identifier          = "${local.name}-replica"
  replicate_source_db = aws_db_instance.main[0].identifier

  instance_class = local.instance_class
  
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.main[0].name
  publicly_accessible    = false

  performance_insights_enabled          = local.performance_insights
  performance_insights_retention_period = local.performance_insights ? 7 : null

  skip_final_snapshot = true

  tags = { Name = "${local.name}-replica" }
}

################################################################################
# Aurora Cluster
################################################################################

resource "aws_rds_cluster" "main" {
  count = local.is_aurora ? 1 : 0

  cluster_identifier = local.name

  engine         = local.engine
  engine_version = local.engine_version

  database_name   = local.database_name
  master_username = "dbadmin"
  master_password = random_password.master.result
  port            = local.port

  db_subnet_group_name            = aws_db_subnet_group.main.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.main[0].name

  storage_encrypted = true
  kms_key_id        = aws_kms_key.db.arn

  # IAM authentication
  iam_database_authentication_enabled = local.iam_auth_enabled

  backup_retention_period      = local.backup_retention_days
  preferred_backup_window      = local.backup_window
  preferred_maintenance_window = local.maintenance_window
  copy_tags_to_snapshot        = true

  deletion_protection       = local.deletion_protection
  skip_final_snapshot       = local.skip_final_snapshot
  final_snapshot_identifier = local.skip_final_snapshot ? null : "${local.name}-final"

  enabled_cloudwatch_logs_exports = local.engine == "aurora-postgresql" ? ["postgresql"] : ["error", "slowquery"]

  tags = { Name = local.name }
}

resource "aws_rds_cluster_instance" "main" {
  count = local.is_aurora ? (local.multi_az ? 2 : 1) : 0

  identifier         = "${local.name}-${count.index}"
  cluster_identifier = aws_rds_cluster.main[0].id

  engine         = aws_rds_cluster.main[0].engine
  engine_version = aws_rds_cluster.main[0].engine_version
  instance_class = local.instance_class

  publicly_accessible = false

  performance_insights_enabled          = local.performance_insights
  performance_insights_retention_period = local.performance_insights ? 7 : null

  tags = { Name = "${local.name}-${count.index}" }
}

################################################################################
# IAM Role for Enhanced Monitoring
################################################################################

resource "aws_iam_role" "rds_monitoring" {
  count = local.monitoring_interval > 0 ? 1 : 0
  name  = "${local.name}-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-rds-monitoring" }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  count      = local.monitoring_interval > 0 ? 1 : 0
  role       = aws_iam_role.rds_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

################################################################################
# CloudWatch Alarms
################################################################################

resource "aws_cloudwatch_metric_alarm" "cpu" {
  alarm_name          = "${local.name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Database CPU utilization high"

  dimensions = {
    DBInstanceIdentifier = local.is_aurora ? aws_rds_cluster_instance.main[0].identifier : aws_db_instance.main[0].identifier
  }

  tags = { Name = "${local.name}-cpu-high" }
}

resource "aws_cloudwatch_metric_alarm" "storage" {
  count = local.is_aurora ? 0 : 1

  alarm_name          = "${local.name}-storage-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 5368709120 # 5 GB
  alarm_description   = "Database free storage space low"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main[0].identifier
  }

  tags = { Name = "${local.name}-storage-low" }
}

resource "aws_cloudwatch_metric_alarm" "connections" {
  alarm_name          = "${local.name}-connections-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 50 # Adjust based on instance class
  alarm_description   = "Database connections high"

  dimensions = {
    DBInstanceIdentifier = local.is_aurora ? aws_rds_cluster_instance.main[0].identifier : aws_db_instance.main[0].identifier
  }

  tags = { Name = "${local.name}-connections-high" }
}

################################################################################
# Outputs
################################################################################

output "endpoint" {
  value = local.is_aurora ? aws_rds_cluster.main[0].endpoint : aws_db_instance.main[0].address
}

output "reader_endpoint" {
  value = local.is_aurora ? aws_rds_cluster.main[0].reader_endpoint : (local.read_replica ? aws_db_instance.replica[0].address : null)
}

output "port" {
  value = local.port
}

output "database_name" {
  value = local.database_name
}

output "secret_arn" {
  value = aws_secretsmanager_secret.db.arn
}

output "security_group_id" {
  value = aws_security_group.db.id
}

output "connection_string_ssm" {
  value       = "Retrieve from: aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.db.name}"
  description = "Command to retrieve connection string"
}
