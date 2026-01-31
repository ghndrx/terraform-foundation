################################################################################
# Workload: OpenSearch (Elasticsearch)
# 
# Search and analytics with:
# - Serverless or provisioned clusters
# - Fine-grained access control
# - VPC or public access
# - Cognito authentication
# - UltraWarm for cost-effective storage
# - Cross-cluster search
#
# Use cases: Log analytics, full-text search, observability
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
    key = "05-workloads/<TENANT>-<NAME>-opensearch/terraform.tfstate"
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
  
  domain_name = "${local.tenant}-${local.name}-${local.env}"

  # Engine
  engine_version = "OpenSearch_2.11"

  # Cluster sizing
  cluster = {
    # Data nodes
    instance_type  = "t3.medium.search"  # t3.small.search for dev
    instance_count = 2

    # Dedicated master nodes (recommended for production)
    dedicated_master_enabled = local.env == "prod"
    dedicated_master_type    = "t3.medium.search"
    dedicated_master_count   = 3

    # Multi-AZ
    zone_awareness_enabled = local.env == "prod"
    availability_zone_count = local.env == "prod" ? 2 : 1
  }

  # Storage
  storage = {
    type        = "gp3"
    size_gb     = 100
    iops        = 3000
    throughput  = 125
  }

  # UltraWarm (cost-effective warm storage)
  ultrawarm = {
    enabled = false
    type    = "ultrawarm1.medium.search"
    count   = 2
  }

  # Network
  # Option 1: VPC (private, more secure)
  vpc_enabled        = true
  vpc_id             = "" # data.terraform_remote_state.network.outputs.vpc_id
  private_subnet_ids = [] # data.terraform_remote_state.network.outputs.private_subnet_ids

  # Option 2: Public (set vpc_enabled = false)
  # Uses IP-based access policy

  # Access control
  enable_fine_grained_access = true
  master_user_name           = "admin"

  # Cognito authentication (optional, for Dashboards)
  cognito = {
    enabled          = false
    user_pool_id     = ""
    identity_pool_id = ""
    role_arn         = ""
  }

  # Encryption
  encrypt_at_rest    = true
  node_to_node_encryption = true

  # Logging
  log_types = ["INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS", "ES_APPLICATION_LOGS"]

  # Auto-tune
  auto_tune_enabled = true
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
# Random Password for Master User
################################################################################

resource "random_password" "master" {
  count   = local.enable_fine_grained_access ? 1 : 0
  length  = 24
  special = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

################################################################################
# Secrets Manager
################################################################################

resource "aws_secretsmanager_secret" "opensearch" {
  count       = local.enable_fine_grained_access ? 1 : 0
  name        = "${local.tenant}/${local.env}/${local.name}/opensearch"
  description = "OpenSearch master credentials"

  tags = { Name = "${local.domain_name}-credentials" }
}

resource "aws_secretsmanager_secret_version" "opensearch" {
  count     = local.enable_fine_grained_access ? 1 : 0
  secret_id = aws_secretsmanager_secret.opensearch[0].id
  secret_string = jsonencode({
    username = local.master_user_name
    password = random_password.master[0].result
    endpoint = aws_opensearch_domain.main.endpoint
  })
}

################################################################################
# CloudWatch Log Groups
################################################################################

resource "aws_cloudwatch_log_group" "opensearch" {
  for_each          = toset(local.log_types)
  name              = "/aws/opensearch/${local.domain_name}/${lower(each.key)}"
  retention_in_days = 30

  tags = { Name = "${local.domain_name}-${lower(each.key)}" }
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${local.domain_name}-logs"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "es.amazonaws.com"
      }
      Action = [
        "logs:PutLogEvents",
        "logs:CreateLogStream"
      ]
      Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/opensearch/${local.domain_name}/*"
    }]
  })
}

################################################################################
# Security Group (VPC mode)
################################################################################

resource "aws_security_group" "opensearch" {
  count  = local.vpc_enabled && length(local.vpc_id) > 0 ? 1 : 0
  name   = "${local.domain_name}-opensearch"
  vpc_id = local.vpc_id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.domain_name}-opensearch" }
}

################################################################################
# IAM Service-Linked Role
################################################################################

resource "aws_iam_service_linked_role" "opensearch" {
  count            = local.vpc_enabled ? 1 : 0
  aws_service_name = "opensearchservice.amazonaws.com"
}

################################################################################
# OpenSearch Domain
################################################################################

resource "aws_opensearch_domain" "main" {
  domain_name    = local.domain_name
  engine_version = local.engine_version

  # Cluster configuration
  cluster_config {
    instance_type  = local.cluster.instance_type
    instance_count = local.cluster.instance_count

    dedicated_master_enabled = local.cluster.dedicated_master_enabled
    dedicated_master_type    = local.cluster.dedicated_master_enabled ? local.cluster.dedicated_master_type : null
    dedicated_master_count   = local.cluster.dedicated_master_enabled ? local.cluster.dedicated_master_count : null

    zone_awareness_enabled = local.cluster.zone_awareness_enabled
    
    dynamic "zone_awareness_config" {
      for_each = local.cluster.zone_awareness_enabled ? [1] : []
      content {
        availability_zone_count = local.cluster.availability_zone_count
      }
    }

    # UltraWarm
    warm_enabled = local.ultrawarm.enabled
    warm_type    = local.ultrawarm.enabled ? local.ultrawarm.type : null
    warm_count   = local.ultrawarm.enabled ? local.ultrawarm.count : null
  }

  # Storage
  ebs_options {
    ebs_enabled = true
    volume_type = local.storage.type
    volume_size = local.storage.size_gb
    iops        = local.storage.type == "gp3" ? local.storage.iops : null
    throughput  = local.storage.type == "gp3" ? local.storage.throughput : null
  }

  # VPC configuration
  dynamic "vpc_options" {
    for_each = local.vpc_enabled && length(local.private_subnet_ids) > 0 ? [1] : []
    content {
      subnet_ids         = slice(local.private_subnet_ids, 0, local.cluster.availability_zone_count)
      security_group_ids = [aws_security_group.opensearch[0].id]
    }
  }

  # Encryption
  encrypt_at_rest {
    enabled = local.encrypt_at_rest
  }

  node_to_node_encryption {
    enabled = local.node_to_node_encryption
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  # Fine-grained access control
  advanced_security_options {
    enabled                        = local.enable_fine_grained_access
    internal_user_database_enabled = local.enable_fine_grained_access
    
    dynamic "master_user_options" {
      for_each = local.enable_fine_grained_access ? [1] : []
      content {
        master_user_name     = local.master_user_name
        master_user_password = random_password.master[0].result
      }
    }
  }

  # Cognito authentication
  dynamic "cognito_options" {
    for_each = local.cognito.enabled ? [1] : []
    content {
      enabled          = true
      user_pool_id     = local.cognito.user_pool_id
      identity_pool_id = local.cognito.identity_pool_id
      role_arn         = local.cognito.role_arn
    }
  }

  # Logging
  dynamic "log_publishing_options" {
    for_each = local.log_types
    content {
      cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch[log_publishing_options.value].arn
      log_type                 = log_publishing_options.value
    }
  }

  # Auto-tune
  auto_tune_options {
    desired_state       = local.auto_tune_enabled ? "ENABLED" : "DISABLED"
    rollback_on_disable = "NO_ROLLBACK"
  }

  # Access policy (for non-VPC or fine-grained access)
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "es:*"
        Resource = "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${local.domain_name}/*"
        Condition = local.vpc_enabled ? {} : {
          IpAddress = {
            "aws:SourceIp" = ["0.0.0.0/0"]  # Restrict in production!
          }
        }
      }
    ]
  })

  tags = { Name = local.domain_name }

  depends_on = [
    aws_iam_service_linked_role.opensearch,
    aws_cloudwatch_log_resource_policy.opensearch
  ]
}

################################################################################
# IAM Policy for Application Access
################################################################################

resource "aws_iam_policy" "opensearch_access" {
  name        = "${local.domain_name}-access"
  description = "Access to ${local.domain_name} OpenSearch domain"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OpenSearchAccess"
        Effect = "Allow"
        Action = [
          "es:ESHttpGet",
          "es:ESHttpHead",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpDelete"
        ]
        Resource = "${aws_opensearch_domain.main.arn}/*"
      }
    ]
  })

  tags = { Name = "${local.domain_name}-access" }
}

################################################################################
# Outputs
################################################################################

output "domain_endpoint" {
  value       = aws_opensearch_domain.main.endpoint
  description = "OpenSearch domain endpoint"
}

output "dashboard_endpoint" {
  value       = aws_opensearch_domain.main.dashboard_endpoint
  description = "OpenSearch Dashboards endpoint"
}

output "domain_arn" {
  value       = aws_opensearch_domain.main.arn
  description = "Domain ARN"
}

output "domain_id" {
  value       = aws_opensearch_domain.main.domain_id
  description = "Domain ID"
}

output "secret_arn" {
  value       = length(aws_secretsmanager_secret.opensearch) > 0 ? aws_secretsmanager_secret.opensearch[0].arn : null
  description = "Secrets Manager ARN for credentials"
}

output "access_policy_arn" {
  value       = aws_iam_policy.opensearch_access.arn
  description = "IAM policy for application access"
}

output "kibana_url" {
  value       = "https://${aws_opensearch_domain.main.dashboard_endpoint}/_dashboards"
  description = "OpenSearch Dashboards URL"
}

output "curl_example" {
  value       = local.enable_fine_grained_access ? <<-EOF
    # Get credentials from Secrets Manager
    SECRET=$(aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.opensearch[0].arn} --query SecretString --output text)
    USER=$(echo $SECRET | jq -r .username)
    PASS=$(echo $SECRET | jq -r .password)
    
    # Query cluster health
    curl -u "$USER:$PASS" "https://${aws_opensearch_domain.main.endpoint}/_cluster/health?pretty"
  EOF
  : null
  description = "Example curl commands"
}
