################################################################################
# Workload: ECR Repository
# 
# Container registry with:
# - Image scanning on push
# - Lifecycle policies (cleanup old images)
# - Cross-account access
# - Replication to other regions
# - Immutable tags (optional)
#
# Use cases: Docker images, Lambda container images
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
    key = "05-workloads/<TENANT>-<NAME>-ecr/terraform.tfstate"
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
  
  # Multiple repositories can be created
  repositories = {
    api = {
      description = "API service container"
    }
    worker = {
      description = "Background worker container"
    }
    # Add more as needed
  }

  # Image scanning
  scan_on_push = true

  # Tag immutability (prevents overwriting tags)
  image_tag_mutability = "MUTABLE" # MUTABLE or IMMUTABLE

  # Encryption
  encryption_type = "AES256" # AES256 or KMS
  kms_key_arn     = null     # Set if using KMS

  # Lifecycle policy - cleanup old images
  lifecycle_policy = {
    # Keep last N tagged images
    keep_tagged_count = 30
    
    # Delete untagged images older than N days
    untagged_expiry_days = 7
    
    # Keep images with these tag prefixes forever
    keep_tag_prefixes = ["release-", "v"]
  }

  # Cross-account access (account IDs that can pull)
  pull_access_accounts = [
    # "123456789012",  # Dev account
    # "234567890123",  # Staging account
  ]

  # Cross-account push access
  push_access_accounts = [
    # "345678901234",  # CI/CD account
  ]

  # IAM principals with pull access
  pull_access_principals = [
    # "arn:aws:iam::123456789012:role/ecs-task-role",
  ]

  # Replication to other regions
  replication_regions = [
    # "us-west-2",
    # "eu-west-1",
  ]
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
# ECR Repositories
################################################################################

resource "aws_ecr_repository" "repos" {
  for_each = local.repositories

  name                 = "${local.tenant}/${local.name}/${each.key}"
  image_tag_mutability = local.image_tag_mutability

  image_scanning_configuration {
    scan_on_push = local.scan_on_push
  }

  encryption_configuration {
    encryption_type = local.encryption_type
    kms_key         = local.kms_key_arn
  }

  tags = { 
    Name        = "${local.tenant}/${local.name}/${each.key}"
    Description = each.value.description
  }
}

################################################################################
# Lifecycle Policies
################################################################################

resource "aws_ecr_lifecycle_policy" "repos" {
  for_each   = local.repositories
  repository = aws_ecr_repository.repos[each.key].name

  policy = jsonencode({
    rules = [
      # Keep tagged images with specific prefixes
      {
        rulePriority = 1
        description  = "Keep release images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = local.lifecycle_policy.keep_tag_prefixes
          countType     = "imageCountMoreThan"
          countNumber   = 9999
        }
        action = {
          type = "expire"
        }
      },
      # Keep last N tagged images
      {
        rulePriority = 10
        description  = "Keep last ${local.lifecycle_policy.keep_tagged_count} tagged images"
        selection = {
          tagStatus   = "tagged"
          tagPrefixList = [""]
          countType   = "imageCountMoreThan"
          countNumber = local.lifecycle_policy.keep_tagged_count
        }
        action = {
          type = "expire"
        }
      },
      # Delete old untagged images
      {
        rulePriority = 20
        description  = "Delete untagged images older than ${local.lifecycle_policy.untagged_expiry_days} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = local.lifecycle_policy.untagged_expiry_days
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

################################################################################
# Repository Policies (Cross-Account Access)
################################################################################

resource "aws_ecr_repository_policy" "repos" {
  for_each   = length(local.pull_access_accounts) > 0 || length(local.push_access_accounts) > 0 || length(local.pull_access_principals) > 0 ? local.repositories : {}
  repository = aws_ecr_repository.repos[each.key].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Cross-account pull access
      length(local.pull_access_accounts) > 0 ? [{
        Sid    = "CrossAccountPull"
        Effect = "Allow"
        Principal = {
          AWS = [for acct in local.pull_access_accounts : "arn:aws:iam::${acct}:root"]
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }] : [],
      
      # Cross-account push access
      length(local.push_access_accounts) > 0 ? [{
        Sid    = "CrossAccountPush"
        Effect = "Allow"
        Principal = {
          AWS = [for acct in local.push_access_accounts : "arn:aws:iam::${acct}:root"]
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
      }] : [],
      
      # Principal-based pull access
      length(local.pull_access_principals) > 0 ? [{
        Sid    = "PrincipalPull"
        Effect = "Allow"
        Principal = {
          AWS = local.pull_access_principals
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }] : []
    )
  })
}

################################################################################
# Replication Configuration
################################################################################

resource "aws_ecr_replication_configuration" "main" {
  count = length(local.replication_regions) > 0 ? 1 : 0

  replication_configuration {
    rule {
      dynamic "destination" {
        for_each = local.replication_regions
        content {
          region      = destination.value
          registry_id = data.aws_caller_identity.current.account_id
        }
      }

      repository_filter {
        filter      = "${local.tenant}/${local.name}/"
        filter_type = "PREFIX_MATCH"
      }
    }
  }
}

################################################################################
# IAM Policy for CI/CD
################################################################################

resource "aws_iam_policy" "push" {
  name        = "${local.tenant}-${local.name}-ecr-push"
  description = "Push access to ${local.tenant}/${local.name} ECR repositories"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetAuthToken"
        Effect = "Allow"
        Action = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "PushImages"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = [for repo in aws_ecr_repository.repos : repo.arn]
      }
    ]
  })

  tags = { Name = "${local.tenant}-${local.name}-ecr-push" }
}

resource "aws_iam_policy" "pull" {
  name        = "${local.tenant}-${local.name}-ecr-pull"
  description = "Pull access to ${local.tenant}/${local.name} ECR repositories"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetAuthToken"
        Effect = "Allow"
        Action = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "PullImages"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = [for repo in aws_ecr_repository.repos : repo.arn]
      }
    ]
  })

  tags = { Name = "${local.tenant}-${local.name}-ecr-pull" }
}

################################################################################
# Outputs
################################################################################

output "repository_urls" {
  value       = { for k, v in aws_ecr_repository.repos : k => v.repository_url }
  description = "Repository URLs for docker push/pull"
}

output "repository_arns" {
  value       = { for k, v in aws_ecr_repository.repos : k => v.arn }
  description = "Repository ARNs"
}

output "push_policy_arn" {
  value       = aws_iam_policy.push.arn
  description = "IAM policy ARN for push access"
}

output "pull_policy_arn" {
  value       = aws_iam_policy.pull.arn
  description = "IAM policy ARN for pull access"
}

output "docker_login_command" {
  value       = "aws ecr get-login-password --region ${data.aws_region.current.name} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com"
  description = "Command to authenticate Docker with ECR"
}

output "push_commands" {
  value = { for k, v in aws_ecr_repository.repos : k => <<-EOF
    docker build -t ${v.repository_url}:latest .
    docker push ${v.repository_url}:latest
  EOF
  }
  description = "Docker build and push commands for each repository"
}
