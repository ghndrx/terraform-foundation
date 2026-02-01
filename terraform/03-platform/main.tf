################################################################################
# Layer 03: Platform
# 
# Shared platform services for all tenants:
# - ECR repositories for container images
# - CodePipeline/CodeBuild for CI/CD
# - Secrets Manager baseline
# - SSM Parameter Store hierarchy
#
# Depends on: 00-bootstrap, 02-network
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
    key = "03-platform/terraform.tfstate"
  }
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

variable "project_name" {
  type        = string
  description = "Project name for resource naming"
}

variable "enable_cicd" {
  type        = bool
  default     = true
  description = "Enable CI/CD resources (CodeBuild, S3 artifacts)"
}

variable "ecr_repos" {
  type        = list(string)
  default     = ["base", "app"]
  description = "List of shared ECR repositories to create"
}

variable "ecr_image_retention_count" {
  type        = number
  default     = 30
  description = "Number of images to retain per repository"
}

################################################################################
# Provider
################################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Layer     = "03-platform"
      ManagedBy = "terraform"
      Project   = var.project_name
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

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# ECR Repositories
################################################################################

resource "aws_ecr_repository" "shared" {
  for_each = toset(var.ecr_repos)

  name                 = "${var.project_name}/${each.key}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = "${var.project_name}-${each.key}"
  }
}

resource "aws_ecr_lifecycle_policy" "shared" {
  for_each   = aws_ecr_repository.shared
  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last ${var.ecr_image_retention_count} images"
        selection = {
          tagStatus     = "any"
          countType     = "imageCountMoreThan"
          countNumber   = var.ecr_image_retention_count
        }
        action = { type = "expire" }
      }
    ]
  })
}

################################################################################
# CI/CD - Artifact Bucket
################################################################################

resource "aws_s3_bucket" "artifacts" {
  count  = var.enable_cicd ? 1 : 0
  bucket = "${var.project_name}-cicd-artifacts-${data.aws_caller_identity.current.account_id}"

  tags = { Name = "CI/CD Artifacts" }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  count  = var.enable_cicd ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  count  = var.enable_cicd ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  rule {
    id     = "cleanup-old-artifacts"
    status = "Enabled"

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  count  = var.enable_cicd ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

################################################################################
# CI/CD - CodeBuild Role
################################################################################

resource "aws_iam_role" "codebuild" {
  count = var.enable_cicd ? 1 : 0
  name  = "${var.project_name}-codebuild"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "codebuild.amazonaws.com" }
    }]
  })

  tags = { Name = "${var.project_name}-codebuild" }
}

resource "aws_iam_role_policy" "codebuild" {
  count = var.enable_cicd ? 1 : 0
  name  = "codebuild-policy"
  role  = aws_iam_role.codebuild[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/${var.project_name}-*",
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/${var.project_name}-*:*"
        ]
      },
      {
        Sid      = "S3Artifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.artifacts[0].arn}/*"
      },
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPush"
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
        Resource = "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/${var.project_name}/*"
      },
      {
        Sid      = "SSMParams"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/*"
      },
      {
        Sid      = "SecretsManager"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}/*"
      },
      {
        Sid    = "VPC"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# CodeBuild - Shared Build Project
################################################################################

resource "aws_codebuild_project" "build" {
  count         = var.enable_cicd ? 1 : 0
  name          = "${var.project_name}-build"
  description   = "Shared build project for ${var.project_name}"
  build_timeout = 30
  service_role  = aws_iam_role.codebuild[0].arn

  artifacts {
    type = "S3"
    location = aws_s3_bucket.artifacts[0].bucket
    packaging = "ZIP"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true # Required for Docker

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = data.aws_region.current.name
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
    }

    environment_variable {
      name  = "ECR_REGISTRY"
      value = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com"
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = <<-YAML
      version: 0.2
      phases:
        pre_build:
          commands:
            - echo "Override this buildspec in your project"
        build:
          commands:
            - echo "Build phase"
        post_build:
          commands:
            - echo "Post-build phase"
    YAML
  }

  vpc_config {
    vpc_id             = data.terraform_remote_state.network.outputs.vpc_id
    subnets            = data.terraform_remote_state.network.outputs.private_subnet_ids
    security_group_ids = [aws_security_group.codebuild[0].id]
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "/aws/codebuild/${var.project_name}"
      stream_name = "build"
    }
  }

  tags = { Name = "${var.project_name}-build" }
}

################################################################################
# CodeBuild Security Group
################################################################################

resource "aws_security_group" "codebuild" {
  count       = var.enable_cicd ? 1 : 0
  name        = "${var.project_name}-codebuild"
  description = "Security group for CodeBuild"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = { Name = "${var.project_name}-codebuild" }
}

################################################################################
# SSM Parameter Store - Hierarchy Base
################################################################################

resource "aws_ssm_parameter" "platform_config" {
  name  = "/${var.project_name}/platform/region"
  type  = "String"
  value = data.aws_region.current.name

  tags = { Name = "Platform Region" }
}

resource "aws_ssm_parameter" "vpc_id" {
  name  = "/${var.project_name}/platform/vpc_id"
  type  = "String"
  value = data.terraform_remote_state.network.outputs.vpc_id

  tags = { Name = "VPC ID" }
}

resource "aws_ssm_parameter" "private_subnets" {
  name  = "/${var.project_name}/platform/private_subnet_ids"
  type  = "StringList"
  value = join(",", data.terraform_remote_state.network.outputs.private_subnet_ids)

  tags = { Name = "Private Subnet IDs" }
}

################################################################################
# Outputs
################################################################################

output "ecr_repositories" {
  value = {
    for k, v in aws_ecr_repository.shared : k => {
      arn = v.arn
      url = v.repository_url
    }
  }
}

output "artifacts_bucket" {
  value = var.enable_cicd ? aws_s3_bucket.artifacts[0].id : null
}

output "codebuild_project" {
  value = var.enable_cicd ? aws_codebuild_project.build[0].name : null
}

output "codebuild_role_arn" {
  value = var.enable_cicd ? aws_iam_role.codebuild[0].arn : null
}

output "codebuild_security_group" {
  value = var.enable_cicd ? aws_security_group.codebuild[0].id : null
}

output "ssm_prefix" {
  value = "/${var.project_name}"
}
