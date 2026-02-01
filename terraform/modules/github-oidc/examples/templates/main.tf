################################################################################
# GitHub OIDC - Pre-built Templates Example
#
# Using pre-built role templates for common patterns
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

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

# Prerequisites - S3 bucket for Terraform state
resource "aws_s3_bucket" "terraform_state" {
  bucket_prefix = "terraform-state-"
  force_destroy = true  # For example only - remove in production

  tags = {
    Purpose = "terraform-state"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Purpose = "terraform-locks"
  }
}

# ECR repository for container builds
resource "aws_ecr_repository" "app" {
  name                 = "my-application"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Purpose = "container-registry"
  }
}

# GitHub OIDC with all templates enabled
module "github_oidc" {
  source = "../../"

  github_org  = "example-org"
  name_prefix = "github"

  # Terraform deployment role
  terraform_deploy_role = {
    enabled             = true
    repos               = ["infrastructure"]
    branches            = ["main"]
    environments        = ["production"]
    state_bucket        = aws_s3_bucket.terraform_state.id
    state_bucket_key_prefix = "live/*"
    dynamodb_table      = aws_dynamodb_table.terraform_locks.name
    allowed_services    = ["ec2", "s3", "iam", "lambda", "rds", "vpc"]
    denied_actions      = [
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "organizations:*"
    ]
  }

  # ECR push role for container builds
  ecr_push_role = {
    enabled      = true
    repos        = ["my-application", "backend-api"]
    branches     = ["main", "develop"]
    ecr_repos    = [aws_ecr_repository.app.name]
    allow_create = false
    allow_delete = false
  }

  # S3 deploy role for static sites
  s3_deploy_role = {
    enabled          = true
    repos            = ["frontend"]
    branches         = ["main"]
    bucket_arns      = ["arn:aws:s3:::www.example.com"]
    allowed_prefixes = ["*"]
    cloudfront_arns  = []  # Add CloudFront distribution ARN if needed
  }

  # Lambda deploy role for serverless
  lambda_deploy_role = {
    enabled       = true
    repos         = ["serverless-api"]
    branches      = ["main"]
    function_arns = ["arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:api-*"]
    allow_create  = false
    allow_logs    = true
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Outputs
output "terraform_role_arn" {
  description = "Role ARN for Terraform deployments"
  value       = module.github_oidc.terraform_role_arn
}

output "ecr_role_arn" {
  description = "Role ARN for ECR push operations"
  value       = module.github_oidc.ecr_role_arn
}

output "s3_deploy_role_arn" {
  description = "Role ARN for S3 static site deployments"
  value       = module.github_oidc.s3_deploy_role_arn
}

output "lambda_deploy_role_arn" {
  description = "Role ARN for Lambda deployments"
  value       = module.github_oidc.lambda_deploy_role_arn
}

output "all_roles" {
  description = "All created role ARNs"
  value       = module.github_oidc.all_role_arns
}

output "workflow_examples" {
  description = "Example workflow snippets"
  value       = module.github_oidc.workflow_examples
}
