################################################################################
# GitHub OIDC - Basic Example
#
# Single role with branch restriction
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

module "github_oidc" {
  source = "../../"

  github_org  = "example-org"
  name_prefix = "github"

  roles = {
    deploy = {
      repos    = ["my-app"]
      branches = ["main"]
      policy_statements = [
        {
          sid       = "S3Access"
          actions   = ["s3:GetObject", "s3:PutObject"]
          resources = ["arn:aws:s3:::my-bucket/*"]
        }
      ]
    }
  }

  tags = {
    Environment = "production"
    Project     = "my-app"
  }
}

output "role_arn" {
  value = module.github_oidc.role_arns["deploy"]
}

output "provider_arn" {
  value = module.github_oidc.provider_arn
}
