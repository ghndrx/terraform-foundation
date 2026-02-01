# GitHub OIDC Module

Secure CI/CD access from GitHub Actions to AWS without long-lived credentials.

## Features

- 🔐 **OIDC Provider** - Automatic setup of GitHub OIDC trust
- 🎯 **Fine-grained access** - Restrict by repo, branch, tag, environment
- 📦 **Pre-built templates** - Common patterns for Terraform, ECR, S3, Lambda
- 🔧 **Custom roles** - Full flexibility for any use case
- 📝 **Policy generation** - Build policies from simple statements

## Quick Start

```hcl
module "github_oidc" {
  source = "../modules/github-oidc"
  
  github_org = "myorg"
  
  # Custom role
  roles = {
    deploy = {
      repos    = ["myrepo"]
      branches = ["main"]
      policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]
    }
  }
}
```

## Pre-built Templates

### Terraform Deployments

```hcl
module "github_oidc" {
  source = "../modules/github-oidc"
  
  github_org = "myorg"
  
  terraform_deploy_role = {
    enabled        = true
    repos          = ["infrastructure"]
    branches       = ["main"]
    environments   = ["production"]
    state_bucket   = "myorg-tf-state"
    dynamodb_table = "terraform-locks"
  }
}
```

### ECR Push

```hcl
module "github_oidc" {
  source = "../modules/github-oidc"
  
  github_org = "myorg"
  
  ecr_push_role = {
    enabled      = true
    repos        = ["backend", "frontend"]
    branches     = ["main", "develop"]
    ecr_repos    = ["backend", "frontend"]
    allow_create = false
  }
}
```

### S3 Static Site Deploy

```hcl
module "github_oidc" {
  source = "../modules/github-oidc"
  
  github_org = "myorg"
  
  s3_deploy_role = {
    enabled         = true
    repos           = ["website"]
    branches        = ["main"]
    bucket_arns     = ["arn:aws:s3:::mysite.com"]
    cloudfront_arns = ["arn:aws:cloudfront::123456789012:distribution/EXAMPLE"]
  }
}
```

### Lambda Deploy

```hcl
module "github_oidc" {
  source = "../modules/github-oidc"
  
  github_org = "myorg"
  
  lambda_deploy_role = {
    enabled       = true
    repos         = ["serverless-api"]
    branches      = ["main"]
    function_arns = ["arn:aws:lambda:us-east-1:123456789012:function:my-api"]
  }
}
```

## Advanced Usage

### Multiple Custom Roles

```hcl
module "github_oidc" {
  source = "../modules/github-oidc"
  
  github_org = "myorg"
  
  roles = {
    # Read-only for PRs
    preview = {
      repos        = ["webapp"]
      pull_request = true
      policy_arns  = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    }
    
    # Full deploy for main
    deploy = {
      repos    = ["webapp"]
      branches = ["main"]
      policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]
    }
    
    # Tag-based releases
    release = {
      repos = ["webapp"]
      tags  = ["v*"]
      policy_statements = [{
        actions   = ["s3:PutObject", "cloudfront:CreateInvalidation"]
        resources = ["*"]
      }]
    }
  }
}
```

### Reusable Workflow Restriction

```hcl
roles = {
  deploy = {
    repos        = ["*"]  # Any repo in org
    workflow_ref = "myorg/workflows/.github/workflows/deploy.yml@main"
    policy_arns  = ["arn:aws:iam::aws:policy/PowerUserAccess"]
  }
}
```

### Custom Trust Conditions

```hcl
roles = {
  restricted = {
    repos    = ["myrepo"]
    branches = ["main"]
    extra_conditions = {
      StringEquals = {
        "token.actions.githubusercontent.com:actor" = ["trusted-user"]
      }
    }
    policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
  }
}
```

## GitHub Actions Workflow

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # Required for OIDC
      contents: read
    
    steps:
      - uses: actions/checkout@v4
      
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
          aws-region: us-east-1
      
      - run: aws sts get-caller-identity
```

## Inputs

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `create_provider` | Create OIDC provider | `bool` | `true` |
| `provider_arn` | Existing provider ARN | `string` | `""` |
| `github_org` | GitHub organization | `string` | `""` |
| `name_prefix` | Role name prefix | `string` | `"github"` |
| `roles` | Custom role configs | `map(object)` | `{}` |
| `terraform_deploy_role` | Terraform template | `object` | `{}` |
| `ecr_push_role` | ECR template | `object` | `{}` |
| `s3_deploy_role` | S3 template | `object` | `{}` |
| `lambda_deploy_role` | Lambda template | `object` | `{}` |

## Outputs

| Name | Description |
|------|-------------|
| `provider_arn` | OIDC provider ARN |
| `role_arns` | Map of custom role ARNs |
| `all_role_arns` | All role ARNs (custom + templates) |
| `terraform_role_arn` | Terraform role ARN |
| `ecr_role_arn` | ECR role ARN |
| `workflow_examples` | Example workflow snippets |

## Security Considerations

1. **Principle of least privilege** - Use specific repos/branches, not wildcards
2. **Environment protection** - Use GitHub environments for production
3. **Permissions boundary** - Consider attaching a boundary for defense-in-depth
4. **Audit** - CloudTrail logs all AssumeRoleWithWebIdentity calls
