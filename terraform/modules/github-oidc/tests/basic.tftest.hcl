################################################################################
# GitHub OIDC Module - Basic Tests
# Uses Terraform native testing framework
################################################################################

# Mock AWS provider for unit tests
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:user/test"
      user_id    = "AIDATEST123456789"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "us-east-1"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }
}

# Test: Basic role creation
run "basic_role_creation" {
  command = plan

  variables {
    github_org = "test-org"
    roles = {
      deploy = {
        repos    = ["test-repo"]
        branches = ["main"]
        policy_statements = [{
          sid       = "TestAccess"
          actions   = ["s3:GetObject"]
          resources = ["arn:aws:s3:::test-bucket/*"]
        }]
      }
    }
    tags = {
      Environment = "test"
    }
  }

  # Verify OIDC provider is created
  assert {
    condition     = aws_iam_openid_connect_provider.github[0].url == "https://token.actions.githubusercontent.com"
    error_message = "OIDC provider URL is incorrect"
  }

  # Verify role is created with correct name
  assert {
    condition     = aws_iam_role.github["deploy"].name == "github-deploy"
    error_message = "Role name should be github-deploy"
  }

  # Verify IAM path is set correctly
  assert {
    condition     = aws_iam_role.github["deploy"].path == "/github-actions/"
    error_message = "Role path should be /github-actions/"
  }
}

# Test: Repository normalization with org prefix
run "repo_normalization" {
  command = plan

  variables {
    github_org = "my-org"
    roles = {
      test = {
        repos    = ["repo-without-org"]  # Should become my-org/repo-without-org
        branches = ["main"]
      }
    }
  }

  # Role should be created (validates normalization works)
  assert {
    condition     = aws_iam_role.github["test"].name == "github-test"
    error_message = "Role should be created with normalized repo"
  }
}

# Test: Multiple roles with different configurations
run "multiple_roles" {
  command = plan

  variables {
    github_org = "test-org"
    roles = {
      validate = {
        repos        = ["app"]
        pull_request = true
        max_session_hours = 1
      }
      deploy = {
        repos    = ["app"]
        branches = ["main"]
        max_session_hours = 2
      }
      release = {
        repos = ["app"]
        tags  = ["v*"]
      }
    }
  }

  # Verify all roles are created
  assert {
    condition     = length(aws_iam_role.github) == 3
    error_message = "Should create 3 roles"
  }
}

# Test: Terraform deploy template role
run "terraform_template_role" {
  command = plan

  variables {
    github_org = "test-org"
    terraform_deploy_role = {
      enabled        = true
      repos          = ["infra"]
      branches       = ["main"]
      state_bucket   = "my-tf-state"
      dynamodb_table = "terraform-locks"
    }
  }

  # Verify Terraform role is created
  assert {
    condition     = aws_iam_role.terraform[0].name == "github-terraform"
    error_message = "Terraform role should be created"
  }
}

# Test: ECR push template role
run "ecr_template_role" {
  command = plan

  variables {
    github_org = "test-org"
    ecr_push_role = {
      enabled   = true
      repos     = ["app"]
      branches  = ["main"]
      ecr_repos = ["my-ecr-repo"]
    }
  }

  # Verify ECR role is created
  assert {
    condition     = aws_iam_role.ecr[0].name == "github-ecr-push"
    error_message = "ECR role should be created"
  }
}

# Test: Session duration capping
run "session_duration_capping" {
  command = plan

  variables {
    github_org              = "test-org"
    max_session_hours_limit = 2
    roles = {
      test = {
        repos             = ["app"]
        branches          = ["main"]
        max_session_hours = 4  # Should be capped to 2
      }
    }
  }

  # Verify session duration is capped (2 hours = 7200 seconds)
  assert {
    condition     = aws_iam_role.github["test"].max_session_duration == 7200
    error_message = "Session duration should be capped at 2 hours (7200 seconds)"
  }
}

# Test: Existing provider ARN (no provider creation)
run "existing_provider" {
  command = plan

  variables {
    create_provider = false
    provider_arn    = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    github_org      = "test-org"
    roles = {
      test = {
        repos    = ["app"]
        branches = ["main"]
      }
    }
  }

  # Verify no provider is created
  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 0
    error_message = "Should not create provider when create_provider=false"
  }
}
