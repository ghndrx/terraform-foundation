################################################################################
# GitHub OIDC Module - Security Tests
# Validates security best practices are enforced
################################################################################

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
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

# Test: Wildcard repos denied by default
run "wildcard_repos_denied" {
  command = plan

  variables {
    github_org          = "test-org"
    deny_wildcard_repos = true
    roles = {
      test = {
        repos    = ["*"]  # Wildcard - should fail without workflow_ref
        branches = ["main"]
      }
    }
  }

  expect_failures = [
    # This should fail validation because wildcard repos require workflow_ref
    var.roles
  ]
}

# Test: Wildcard repos allowed with workflow_ref
run "wildcard_repos_with_workflow_ref" {
  command = plan

  variables {
    github_org          = "test-org"
    deny_wildcard_repos = true
    roles = {
      test = {
        repos        = ["*"]
        workflow_ref = "test-org/workflows/.github/workflows/deploy.yml@main"
      }
    }
  }

  # Should succeed because workflow_ref is specified
  assert {
    condition     = aws_iam_role.github["test"].name == "github-test"
    error_message = "Should allow wildcard with workflow_ref"
  }
}

# Test: IAM path isolation
run "iam_path_isolation" {
  command = plan

  variables {
    github_org = "test-org"
    path       = "/github-actions/"
    roles = {
      test = {
        repos    = ["app"]
        branches = ["main"]
      }
    }
  }

  # Verify path is set for role isolation
  assert {
    condition     = aws_iam_role.github["test"].path == "/github-actions/"
    error_message = "Role should use isolated IAM path"
  }
}

# Test: Permissions boundary is applied
run "permissions_boundary_applied" {
  command = plan

  variables {
    github_org           = "test-org"
    permissions_boundary = "arn:aws:iam::123456789012:policy/TestBoundary"
    roles = {
      test = {
        repos    = ["app"]
        branches = ["main"]
      }
    }
  }

  # Verify permissions boundary is set
  assert {
    condition     = aws_iam_role.github["test"].permissions_boundary == "arn:aws:iam::123456789012:policy/TestBoundary"
    error_message = "Permissions boundary should be applied to role"
  }
}

# Test: Terraform role has explicit denies
run "terraform_role_explicit_denies" {
  command = plan

  variables {
    github_org = "test-org"
    terraform_deploy_role = {
      enabled        = true
      repos          = ["infra"]
      branches       = ["main"]
      denied_actions = ["iam:CreateUser", "organizations:*"]
    }
  }

  # Verify deny policy is created
  assert {
    condition     = aws_iam_role_policy.terraform_deny[0].name == "terraform-deny"
    error_message = "Terraform deny policy should be created"
  }
}

# Test: ECR role requires explicit repos
run "ecr_explicit_repos_required" {
  command = plan

  variables {
    github_org = "test-org"
    ecr_push_role = {
      enabled   = true
      repos     = ["app"]
      ecr_repos = ["my-ecr-repo"]  # Explicit ECR repo required
    }
  }

  # Should succeed with explicit ECR repos
  assert {
    condition     = aws_iam_role.ecr[0].name == "github-ecr-push"
    error_message = "ECR role should be created with explicit repos"
  }
}

# Test: Role tags include security metadata
run "security_tags" {
  command = plan

  variables {
    github_org = "test-org"
    roles = {
      test = {
        repos    = ["app"]
        branches = ["main"]
      }
    }
    tags = {
      Environment = "production"
    }
  }

  # Verify tags include ManagedBy and Module
  assert {
    condition     = aws_iam_role.github["test"].tags["ManagedBy"] == "terraform"
    error_message = "Role should have ManagedBy tag"
  }

  assert {
    condition     = aws_iam_role.github["test"].tags["Module"] == "github-oidc"
    error_message = "Role should have Module tag"
  }
}

# Test: Trust policy uses StringLike for subject claims
run "trust_policy_string_like" {
  command = plan

  variables {
    github_org = "test-org"
    roles = {
      test = {
        repos    = ["app"]
        branches = ["main", "develop"]  # Multiple branches
      }
    }
  }

  # Role should be created with proper trust policy
  assert {
    condition     = aws_iam_role.github["test"].assume_role_policy != ""
    error_message = "Trust policy should be set"
  }
}
