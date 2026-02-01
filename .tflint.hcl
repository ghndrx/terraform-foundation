# TFLint Configuration
# Terraform linting with AWS best practices
# https://github.com/terraform-linters/tflint

config {
  module = true
  force  = false
}

# AWS Provider Plugin
plugin "aws" {
  enabled = true
  version = "0.29.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"

  # Deep checking (requires AWS credentials)
  deep_check = false
}

################################################################################
# Terraform Core Rules
################################################################################

# Enforce snake_case naming
rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}

# Require descriptions
rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

# Standard module structure
rule "terraform_standard_module_structure" {
  enabled = true
}

# Deprecated syntax
rule "terraform_deprecated_interpolation" {
  enabled = true
}

rule "terraform_deprecated_index" {
  enabled = true
}

# Comment formatting
rule "terraform_comment_syntax" {
  enabled = true
}

# Require type declarations
rule "terraform_typed_variables" {
  enabled = true
}

# Workspace usage (discouraged with Terragrunt)
rule "terraform_workspace_remote" {
  enabled = true
}

################################################################################
# AWS Security Rules
################################################################################

# Invalid instance types
rule "aws_instance_invalid_type" {
  enabled = true
}

# Invalid AMIs
rule "aws_instance_invalid_ami" {
  enabled = true
}

# Resource tagging
rule "aws_resource_missing_tags" {
  enabled = true
  tags    = ["Name", "Environment", "ManagedBy"]
}

# IAM Policy best practices
rule "aws_iam_policy_document_gov_friendly_arns" {
  enabled = true
}

rule "aws_iam_policy_too_long_policy" {
  enabled = true
}

# S3 bucket configuration
rule "aws_s3_bucket_invalid_acl" {
  enabled = true
}

# Security group rules
rule "aws_security_group_invalid_protocol" {
  enabled = true
}

# DB instance sizing
rule "aws_db_instance_invalid_type" {
  enabled = true
}

rule "aws_db_instance_invalid_db_subnet_group" {
  enabled = true
}

# ElastiCache
rule "aws_elasticache_cluster_invalid_type" {
  enabled = true
}

# Lambda
rule "aws_lambda_function_invalid_runtime" {
  enabled = true
}

################################################################################
# Disabled Rules
################################################################################

# Too strict for template modules with dynamic configs
rule "terraform_unused_declarations" {
  enabled = false
}

# Allow empty defaults for optional objects
rule "terraform_required_providers" {
  enabled = false
}
