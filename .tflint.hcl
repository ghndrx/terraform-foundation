# TFLint configuration
# https://github.com/terraform-linters/tflint

config {
  # Module inspection
  call_module_type = "local"
  force = false
}

# AWS Plugin
plugin "aws" {
  enabled = true
  version = "0.29.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Terraform rules
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# Naming convention rules
rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}

rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_typed_variables" {
  enabled = true
}

# AWS-specific rules
rule "aws_instance_invalid_type" {
  enabled = true
}

rule "aws_instance_previous_type" {
  enabled = true
}

rule "aws_db_instance_invalid_type" {
  enabled = true
}

rule "aws_elasticache_cluster_invalid_type" {
  enabled = true
}

# Disable overly strict rules
rule "terraform_comment_syntax" {
  enabled = false
}
