# TFLint configuration
# https://github.com/terraform-linters/tflint

config {
  module = true
}

plugin "aws" {
  enabled = true
  version = "0.29.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Enforce naming conventions
rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}

# Require descriptions for variables/outputs
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

# Prevent deprecated syntax
rule "terraform_deprecated_interpolation" {
  enabled = true
}

# AWS specific rules
rule "aws_instance_invalid_type" {
  enabled = true
}

rule "aws_resource_missing_tags" {
  enabled = true
  tags    = ["Name", "Environment"]
}

# Disable noisy rules
rule "terraform_unused_declarations" {
  enabled = false  # Too strict for templates with placeholders
}
