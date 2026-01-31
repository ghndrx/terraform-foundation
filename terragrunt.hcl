# Root Terragrunt configuration
# This enables DRY (Don't Repeat Yourself) configuration across environments
#
# Directory structure with Terragrunt:
# live/
# ├── terragrunt.hcl (this file, copied to live/)
# ├── prod/
# │   ├── env.hcl
# │   ├── network/
# │   │   └── terragrunt.hcl
# │   └── tenants/
# │       └── acme/
# │           └── terragrunt.hcl
# ├── staging/
# │   └── ...
# └── dev/
#     └── ...

locals {
  # Parse the file path to extract environment and component
  path_components = split("/", path_relative_to_include())
  
  # Load environment-specific variables
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl", "env.hcl"))
  
  # Common variables
  aws_region   = local.env_vars.locals.aws_region
  environment  = local.env_vars.locals.environment
  project_name = local.env_vars.locals.project_name
  
  # State bucket (from bootstrap)
  state_bucket = "${local.project_name}-terraform-state"
  lock_table   = "${local.project_name}-terraform-locks"
}

# Generate provider configuration
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  region = "${local.aws_region}"

  default_tags {
    tags = {
      Environment = "${local.environment}"
      Project     = "${local.project_name}"
      ManagedBy   = "terragrunt"
    }
  }
}
EOF
}

# Configure remote state
remote_state {
  backend = "s3"
  
  config = {
    bucket         = local.state_bucket
    key            = "${path_relative_to_include()}/terraform.tfstate"
    region         = local.aws_region
    encrypt        = true
    dynamodb_table = local.lock_table
  }
  
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

# Default inputs passed to all modules
inputs = {
  region       = local.aws_region
  environment  = local.environment
  project_name = local.project_name
  state_bucket = local.state_bucket
}

# Retry configuration for transient errors
retry_max_attempts       = 3
retry_sleep_interval_sec = 5
