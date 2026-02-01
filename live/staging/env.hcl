# Staging environment configuration
locals {
  environment  = "staging"
  aws_region   = "us-east-1"
  project_name = "myproject"  # Update this
  
  # Environment-specific settings
  settings = {
    multi_az           = false
    deletion_protection = false
    backup_retention   = 7
    instance_class     = "db.t3.small"
    node_type          = "cache.t3.small"
    min_capacity       = 1
    max_capacity       = 5
  }
}
