# Production environment configuration
locals {
  environment  = "prod"
  aws_region   = "us-east-1"
  project_name = "myproject"  # Update this
  
  # Environment-specific settings
  settings = {
    multi_az           = true
    deletion_protection = true
    backup_retention   = 35
    instance_class     = "db.r6g.large"
    node_type          = "cache.r6g.large"
    min_capacity       = 2
    max_capacity       = 20
  }
}
