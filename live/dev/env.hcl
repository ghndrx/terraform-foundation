# Development environment configuration
locals {
  environment  = "dev"
  aws_region   = "us-east-1"
  project_name = "myproject"  # Update this
  
  # Environment-specific settings
  settings = {
    multi_az           = false
    deletion_protection = false
    backup_retention   = 1
    instance_class     = "db.t3.micro"
    node_type          = "cache.t3.micro"
    min_capacity       = 1
    max_capacity       = 2
  }
}
