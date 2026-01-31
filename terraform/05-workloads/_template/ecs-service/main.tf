################################################################################
# Workload: ECS Fargate Service
# 
# Deploys a containerized application on ECS Fargate:
# - ECS Service with Fargate launch type
# - Application Load Balancer (optional)
# - Auto-scaling based on CPU/Memory
# - CloudWatch logging
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<app>/
#   Update locals and variables
#   terraform init -backend-config=../../00-bootstrap/backend.hcl
#   terraform apply
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  backend "s3" {
    key = "05-workloads/<TENANT>-<APP>/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  app    = "<APP>"
  env    = "prod" # prod, staging, dev
  name   = "${local.tenant}-${local.app}-${local.env}"
  
  # Short name for resources with strict limits (ALB: 32 chars, TG: 32 chars)
  # Uses first 10 chars of tenant + first 10 of app + env suffix
  short_name = "${substr(local.tenant, 0, min(10, length(local.tenant)))}-${substr(local.app, 0, min(10, length(local.app)))}-${substr(local.env, 0, 4)}"

  # Container config
  container_image = "<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/<IMAGE>:latest"
  container_port  = 8080
  cpu             = 256  # 0.25 vCPU
  memory          = 512  # MB

  # Scaling
  desired_count = 2
  min_count     = 1
  max_count     = 10

  # Load balancer
  enable_alb       = true
  health_check_path = "/health"

  # Environment variables (non-sensitive)
  environment = {
    APP_ENV    = local.env
    LOG_LEVEL  = "info"
  }

  # Secrets from SSM/Secrets Manager (ARNs)
  secrets = {
    # DATABASE_URL = "arn:aws:secretsmanager:us-east-1:123456789:secret:mydb-xxx"
  }
}

################################################################################
# Variables
################################################################################

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "state_bucket" {
  type = string
}

################################################################################
# Provider
################################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Tenant      = local.tenant
      App         = local.app
      Environment = local.env
      ManagedBy   = "terraform"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "02-network/terraform.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "tenant" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "04-tenants/${local.tenant}/terraform.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "bootstrap" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "00-bootstrap/terraform.tfstate"
    region = var.region
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# ECS Cluster
################################################################################

resource "aws_ecs_cluster" "main" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = local.name }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

################################################################################
# CloudWatch Log Group
################################################################################

resource "aws_cloudwatch_log_group" "main" {
  name              = "/ecs/${local.name}"
  retention_in_days = 30

  tags = { Name = local.name }
}

################################################################################
# IAM - Task Execution Role
################################################################################

resource "aws_iam_role" "execution" {
  name = "${local.name}-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-execution" }
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  count = length(local.secrets) > 0 ? 1 : 0
  name  = "secrets-access"
  role  = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = values(local.secrets)
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameters"]
        Resource = values(local.secrets)
      }
    ]
  })
}

################################################################################
# IAM - Task Role (app permissions)
################################################################################

resource "aws_iam_role" "task" {
  name = "${local.name}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-task" }
}

# Add app-specific permissions here
resource "aws_iam_role_policy" "task" {
  name = "app-permissions"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTaggedResources"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "dynamodb:*"]
        Resource = "*"
        Condition = { StringEquals = { "aws:ResourceTag/Tenant" = local.tenant } }
      }
    ]
  })
}

################################################################################
# Task Definition
################################################################################

resource "aws_ecs_task_definition" "main" {
  family                   = local.name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = local.cpu
  memory                   = local.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = local.app
      image     = local.container_image
      essential = true

      portMappings = [{
        containerPort = local.container_port
        protocol      = "tcp"
      }]

      environment = [
        for k, v in local.environment : { name = k, value = v }
      ]

      secrets = [
        for k, v in local.secrets : { name = k, valueFrom = v }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.main.name
          awslogs-region        = data.aws_region.current.name
          awslogs-stream-prefix = "ecs"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${local.container_port}${local.health_check_path} || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = { Name = local.name }
}

################################################################################
# Security Group - Service
################################################################################

resource "aws_security_group" "service" {
  name        = "${local.name}-service"
  description = "ECS service for ${local.name}"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = { Name = "${local.name}-service" }
}

# Separate ingress rules to handle conditional ALB
resource "aws_security_group_rule" "service_from_alb" {
  count                    = local.enable_alb ? 1 : 0
  type                     = "ingress"
  from_port                = local.container_port
  to_port                  = local.container_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb[0].id
  security_group_id        = aws_security_group.service.id
  description              = "From ALB"
}

resource "aws_security_group_rule" "service_self" {
  count             = local.enable_alb ? 0 : 1
  type              = "ingress"
  from_port         = local.container_port
  to_port           = local.container_port
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.service.id
  description       = "Self-referencing for service mesh"
}

################################################################################
# ALB
################################################################################

resource "aws_security_group" "alb" {
  count       = local.enable_alb ? 1 : 0
  name        = "${local.name}-alb"
  description = "ALB for ${local.name}"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-alb" }
}

resource "aws_lb" "main" {
  count              = local.enable_alb ? 1 : 0
  name               = local.short_name # ALB names max 32 chars
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = data.terraform_remote_state.network.outputs.public_subnet_ids

  # Security: Drop invalid headers
  drop_invalid_header_fields = true

  # Access logging for audit trail
  access_logs {
    bucket  = data.terraform_remote_state.bootstrap.outputs.logs_bucket
    prefix  = "alb/${local.name}"
    enabled = true
  }

  tags = { Name = local.name }
}

resource "aws_lb_target_group" "main" {
  count       = local.enable_alb ? 1 : 0
  name        = local.short_name # Target group names max 32 chars
  port        = local.container_port
  protocol    = "HTTP"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = local.health_check_path
    port                = "traffic-port"
    timeout             = 5
    unhealthy_threshold = 3
  }

  # Enable stickiness for stateful apps (disabled by default)
  stickiness {
    type            = "lb_cookie"
    enabled         = false
    cookie_duration = 86400
  }

  tags = { Name = local.name }
}

resource "aws_lb_listener" "http" {
  count             = local.enable_alb ? 1 : 0
  load_balancer_arn = aws_lb.main[0].arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main[0].arn
  }
}

################################################################################
# ECS Service
################################################################################

resource "aws_ecs_service" "main" {
  name            = local.app
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.main.arn
  desired_count   = local.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.terraform_remote_state.network.outputs.private_subnet_ids
    security_groups  = [aws_security_group.service.id, data.terraform_remote_state.tenant.outputs.security_groups.base]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = local.enable_alb ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.main[0].arn
      container_name   = local.app
      container_port   = local.container_port
    }
  }

  lifecycle {
    ignore_changes = [desired_count] # Managed by auto-scaling
  }

  tags = { Name = local.name }
}

################################################################################
# Auto Scaling
################################################################################

resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = local.max_count
  min_capacity       = local.min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "memory" {
  name               = "${local.name}-memory"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 80
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

################################################################################
# Outputs
################################################################################

output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "service_name" {
  value = aws_ecs_service.main.name
}

output "alb_dns_name" {
  value = local.enable_alb ? aws_lb.main[0].dns_name : null
}

output "alb_zone_id" {
  value = local.enable_alb ? aws_lb.main[0].zone_id : null
}

output "log_group" {
  value = aws_cloudwatch_log_group.main.name
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}
