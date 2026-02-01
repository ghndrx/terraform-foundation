################################################################################
# Workload: ECS Fargate Service
# 
# Container service with:
# - Fargate (serverless containers)
# - Auto-scaling
# - ALB integration
# - Service discovery
# - Secrets/SSM integration
# - CloudWatch logging
# - X-Ray tracing
#
# Use cases: Web services, APIs, microservices
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
    key = "05-workloads/<TENANT>-<NAME>-ecs/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  name   = "<NAME>"
  env    = "prod"
  
  prefix = "${local.tenant}-${local.name}-${local.env}"

  # Container configuration
  container = {
    image      = "nginx:latest" # Update to your ECR image
    port       = 80
    protocol   = "HTTP"
    
    # Resources (Fargate valid combinations)
    # CPU: 256, 512, 1024, 2048, 4096
    # Memory depends on CPU
    cpu    = 256
    memory = 512

    # Health check
    health_check_path = "/health"
    health_check_interval = 30

    # Environment variables
    environment = {
      LOG_LEVEL = "info"
      NODE_ENV  = local.env
    }

    # Secrets from SSM Parameter Store
    secrets_ssm = {
      # DATABASE_URL = "/${local.tenant}/${local.env}/${local.name}/database/url"
    }

    # Secrets from Secrets Manager
    secrets_sm = {
      # API_KEY = "myapp/api-key"
    }
  }

  # Service configuration
  service = {
    desired_count = 2
    min_count     = 1
    max_count     = 10

    # Deployment
    deployment_max_percent         = 200
    deployment_min_healthy_percent = 100
    
    # Enable execute command (for debugging)
    enable_execute_command = true
  }

  # Network (get from remote state or hardcode)
  vpc_id             = "" # data.terraform_remote_state.network.outputs.vpc_id
  private_subnet_ids = [] # data.terraform_remote_state.network.outputs.private_subnet_ids
  public_subnet_ids  = [] # data.terraform_remote_state.network.outputs.public_subnet_ids

  # Load balancer
  alb = {
    enabled           = true
    internal          = false
    certificate_arn   = "" # ACM certificate ARN for HTTPS
    health_check_path = local.container.health_check_path
  }

  # Auto-scaling
  autoscaling = {
    enabled = true
    
    # CPU-based scaling
    cpu_target    = 70
    
    # Request count scaling (if ALB)
    requests_target = 1000  # requests per target per minute
    
    # Scale-in cooldown
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }

  # Service discovery (Cloud Map)
  service_discovery = {
    enabled       = false
    namespace_id  = ""  # Cloud Map namespace ID
    dns_ttl       = 10
  }

  # Logging
  log_retention_days = 30

  # X-Ray tracing
  enable_xray = false
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
      App         = local.name
      Environment = local.env
      ManagedBy   = "terraform"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# ECS Cluster
################################################################################

resource "aws_ecs_cluster" "main" {
  name = local.prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = local.prefix }
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
# CloudWatch Logs
################################################################################

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${local.prefix}"
  retention_in_days = local.log_retention_days

  tags = { Name = local.prefix }
}

################################################################################
# IAM Roles
################################################################################

# Task execution role (ECS agent)
resource "aws_iam_role" "execution" {
  name = "${local.prefix}-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.prefix}-execution" }
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMParameters"
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${local.tenant}/*"
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${local.tenant}/*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = "kms:Decrypt"
        Resource = "*"
      }
    ]
  })
}

# Task role (application)
resource "aws_iam_role" "task" {
  name = "${local.prefix}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.prefix}-task" }
}

# Allow ECS exec
resource "aws_iam_role_policy" "task_exec" {
  count = local.service.enable_execute_command ? 1 : 0
  name  = "ecs-exec"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ]
      Resource = "*"
    }]
  })
}

# X-Ray tracing
resource "aws_iam_role_policy" "task_xray" {
  count = local.enable_xray ? 1 : 0
  name  = "xray"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords",
        "xray:GetSamplingRules",
        "xray:GetSamplingTargets",
        "xray:GetSamplingStatisticSummaries"
      ]
      Resource = "*"
    }]
  })
}

################################################################################
# Security Groups
################################################################################

resource "aws_security_group" "service" {
  count  = length(local.vpc_id) > 0 ? 1 : 0
  name   = "${local.prefix}-service"
  vpc_id = local.vpc_id

  ingress {
    description     = "From ALB"
    from_port       = local.container.port
    to_port         = local.container.port
    protocol        = "tcp"
    security_groups = local.alb.enabled ? [aws_security_group.alb[0].id] : []
    cidr_blocks     = local.alb.enabled ? [] : ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-service" }
}

resource "aws_security_group" "alb" {
  count  = local.alb.enabled && length(local.vpc_id) > 0 ? 1 : 0
  name   = "${local.prefix}-alb"
  vpc_id = local.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "To service"
    from_port   = local.container.port
    to_port     = local.container.port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-alb" }
}

################################################################################
# Application Load Balancer
################################################################################

resource "aws_lb" "main" {
  count              = local.alb.enabled && length(local.public_subnet_ids) > 0 ? 1 : 0
  name               = local.prefix
  internal           = local.alb.internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = local.alb.internal ? local.private_subnet_ids : local.public_subnet_ids

  enable_deletion_protection = local.env == "prod"

  tags = { Name = local.prefix }
}

resource "aws_lb_target_group" "main" {
  count       = local.alb.enabled && length(local.vpc_id) > 0 ? 1 : 0
  name        = local.prefix
  port        = local.container.port
  protocol    = "HTTP"
  vpc_id      = local.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = local.container.health_check_interval
    path                = local.alb.health_check_path
    matcher             = "200-299"
  }

  tags = { Name = local.prefix }
}

resource "aws_lb_listener" "https" {
  count             = local.alb.enabled && length(local.alb.certificate_arn) > 0 && length(local.public_subnet_ids) > 0 ? 1 : 0
  load_balancer_arn = aws_lb.main[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.alb.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main[0].arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count             = local.alb.enabled && length(local.public_subnet_ids) > 0 ? 1 : 0
  load_balancer_arn = aws_lb.main[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = length(local.alb.certificate_arn) > 0 ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = length(local.alb.certificate_arn) > 0 ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = length(local.alb.certificate_arn) > 0 ? null : aws_lb_target_group.main[0].arn
  }
}

################################################################################
# Task Definition
################################################################################

resource "aws_ecs_task_definition" "main" {
  family                   = local.prefix
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = local.container.cpu
  memory                   = local.container.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode(concat(
    [{
      name      = "app"
      image     = local.container.image
      essential = true

      portMappings = [{
        containerPort = local.container.port
        protocol      = "tcp"
      }]

      environment = [
        for k, v in local.container.environment : { name = k, value = v }
      ]

      secrets = concat(
        [for k, v in local.container.secrets_ssm : {
          name      = k
          valueFrom = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${v}"
        }],
        [for k, v in local.container.secrets_sm : {
          name      = k
          valueFrom = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${v}"
        }]
      )

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "app"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${local.container.port}${local.container.health_check_path} || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }],
    local.enable_xray ? [{
      name      = "xray-daemon"
      image     = "amazon/aws-xray-daemon:latest"
      essential = false
      cpu       = 32
      memory    = 256
      portMappings = [{
        containerPort = 2000
        protocol      = "udp"
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "xray"
        }
      }
    }] : []
  ))

  tags = { Name = local.prefix }
}

################################################################################
# ECS Service
################################################################################

resource "aws_ecs_service" "main" {
  count           = length(local.vpc_id) > 0 && length(local.private_subnet_ids) > 0 ? 1 : 0
  name            = local.prefix
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.main.arn
  desired_count   = local.service.desired_count
  launch_type     = "FARGATE"

  deployment_maximum_percent         = local.service.deployment_max_percent
  deployment_minimum_healthy_percent = local.service.deployment_min_healthy_percent
  enable_execute_command             = local.service.enable_execute_command

  network_configuration {
    subnets          = local.private_subnet_ids
    security_groups  = [aws_security_group.service[0].id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = local.alb.enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.main[0].arn
      container_name   = "app"
      container_port   = local.container.port
    }
  }

  dynamic "service_registries" {
    for_each = local.service_discovery.enabled ? [1] : []
    content {
      registry_arn = aws_service_discovery_service.main[0].arn
    }
  }

  tags = { Name = local.prefix }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

################################################################################
# Auto Scaling
################################################################################

resource "aws_appautoscaling_target" "main" {
  count              = local.autoscaling.enabled && length(local.vpc_id) > 0 ? 1 : 0
  max_capacity       = local.service.max_count
  min_capacity       = local.service.min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  count              = local.autoscaling.enabled && length(local.vpc_id) > 0 ? 1 : 0
  name               = "${local.prefix}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.main[0].resource_id
  scalable_dimension = aws_appautoscaling_target.main[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.main[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = local.autoscaling.cpu_target
    scale_in_cooldown  = local.autoscaling.scale_in_cooldown
    scale_out_cooldown = local.autoscaling.scale_out_cooldown
  }
}

resource "aws_appautoscaling_policy" "requests" {
  count              = local.autoscaling.enabled && local.alb.enabled && length(local.vpc_id) > 0 ? 1 : 0
  name               = "${local.prefix}-requests"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.main[0].resource_id
  scalable_dimension = aws_appautoscaling_target.main[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.main[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.main[0].arn_suffix}/${aws_lb_target_group.main[0].arn_suffix}"
    }
    target_value       = local.autoscaling.requests_target
    scale_in_cooldown  = local.autoscaling.scale_in_cooldown
    scale_out_cooldown = local.autoscaling.scale_out_cooldown
  }
}

################################################################################
# Service Discovery
################################################################################

resource "aws_service_discovery_service" "main" {
  count = local.service_discovery.enabled ? 1 : 0
  name  = local.name

  dns_config {
    namespace_id = local.service_discovery.namespace_id

    dns_records {
      ttl  = local.service_discovery.dns_ttl
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = { Name = local.prefix }
}

################################################################################
# Outputs
################################################################################

output "cluster_name" {
  value       = aws_ecs_cluster.main.name
  description = "ECS cluster name"
}

output "service_name" {
  value       = length(aws_ecs_service.main) > 0 ? aws_ecs_service.main[0].name : null
  description = "ECS service name"
}

output "alb_dns_name" {
  value       = length(aws_lb.main) > 0 ? aws_lb.main[0].dns_name : null
  description = "ALB DNS name"
}

output "alb_zone_id" {
  value       = length(aws_lb.main) > 0 ? aws_lb.main[0].zone_id : null
  description = "ALB hosted zone ID (for Route53 alias)"
}

output "task_definition_arn" {
  value       = aws_ecs_task_definition.main.arn
  description = "Task definition ARN"
}

output "log_group" {
  value       = aws_cloudwatch_log_group.app.name
  description = "CloudWatch log group"
}

output "exec_command" {
  value       = length(aws_ecs_service.main) > 0 ? "aws ecs execute-command --cluster ${aws_ecs_cluster.main.name} --task <task-id> --container app --interactive --command '/bin/sh'" : null
  description = "ECS exec command for debugging"
}

output "update_command" {
  value       = length(aws_ecs_service.main) > 0 ? "aws ecs update-service --cluster ${aws_ecs_cluster.main.name} --service ${aws_ecs_service.main[0].name} --force-new-deployment" : null
  description = "Force new deployment command"
}
