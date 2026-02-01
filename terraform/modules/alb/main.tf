################################################################################
# Application Load Balancer Module
#
# Full-featured ALB with:
# - HTTPS with ACM certificate
# - HTTP to HTTPS redirect
# - Access logging to S3
# - WAF integration (optional)
# - Multiple target groups
# - Host/path-based routing
# - Health checks
#
# Usage:
#   module "alb" {
#     source = "../modules/alb"
#     
#     name       = "web-alb"
#     vpc_id     = module.vpc.vpc_id
#     subnet_ids = module.vpc.public_subnet_ids
#     
#     certificate_arn = module.acm.certificate_arn
#     
#     target_groups = {
#       api = {
#         port        = 8080
#         protocol    = "HTTP"
#         target_type = "ip"
#         health_check_path = "/health"
#       }
#     }
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "name" {
  type        = string
  description = "ALB name"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs (public for internet-facing, private for internal)"
}

variable "internal" {
  type        = bool
  default     = false
  description = "Internal ALB (no public IP)"
}

variable "certificate_arn" {
  type        = string
  default     = ""
  description = "ACM certificate ARN for HTTPS"
}

variable "additional_certificates" {
  type        = list(string)
  default     = []
  description = "Additional certificate ARNs for SNI"
}

variable "ssl_policy" {
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  description = "SSL policy for HTTPS listeners"
}

variable "enable_deletion_protection" {
  type        = bool
  default     = true
  description = "Prevent accidental deletion"
}

variable "enable_http2" {
  type        = bool
  default     = true
  description = "Enable HTTP/2"
}

variable "idle_timeout" {
  type        = number
  default     = 60
  description = "Idle timeout in seconds"
}

variable "drop_invalid_header_fields" {
  type        = bool
  default     = true
  description = "Drop requests with invalid headers"
}

variable "access_logs" {
  type = object({
    enabled = bool
    bucket  = string
    prefix  = optional(string, "")
  })
  default = {
    enabled = false
    bucket  = ""
  }
  description = "Access logging configuration"
}

variable "target_groups" {
  type = map(object({
    port                 = number
    protocol             = optional(string, "HTTP")
    target_type          = optional(string, "ip")
    deregistration_delay = optional(number, 30)
    slow_start           = optional(number, 0)
    
    health_check_path     = optional(string, "/")
    health_check_port     = optional(string, "traffic-port")
    health_check_protocol = optional(string, "HTTP")
    health_check_interval = optional(number, 30)
    health_check_timeout  = optional(number, 5)
    healthy_threshold     = optional(number, 2)
    unhealthy_threshold   = optional(number, 3)
    health_check_matcher  = optional(string, "200-299")
    
    stickiness_enabled  = optional(bool, false)
    stickiness_duration = optional(number, 86400)
  }))
  default     = {}
  description = "Target group configurations"
}

variable "listener_rules" {
  type = map(object({
    priority         = number
    target_group_key = string
    
    # Conditions (at least one required)
    host_headers = optional(list(string), [])
    path_patterns = optional(list(string), [])
    http_headers = optional(map(list(string)), {})
    query_strings = optional(map(string), {})
    source_ips = optional(list(string), [])
  }))
  default     = {}
  description = "HTTPS listener rules for routing"
}

variable "waf_arn" {
  type        = string
  default     = ""
  description = "WAF Web ACL ARN to associate"
}

variable "security_group_ids" {
  type        = list(string)
  default     = []
  description = "Additional security group IDs"
}

variable "ingress_cidr_blocks" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "CIDR blocks for ingress (HTTP/HTTPS)"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "ALB security group"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidr_blocks
  }

  ingress {
    description = "HTTP (redirect)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidr_blocks
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.name}-alb" })
}

################################################################################
# Application Load Balancer
################################################################################

resource "aws_lb" "main" {
  name               = var.name
  internal           = var.internal
  load_balancer_type = "application"
  security_groups    = concat([aws_security_group.alb.id], var.security_group_ids)
  subnets            = var.subnet_ids

  enable_deletion_protection = var.enable_deletion_protection
  enable_http2               = var.enable_http2
  idle_timeout               = var.idle_timeout
  drop_invalid_header_fields = var.drop_invalid_header_fields

  dynamic "access_logs" {
    for_each = var.access_logs.enabled ? [1] : []
    content {
      bucket  = var.access_logs.bucket
      prefix  = var.access_logs.prefix
      enabled = true
    }
  }

  tags = merge(var.tags, { Name = var.name })
}

################################################################################
# Target Groups
################################################################################

resource "aws_lb_target_group" "main" {
  for_each = var.target_groups

  name                 = "${var.name}-${each.key}"
  port                 = each.value.port
  protocol             = each.value.protocol
  vpc_id               = var.vpc_id
  target_type          = each.value.target_type
  deregistration_delay = each.value.deregistration_delay
  slow_start           = each.value.slow_start

  health_check {
    enabled             = true
    path                = each.value.health_check_path
    port                = each.value.health_check_port
    protocol            = each.value.health_check_protocol
    interval            = each.value.health_check_interval
    timeout             = each.value.health_check_timeout
    healthy_threshold   = each.value.healthy_threshold
    unhealthy_threshold = each.value.unhealthy_threshold
    matcher             = each.value.health_check_matcher
  }

  dynamic "stickiness" {
    for_each = each.value.stickiness_enabled ? [1] : []
    content {
      type            = "lb_cookie"
      cookie_duration = each.value.stickiness_duration
      enabled         = true
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-${each.key}" })

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# HTTPS Listener
################################################################################

resource "aws_lb_listener" "https" {
  count = var.certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_arn

  default_action {
    type = length(var.target_groups) > 0 ? "forward" : "fixed-response"

    dynamic "forward" {
      for_each = length(var.target_groups) > 0 ? [1] : []
      content {
        target_group {
          arn = aws_lb_target_group.main[keys(var.target_groups)[0]].arn
        }
      }
    }

    dynamic "fixed_response" {
      for_each = length(var.target_groups) == 0 ? [1] : []
      content {
        content_type = "text/plain"
        message_body = "No backend configured"
        status_code  = "503"
      }
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-https" })
}

# Additional certificates (SNI)
resource "aws_lb_listener_certificate" "additional" {
  for_each = toset(var.additional_certificates)

  listener_arn    = aws_lb_listener.https[0].arn
  certificate_arn = each.value
}

################################################################################
# HTTP Listener (Redirect to HTTPS)
################################################################################

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.certificate_arn != "" ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.certificate_arn != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    dynamic "forward" {
      for_each = var.certificate_arn == "" && length(var.target_groups) > 0 ? [1] : []
      content {
        target_group {
          arn = aws_lb_target_group.main[keys(var.target_groups)[0]].arn
        }
      }
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-http" })
}

################################################################################
# Listener Rules
################################################################################

resource "aws_lb_listener_rule" "main" {
  for_each = var.certificate_arn != "" ? var.listener_rules : {}

  listener_arn = aws_lb_listener.https[0].arn
  priority     = each.value.priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main[each.value.target_group_key].arn
  }

  # Host header condition
  dynamic "condition" {
    for_each = length(each.value.host_headers) > 0 ? [1] : []
    content {
      host_header {
        values = each.value.host_headers
      }
    }
  }

  # Path pattern condition
  dynamic "condition" {
    for_each = length(each.value.path_patterns) > 0 ? [1] : []
    content {
      path_pattern {
        values = each.value.path_patterns
      }
    }
  }

  # HTTP header conditions
  dynamic "condition" {
    for_each = each.value.http_headers
    content {
      http_header {
        http_header_name = condition.key
        values           = condition.value
      }
    }
  }

  # Query string conditions
  dynamic "condition" {
    for_each = each.value.query_strings
    content {
      query_string {
        key   = condition.key
        value = condition.value
      }
    }
  }

  # Source IP condition
  dynamic "condition" {
    for_each = length(each.value.source_ips) > 0 ? [1] : []
    content {
      source_ip {
        values = each.value.source_ips
      }
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-${each.key}" })
}

################################################################################
# WAF Association
################################################################################

resource "aws_wafv2_web_acl_association" "main" {
  count = var.waf_arn != "" ? 1 : 0

  resource_arn = aws_lb.main.arn
  web_acl_arn  = var.waf_arn
}

################################################################################
# Outputs
################################################################################

output "arn" {
  value       = aws_lb.main.arn
  description = "ALB ARN"
}

output "arn_suffix" {
  value       = aws_lb.main.arn_suffix
  description = "ALB ARN suffix (for CloudWatch metrics)"
}

output "dns_name" {
  value       = aws_lb.main.dns_name
  description = "ALB DNS name"
}

output "zone_id" {
  value       = aws_lb.main.zone_id
  description = "ALB hosted zone ID"
}

output "security_group_id" {
  value       = aws_security_group.alb.id
  description = "ALB security group ID"
}

output "target_group_arns" {
  value       = { for k, v in aws_lb_target_group.main : k => v.arn }
  description = "Target group ARNs"
}

output "target_group_arn_suffixes" {
  value       = { for k, v in aws_lb_target_group.main : k => v.arn_suffix }
  description = "Target group ARN suffixes"
}

output "https_listener_arn" {
  value       = length(aws_lb_listener.https) > 0 ? aws_lb_listener.https[0].arn : null
  description = "HTTPS listener ARN"
}

output "http_listener_arn" {
  value       = aws_lb_listener.http.arn
  description = "HTTP listener ARN"
}
