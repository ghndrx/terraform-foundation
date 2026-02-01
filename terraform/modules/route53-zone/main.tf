################################################################################
# Route53 Zone Module
#
# DNS zone management:
# - Public or private hosted zones
# - Common record types (A, AAAA, CNAME, MX, TXT)
# - Alias records (CloudFront, ALB, S3, API Gateway)
# - DNSSEC signing
# - Query logging
# - Health checks
#
# Usage:
#   module "dns" {
#     source = "../modules/route53-zone"
#     
#     domain_name = "example.com"
#     
#     records = {
#       "www" = {
#         type    = "CNAME"
#         ttl     = 300
#         records = ["example.com"]
#       }
#       "mail" = {
#         type    = "MX"
#         ttl     = 300
#         records = ["10 mail.example.com"]
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

variable "domain_name" {
  type        = string
  description = "Domain name for the hosted zone"
}

variable "comment" {
  type        = string
  default     = ""
  description = "Comment for the hosted zone"
}

variable "private_zone" {
  type        = bool
  default     = false
  description = "Create a private hosted zone"
}

variable "vpc_ids" {
  type        = list(string)
  default     = []
  description = "VPC IDs to associate with private zone"
}

variable "enable_dnssec" {
  type        = bool
  default     = false
  description = "Enable DNSSEC signing"
}

variable "enable_query_logging" {
  type        = bool
  default     = false
  description = "Enable query logging to CloudWatch"
}

variable "query_log_retention_days" {
  type        = number
  default     = 30
  description = "Query log retention in days"
}

variable "records" {
  type = map(object({
    type    = string
    ttl     = optional(number, 300)
    records = optional(list(string))
    alias = optional(object({
      name                   = string
      zone_id                = string
      evaluate_target_health = optional(bool, false)
    }))
    health_check_id = optional(string)
    set_identifier  = optional(string)
    weight          = optional(number)
    latency_routing_region = optional(string)
    geolocation = optional(object({
      continent   = optional(string)
      country     = optional(string)
      subdivision = optional(string)
    }))
    failover = optional(string)
  }))
  default     = {}
  description = "DNS records to create"
}

variable "alias_records" {
  type = map(object({
    type                   = optional(string, "A")
    target_dns_name        = string
    target_zone_id         = string
    evaluate_target_health = optional(bool, false)
  }))
  default     = {}
  description = "Alias records (simplified syntax for CloudFront, ALB, etc.)"
}

variable "mx_records" {
  type = list(object({
    priority = number
    server   = string
  }))
  default     = []
  description = "MX records for email"
}

variable "txt_records" {
  type        = map(string)
  default     = {}
  description = "TXT records (name -> value)"
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_region" "current" {}

################################################################################
# Hosted Zone
################################################################################

resource "aws_route53_zone" "main" {
  name    = var.domain_name
  comment = var.comment != "" ? var.comment : "Managed by Terraform"

  dynamic "vpc" {
    for_each = var.private_zone ? var.vpc_ids : []
    content {
      vpc_id = vpc.value
    }
  }

  tags = merge(var.tags, { Name = var.domain_name })
}

################################################################################
# Standard Records
################################################################################

resource "aws_route53_record" "records" {
  for_each = var.records

  zone_id = aws_route53_zone.main.zone_id
  name    = each.key == "@" ? var.domain_name : "${each.key}.${var.domain_name}"
  type    = each.value.type

  # Standard records
  ttl     = each.value.alias == null ? each.value.ttl : null
  records = each.value.alias == null ? each.value.records : null

  # Alias records
  dynamic "alias" {
    for_each = each.value.alias != null ? [each.value.alias] : []
    content {
      name                   = alias.value.name
      zone_id                = alias.value.zone_id
      evaluate_target_health = alias.value.evaluate_target_health
    }
  }

  # Routing policies
  health_check_id = each.value.health_check_id
  set_identifier  = each.value.set_identifier

  dynamic "weighted_routing_policy" {
    for_each = each.value.weight != null ? [1] : []
    content {
      weight = each.value.weight
    }
  }

  dynamic "latency_routing_policy" {
    for_each = each.value.latency_routing_region != null ? [1] : []
    content {
      region = each.value.latency_routing_region
    }
  }

  dynamic "geolocation_routing_policy" {
    for_each = each.value.geolocation != null ? [each.value.geolocation] : []
    content {
      continent   = geolocation_routing_policy.value.continent
      country     = geolocation_routing_policy.value.country
      subdivision = geolocation_routing_policy.value.subdivision
    }
  }

  dynamic "failover_routing_policy" {
    for_each = each.value.failover != null ? [1] : []
    content {
      type = each.value.failover
    }
  }
}

################################################################################
# Simplified Alias Records
################################################################################

resource "aws_route53_record" "alias" {
  for_each = var.alias_records

  zone_id = aws_route53_zone.main.zone_id
  name    = each.key == "@" ? var.domain_name : "${each.key}.${var.domain_name}"
  type    = each.value.type

  alias {
    name                   = each.value.target_dns_name
    zone_id                = each.value.target_zone_id
    evaluate_target_health = each.value.evaluate_target_health
  }
}

################################################################################
# MX Records
################################################################################

resource "aws_route53_record" "mx" {
  count = length(var.mx_records) > 0 ? 1 : 0

  zone_id = aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "MX"
  ttl     = 300

  records = [for mx in var.mx_records : "${mx.priority} ${mx.server}"]
}

################################################################################
# TXT Records
################################################################################

resource "aws_route53_record" "txt" {
  for_each = var.txt_records

  zone_id = aws_route53_zone.main.zone_id
  name    = each.key == "@" ? var.domain_name : "${each.key}.${var.domain_name}"
  type    = "TXT"
  ttl     = 300
  records = [each.value]
}

################################################################################
# DNSSEC
################################################################################

resource "aws_route53_key_signing_key" "main" {
  count = var.enable_dnssec && !var.private_zone ? 1 : 0

  hosted_zone_id             = aws_route53_zone.main.id
  key_management_service_arn = aws_kms_key.dnssec[0].arn
  name                       = "${replace(var.domain_name, ".", "-")}-ksk"
}

resource "aws_kms_key" "dnssec" {
  count = var.enable_dnssec && !var.private_zone ? 1 : 0

  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 7
  key_usage                = "SIGN_VERIFY"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Route 53 DNSSEC Service"
        Effect = "Allow"
        Principal = {
          Service = "dnssec-route53.amazonaws.com"
        }
        Action = [
          "kms:DescribeKey",
          "kms:GetPublicKey",
          "kms:Sign"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:route53:::hostedzone/*"
          }
        }
      },
      {
        Sid    = "Allow Route 53 DNSSEC to CreateGrant"
        Effect = "Allow"
        Principal = {
          Service = "dnssec-route53.amazonaws.com"
        }
        Action   = "kms:CreateGrant"
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.domain_name}-dnssec" })
}

data "aws_caller_identity" "current" {}

resource "aws_route53_hosted_zone_dnssec" "main" {
  count = var.enable_dnssec && !var.private_zone ? 1 : 0

  hosted_zone_id = aws_route53_zone.main.id

  depends_on = [aws_route53_key_signing_key.main]
}

################################################################################
# Query Logging
################################################################################

resource "aws_cloudwatch_log_group" "query_log" {
  count = var.enable_query_logging && !var.private_zone ? 1 : 0

  name              = "/aws/route53/${var.domain_name}"
  retention_in_days = var.query_log_retention_days

  tags = merge(var.tags, { Name = var.domain_name })
}

resource "aws_cloudwatch_log_resource_policy" "query_log" {
  count = var.enable_query_logging && !var.private_zone ? 1 : 0

  policy_name = "route53-query-logging-${replace(var.domain_name, ".", "-")}"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "route53.amazonaws.com"
      }
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.query_log[0].arn}:*"
    }]
  })
}

resource "aws_route53_query_log" "main" {
  count = var.enable_query_logging && !var.private_zone ? 1 : 0

  cloudwatch_log_group_arn = aws_cloudwatch_log_group.query_log[0].arn
  zone_id                  = aws_route53_zone.main.zone_id

  depends_on = [aws_cloudwatch_log_resource_policy.query_log]
}

################################################################################
# Outputs
################################################################################

output "zone_id" {
  value       = aws_route53_zone.main.zone_id
  description = "Hosted zone ID"
}

output "zone_arn" {
  value       = aws_route53_zone.main.arn
  description = "Hosted zone ARN"
}

output "name_servers" {
  value       = aws_route53_zone.main.name_servers
  description = "Name servers for the zone (update at registrar)"
}

output "domain_name" {
  value       = var.domain_name
  description = "Domain name"
}

output "dnssec_ds_record" {
  value       = var.enable_dnssec && !var.private_zone ? aws_route53_key_signing_key.main[0].ds_record : null
  description = "DS record for DNSSEC (add to parent zone/registrar)"
}
