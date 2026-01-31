################################################################################
# ACM Certificate Module
#
# SSL/TLS certificates with:
# - DNS or email validation
# - Automatic Route53 validation records
# - SAN (Subject Alternative Names) support
# - Wildcard certificates
#
# Usage:
#   module "cert" {
#     source = "../modules/acm-certificate"
#     
#     domain_name    = "example.com"
#     zone_id        = "Z1234567890"
#     
#     subject_alternative_names = [
#       "*.example.com",
#       "api.example.com"
#     ]
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
  description = "Primary domain name for the certificate"
}

variable "subject_alternative_names" {
  type        = list(string)
  default     = []
  description = "Additional domain names (SANs) for the certificate"
}

variable "zone_id" {
  type        = string
  default     = null
  description = "Route53 zone ID for DNS validation (null for email validation)"
}

variable "validation_method" {
  type        = string
  default     = "DNS"
  description = "Validation method: DNS or EMAIL"

  validation {
    condition     = contains(["DNS", "EMAIL"], var.validation_method)
    error_message = "Must be DNS or EMAIL"
  }
}

variable "wait_for_validation" {
  type        = bool
  default     = true
  description = "Wait for certificate validation to complete"
}

variable "validation_timeout" {
  type        = string
  default     = "45m"
  description = "Timeout for certificate validation"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# ACM Certificate
################################################################################

resource "aws_acm_certificate" "main" {
  domain_name               = var.domain_name
  subject_alternative_names = var.subject_alternative_names
  validation_method         = var.validation_method

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(var.tags, { Name = var.domain_name })
}

################################################################################
# DNS Validation Records
################################################################################

resource "aws_route53_record" "validation" {
  for_each = var.validation_method == "DNS" && var.zone_id != null ? {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.zone_id
}

################################################################################
# Certificate Validation
################################################################################

resource "aws_acm_certificate_validation" "main" {
  count = var.wait_for_validation ? 1 : 0

  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = var.validation_method == "DNS" && var.zone_id != null ? [for record in aws_route53_record.validation : record.fqdn] : null

  timeouts {
    create = var.validation_timeout
  }
}

################################################################################
# Outputs
################################################################################

output "certificate_arn" {
  value       = aws_acm_certificate.main.arn
  description = "ARN of the certificate"
}

output "certificate_domain_name" {
  value       = aws_acm_certificate.main.domain_name
  description = "Primary domain name"
}

output "certificate_status" {
  value       = aws_acm_certificate.main.status
  description = "Certificate status"
}

output "validation_records" {
  value = var.validation_method == "DNS" ? {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  } : null
  description = "DNS validation records (if using DNS validation without auto Route53)"
}

output "validated_certificate_arn" {
  value       = var.wait_for_validation ? aws_acm_certificate_validation.main[0].certificate_arn : aws_acm_certificate.main.arn
  description = "ARN of the validated certificate"
}
