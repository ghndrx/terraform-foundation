################################################################################
# Workload: Static Site (S3 + CloudFront)
# 
# Deploys a static website:
# - S3 bucket for content (private, OAC access only)
# - CloudFront distribution with HTTPS
# - ACM certificate (DNS validation)
# - WAF integration (optional)
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<site-name>/
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
    key = "05-workloads/<TENANT>-<NAME>/terraform.tfstate"
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

  # Domain (leave empty for CloudFront default domain)
  domain_name         = "" # e.g., "www.example.com"
  hosted_zone_id      = "" # Route53 hosted zone ID
  create_certificate  = local.domain_name != ""

  # Content settings
  default_root_object = "index.html"
  error_page_path     = "/error.html"

  # Caching
  default_ttl = 86400   # 1 day
  min_ttl     = 0
  max_ttl     = 31536000 # 1 year

  # Price class
  # PriceClass_100 = US, Canada, Europe (cheapest)
  # PriceClass_200 = Above + Asia, Africa, Middle East
  # PriceClass_All = All edge locations
  price_class = "PriceClass_100"

  # WAF (set to WAF web ACL ARN to enable)
  waf_web_acl_arn = ""

  # Logging
  enable_logging = true
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

# ACM certificates must be in us-east-1 for CloudFront
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

################################################################################
# Data Sources
################################################################################

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
# S3 Bucket
################################################################################

resource "aws_s3_bucket" "site" {
  bucket = "${local.tenant}-${local.name}-${local.env}-${data.aws_caller_identity.current.account_id}"

  tags = { Name = "${local.tenant}-${local.name}" }
}

resource "aws_s3_bucket_versioning" "site" {
  bucket = aws_s3_bucket.site.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "site" {
  bucket = aws_s3_bucket.site.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket = aws_s3_bucket.site.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy for CloudFront OAC
resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontOAC"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.site.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.site.arn
          }
        }
      }
    ]
  })
}

################################################################################
# CloudFront Origin Access Control
################################################################################

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${local.tenant}-${local.name}"
  description                       = "OAC for ${local.tenant}-${local.name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

################################################################################
# ACM Certificate (if custom domain)
################################################################################

resource "aws_acm_certificate" "site" {
  count    = local.create_certificate ? 1 : 0
  provider = aws.us_east_1

  domain_name       = local.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${local.tenant}-${local.name}" }
}

resource "aws_route53_record" "cert_validation" {
  for_each = local.create_certificate ? {
    for dvo in aws_acm_certificate.site[0].domain_validation_options : dvo.domain_name => {
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
  zone_id         = local.hosted_zone_id
}

resource "aws_acm_certificate_validation" "site" {
  count    = local.create_certificate ? 1 : 0
  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.site[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

################################################################################
# CloudFront Logging Bucket
################################################################################

resource "aws_s3_bucket" "logs" {
  count  = local.enable_logging ? 1 : 0
  bucket = "${local.tenant}-${local.name}-logs-${data.aws_caller_identity.current.account_id}"

  tags = { Name = "${local.tenant}-${local.name}-logs" }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = local.enable_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  count      = local.enable_logging ? 1 : 0
  depends_on = [aws_s3_bucket_ownership_controls.logs]
  bucket     = aws_s3_bucket.logs[0].id
  acl        = "private"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = local.enable_logging ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "cleanup"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

################################################################################
# CloudFront Distribution
################################################################################

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = local.default_root_object
  price_class         = local.price_class
  comment             = "${local.tenant} ${local.name} static site"

  aliases = local.create_certificate ? [local.domain_name] : []

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "S3-${aws_s3_bucket.site.id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${aws_s3_bucket.site.id}"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    min_ttl     = local.min_ttl
    default_ttl = local.default_ttl
    max_ttl     = local.max_ttl

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    # Security headers
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
  }

  # Custom error pages
  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = local.error_page_path
    error_caching_min_ttl = 60
  }

  custom_error_response {
    error_code            = 403
    response_code         = 404
    response_page_path    = local.error_page_path
    error_caching_min_ttl = 60
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn            = local.create_certificate ? aws_acm_certificate.site[0].arn : null
    ssl_support_method             = local.create_certificate ? "sni-only" : null
    minimum_protocol_version       = local.create_certificate ? "TLSv1.2_2021" : null
    cloudfront_default_certificate = !local.create_certificate
  }

  dynamic "logging_config" {
    for_each = local.enable_logging ? [1] : []
    content {
      bucket          = aws_s3_bucket.logs[0].bucket_domain_name
      include_cookies = false
      prefix          = "cloudfront/"
    }
  }

  web_acl_id = local.waf_web_acl_arn != "" ? local.waf_web_acl_arn : null

  tags = { Name = "${local.tenant}-${local.name}" }
}

################################################################################
# Security Headers Policy
################################################################################

resource "aws_cloudfront_response_headers_policy" "security" {
  name    = "${local.tenant}-${local.name}-security"
  comment = "Security headers for ${local.tenant}-${local.name}"

  security_headers_config {
    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    strict_transport_security {
      access_control_max_age_sec = 31536000 # 1 year
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }

    content_security_policy {
      content_security_policy = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'"
      override                = true
    }
  }
}

################################################################################
# Route53 Record (if custom domain)
################################################################################

resource "aws_route53_record" "site" {
  count = local.create_certificate ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = local.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

################################################################################
# Outputs
################################################################################

output "bucket_name" {
  value = aws_s3_bucket.site.id
}

output "bucket_arn" {
  value = aws_s3_bucket.site.arn
}

output "distribution_id" {
  value = aws_cloudfront_distribution.site.id
}

output "distribution_domain" {
  value = aws_cloudfront_distribution.site.domain_name
}

output "site_url" {
  value = local.create_certificate ? "https://${local.domain_name}" : "https://${aws_cloudfront_distribution.site.domain_name}"
}

output "deploy_command" {
  value       = "aws s3 sync ./dist s3://${aws_s3_bucket.site.id} --delete && aws cloudfront create-invalidation --distribution-id ${aws_cloudfront_distribution.site.id} --paths '/*'"
  description = "Command to deploy content"
}
