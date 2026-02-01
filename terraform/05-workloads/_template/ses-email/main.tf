################################################################################
# Workload: SES Email Configuration
# 
# Email sending infrastructure:
# - Domain identity with DKIM
# - Email identities for sending
# - Configuration sets with tracking
# - Event destinations (CloudWatch, SNS, Kinesis)
# - Dedicated IP pools (optional)
# - Suppression list management
#
# Use cases: Transactional email, marketing campaigns, notifications
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
    key = "05-workloads/<TENANT>-<NAME>-email/terraform.tfstate"
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
  
  config_name = "${local.tenant}-${local.name}-${local.env}"

  # Domain to verify (required)
  domain         = "example.com"
  hosted_zone_id = null # Route53 zone ID for automatic DNS verification

  # Additional email identities
  email_identities = [
    # "noreply@example.com",
    # "support@example.com",
  ]

  # MAIL FROM domain (optional custom subdomain)
  mail_from_subdomain = "mail" # Results in mail.example.com

  # DMARC record
  enable_dmarc = true
  dmarc_policy = "none" # none, quarantine, reject
  dmarc_rua    = null   # Aggregate report email, e.g., "mailto:dmarc@example.com"

  # Configuration set (for tracking)
  enable_config_set = true

  # Event tracking
  tracking_options = {
    click    = true
    open     = true
    bounce   = true
    complaint = true
    delivery  = true
    reject    = true
    send      = true
  }

  # Event destinations
  cloudwatch_destination = true
  sns_destination        = true

  # Reputation metrics
  reputation_metrics_enabled = true

  # Sending quotas (request increase via AWS support)
  # These are informational - actual limits set by AWS
  
  # Suppression list
  suppression_list_reasons = ["BOUNCE", "COMPLAINT"]

  # Dedicated IPs (additional cost)
  enable_dedicated_ips = false
  dedicated_ip_count   = 0

  # IAM policy for sending
  create_sending_role = true
  sending_role_name   = "${local.config_name}-ses-sender"
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
# Domain Identity
################################################################################

resource "aws_ses_domain_identity" "main" {
  domain = local.domain
}

resource "aws_ses_domain_dkim" "main" {
  domain = aws_ses_domain_identity.main.domain
}

################################################################################
# DNS Records (if hosted zone provided)
################################################################################

# Domain verification
resource "aws_route53_record" "ses_verification" {
  count   = local.hosted_zone_id != null ? 1 : 0
  zone_id = local.hosted_zone_id
  name    = "_amazonses.${local.domain}"
  type    = "TXT"
  ttl     = 600
  records = [aws_ses_domain_identity.main.verification_token]
}

# DKIM records
resource "aws_route53_record" "dkim" {
  count   = local.hosted_zone_id != null ? 3 : 0
  zone_id = local.hosted_zone_id
  name    = "${aws_ses_domain_dkim.main.dkim_tokens[count.index]}._domainkey.${local.domain}"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_ses_domain_dkim.main.dkim_tokens[count.index]}.dkim.amazonses.com"]
}

# MAIL FROM domain
resource "aws_ses_domain_mail_from" "main" {
  domain           = aws_ses_domain_identity.main.domain
  mail_from_domain = "${local.mail_from_subdomain}.${local.domain}"
}

resource "aws_route53_record" "mail_from_mx" {
  count   = local.hosted_zone_id != null ? 1 : 0
  zone_id = local.hosted_zone_id
  name    = "${local.mail_from_subdomain}.${local.domain}"
  type    = "MX"
  ttl     = 600
  records = ["10 feedback-smtp.${data.aws_region.current.name}.amazonses.com"]
}

resource "aws_route53_record" "mail_from_spf" {
  count   = local.hosted_zone_id != null ? 1 : 0
  zone_id = local.hosted_zone_id
  name    = "${local.mail_from_subdomain}.${local.domain}"
  type    = "TXT"
  ttl     = 600
  records = ["v=spf1 include:amazonses.com ~all"]
}

# DMARC record
resource "aws_route53_record" "dmarc" {
  count   = local.hosted_zone_id != null && local.enable_dmarc ? 1 : 0
  zone_id = local.hosted_zone_id
  name    = "_dmarc.${local.domain}"
  type    = "TXT"
  ttl     = 600
  records = [
    local.dmarc_rua != null 
      ? "v=DMARC1; p=${local.dmarc_policy}; rua=${local.dmarc_rua}"
      : "v=DMARC1; p=${local.dmarc_policy}"
  ]
}

################################################################################
# Email Identities
################################################################################

resource "aws_ses_email_identity" "identities" {
  for_each = toset(local.email_identities)
  email    = each.value
}

################################################################################
# Configuration Set
################################################################################

resource "aws_ses_configuration_set" "main" {
  count = local.enable_config_set ? 1 : 0
  name  = local.config_name

  reputation_metrics_enabled = local.reputation_metrics_enabled

  delivery_options {
    tls_policy = "REQUIRE"
  }

  tracking_options {
    custom_redirect_domain = null
  }
}

################################################################################
# SNS Topic for Events
################################################################################

resource "aws_sns_topic" "ses_events" {
  count             = local.sns_destination ? 1 : 0
  name              = "${local.config_name}-ses-events"
  kms_master_key_id = "alias/aws/sns"

  tags = { Name = "${local.config_name}-ses-events" }
}

resource "aws_sns_topic_policy" "ses_events" {
  count  = local.sns_destination ? 1 : 0
  arn    = aws_sns_topic.ses_events[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowSES"
      Effect = "Allow"
      Principal = {
        Service = "ses.amazonaws.com"
      }
      Action   = "sns:Publish"
      Resource = aws_sns_topic.ses_events[0].arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

################################################################################
# Event Destinations
################################################################################

resource "aws_ses_event_destination" "cloudwatch" {
  count                  = local.enable_config_set && local.cloudwatch_destination ? 1 : 0
  name                   = "cloudwatch"
  configuration_set_name = aws_ses_configuration_set.main[0].name
  enabled                = true

  matching_types = compact([
    local.tracking_options.bounce ? "bounce" : "",
    local.tracking_options.complaint ? "complaint" : "",
    local.tracking_options.delivery ? "delivery" : "",
    local.tracking_options.send ? "send" : "",
    local.tracking_options.reject ? "reject" : "",
    local.tracking_options.open ? "open" : "",
    local.tracking_options.click ? "click" : "",
  ])

  cloudwatch_destination {
    default_value  = "default"
    dimension_name = "ses:source-ip"
    value_source   = "messageTag"
  }
}

resource "aws_ses_event_destination" "sns" {
  count                  = local.enable_config_set && local.sns_destination ? 1 : 0
  name                   = "sns"
  configuration_set_name = aws_ses_configuration_set.main[0].name
  enabled                = true

  matching_types = ["bounce", "complaint"]

  sns_destination {
    topic_arn = aws_sns_topic.ses_events[0].arn
  }
}

################################################################################
# IAM Role for Sending
################################################################################

resource "aws_iam_role" "sending" {
  count = local.create_sending_role ? 1 : 0
  name  = local.sending_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = [
          "lambda.amazonaws.com",
          "ecs-tasks.amazonaws.com",
          "ec2.amazonaws.com"
        ]
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = { Name = local.sending_role_name }
}

resource "aws_iam_role_policy" "sending" {
  count = local.create_sending_role ? 1 : 0
  name  = "ses-sending"
  role  = aws_iam_role.sending[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SendEmail"
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail",
          "ses:SendTemplatedEmail",
          "ses:SendBulkTemplatedEmail"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ses:FromAddress" = [for e in local.email_identities : e]
          }
        }
      },
      {
        Sid    = "UseConfigSet"
        Effect = "Allow"
        Action = ["ses:SendEmail", "ses:SendRawEmail"]
        Resource = local.enable_config_set ? aws_ses_configuration_set.main[0].arn : "*"
      }
    ]
  })
}

################################################################################
# SMTP Credentials (for apps that use SMTP)
################################################################################

resource "aws_iam_user" "smtp" {
  name = "${local.config_name}-smtp"
  tags = { Name = "${local.config_name}-smtp" }
}

resource "aws_iam_user_policy" "smtp" {
  name = "ses-smtp"
  user = aws_iam_user.smtp.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "ses:SendRawEmail"
      Resource = "*"
    }]
  })
}

resource "aws_iam_access_key" "smtp" {
  user = aws_iam_user.smtp.name
}

################################################################################
# Email Templates (Examples)
################################################################################

resource "aws_ses_template" "welcome" {
  name    = "${local.config_name}-welcome"
  subject = "Welcome to {{company_name}}!"
  html    = <<-HTML
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body>
      <h1>Welcome, {{name}}!</h1>
      <p>Thank you for signing up for {{company_name}}.</p>
      <p>Click <a href="{{verification_link}}">here</a> to verify your email.</p>
    </body>
    </html>
  HTML
  text    = <<-TEXT
    Welcome, {{name}}!
    
    Thank you for signing up for {{company_name}}.
    
    Click the link below to verify your email:
    {{verification_link}}
  TEXT
}

resource "aws_ses_template" "password_reset" {
  name    = "${local.config_name}-password-reset"
  subject = "Reset your {{company_name}} password"
  html    = <<-HTML
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body>
      <h1>Password Reset Request</h1>
      <p>Hi {{name}},</p>
      <p>Click <a href="{{reset_link}}">here</a> to reset your password.</p>
      <p>This link expires in {{expiry_hours}} hours.</p>
      <p>If you didn't request this, please ignore this email.</p>
    </body>
    </html>
  HTML
  text    = <<-TEXT
    Password Reset Request
    
    Hi {{name}},
    
    Click the link below to reset your password:
    {{reset_link}}
    
    This link expires in {{expiry_hours}} hours.
    
    If you didn't request this, please ignore this email.
  TEXT
}

################################################################################
# Outputs
################################################################################

output "domain_identity_arn" {
  value = aws_ses_domain_identity.main.arn
}

output "domain_verification_token" {
  value = aws_ses_domain_identity.main.verification_token
}

output "dkim_tokens" {
  value = aws_ses_domain_dkim.main.dkim_tokens
}

output "configuration_set" {
  value = local.enable_config_set ? aws_ses_configuration_set.main[0].name : null
}

output "sns_topic_arn" {
  value = local.sns_destination ? aws_sns_topic.ses_events[0].arn : null
}

output "sending_role_arn" {
  value = local.create_sending_role ? aws_iam_role.sending[0].arn : null
}

output "smtp_credentials" {
  value = {
    username = aws_iam_access_key.smtp.id
    password = aws_iam_access_key.smtp.ses_smtp_password_v4
    endpoint = "email-smtp.${data.aws_region.current.name}.amazonaws.com"
    port     = 587
  }
  sensitive = true
}

output "dns_records_required" {
  value = local.hosted_zone_id == null ? {
    verification = {
      name  = "_amazonses.${local.domain}"
      type  = "TXT"
      value = aws_ses_domain_identity.main.verification_token
    }
    dkim = [
      for i, token in aws_ses_domain_dkim.main.dkim_tokens : {
        name  = "${token}._domainkey.${local.domain}"
        type  = "CNAME"
        value = "${token}.dkim.amazonses.com"
      }
    ]
    mail_from_mx = {
      name  = "${local.mail_from_subdomain}.${local.domain}"
      type  = "MX"
      value = "10 feedback-smtp.${data.aws_region.current.name}.amazonses.com"
    }
    mail_from_spf = {
      name  = "${local.mail_from_subdomain}.${local.domain}"
      type  = "TXT"
      value = "v=spf1 include:amazonses.com ~all"
    }
  } : "DNS records created automatically"
}

output "templates" {
  value = {
    welcome        = aws_ses_template.welcome.name
    password_reset = aws_ses_template.password_reset.name
  }
}
