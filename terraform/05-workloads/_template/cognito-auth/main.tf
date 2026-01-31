################################################################################
# Workload: Cognito User Pool
# 
# User authentication infrastructure:
# - User Pool with customizable password policy
# - App clients (web, mobile, machine-to-machine)
# - Identity Pool for AWS credential federation
# - Social/SAML/OIDC identity providers
# - Custom domain
# - Lambda triggers (pre/post auth, migration)
#
# Use cases: Web/mobile auth, B2C apps, admin portals
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
    key = "05-workloads/<TENANT>-<NAME>-auth/terraform.tfstate"
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
  
  pool_name = "${local.tenant}-${local.name}-${local.env}"

  # Email configuration
  email_sending_account = "COGNITO_DEFAULT" # COGNITO_DEFAULT or DEVELOPER
  ses_email_from        = null              # Required if DEVELOPER

  # Password policy
  password_minimum_length    = 12
  password_require_lowercase = true
  password_require_numbers   = true
  password_require_symbols   = true
  password_require_uppercase = true
  temporary_password_validity_days = 7

  # MFA
  mfa_configuration = "OPTIONAL" # OFF, ON, OPTIONAL
  mfa_methods       = ["SOFTWARE_TOKEN_MFA"] # SOFTWARE_TOKEN_MFA, SMS_MFA

  # Account recovery
  recovery_mechanisms = [
    { name = "verified_email", priority = 1 },
    { name = "verified_phone_number", priority = 2 }
  ]

  # User attributes
  auto_verified_attributes = ["email"]
  username_attributes      = ["email"] # email, phone_number
  alias_attributes         = []        # email, phone_number, preferred_username

  # Custom attributes
  custom_attributes = {
    # "tenant_id" = {
    #   type      = "String"
    #   mutable   = false
    #   min_length = 1
    #   max_length = 50
    # }
  }

  # App clients
  app_clients = {
    web = {
      generate_secret                      = false
      explicit_auth_flows                  = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
      supported_identity_providers         = ["COGNITO"]
      callback_urls                        = ["https://example.com/callback"]
      logout_urls                          = ["https://example.com/logout"]
      allowed_oauth_flows                  = ["code"]
      allowed_oauth_scopes                 = ["email", "openid", "profile"]
      allowed_oauth_flows_user_pool_client = true
      access_token_validity                = 60  # minutes
      id_token_validity                    = 60
      refresh_token_validity               = 30  # days
    }
    mobile = {
      generate_secret                      = false
      explicit_auth_flows                  = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
      supported_identity_providers         = ["COGNITO"]
      callback_urls                        = ["myapp://callback"]
      logout_urls                          = ["myapp://logout"]
      allowed_oauth_flows                  = ["code"]
      allowed_oauth_scopes                 = ["email", "openid", "profile"]
      allowed_oauth_flows_user_pool_client = true
      access_token_validity                = 60
      id_token_validity                    = 60
      refresh_token_validity               = 30
    }
    # m2m = {
    #   generate_secret                      = true
    #   explicit_auth_flows                  = ["ALLOW_ADMIN_USER_PASSWORD_AUTH"]
    #   supported_identity_providers         = ["COGNITO"]
    #   allowed_oauth_flows                  = ["client_credentials"]
    #   allowed_oauth_scopes                 = ["api/read", "api/write"]
    #   allowed_oauth_flows_user_pool_client = true
    # }
  }

  # Custom domain (requires ACM cert in us-east-1 for CloudFront)
  custom_domain       = null # e.g., "auth.example.com"
  custom_domain_cert  = null # ACM certificate ARN
  hosted_zone_id      = null

  # Identity Pool (for AWS credential federation)
  enable_identity_pool = false

  # Lambda triggers
  lambda_triggers = {
    # pre_sign_up          = "arn:aws:lambda:..."
    # post_confirmation    = "arn:aws:lambda:..."
    # pre_authentication   = "arn:aws:lambda:..."
    # post_authentication  = "arn:aws:lambda:..."
    # pre_token_generation = "arn:aws:lambda:..."
    # user_migration       = "arn:aws:lambda:..."
    # custom_message       = "arn:aws:lambda:..."
  }

  # Social identity providers
  social_providers = {
    # google = {
    #   client_id     = "..."
    #   client_secret = "..."
    #   scopes        = ["email", "profile", "openid"]
    # }
    # facebook = {
    #   client_id     = "..."
    #   client_secret = "..."
    #   scopes        = ["email", "public_profile"]
    # }
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
# Cognito User Pool
################################################################################

resource "aws_cognito_user_pool" "main" {
  name = local.pool_name

  # Username configuration
  username_attributes      = local.username_attributes
  alias_attributes         = length(local.alias_attributes) > 0 ? local.alias_attributes : null
  auto_verified_attributes = local.auto_verified_attributes

  # Password policy
  password_policy {
    minimum_length                   = local.password_minimum_length
    require_lowercase                = local.password_require_lowercase
    require_numbers                  = local.password_require_numbers
    require_symbols                  = local.password_require_symbols
    require_uppercase                = local.password_require_uppercase
    temporary_password_validity_days = local.temporary_password_validity_days
  }

  # MFA
  mfa_configuration = local.mfa_configuration

  dynamic "software_token_mfa_configuration" {
    for_each = contains(local.mfa_methods, "SOFTWARE_TOKEN_MFA") && local.mfa_configuration != "OFF" ? [1] : []
    content {
      enabled = true
    }
  }

  # Account recovery
  account_recovery_setting {
    dynamic "recovery_mechanism" {
      for_each = local.recovery_mechanisms
      content {
        name     = recovery_mechanism.value.name
        priority = recovery_mechanism.value.priority
      }
    }
  }

  # Email configuration
  email_configuration {
    email_sending_account = local.email_sending_account
    source_arn            = local.email_sending_account == "DEVELOPER" ? local.ses_email_from : null
  }

  # User attribute verification
  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  # Admin create user config
  admin_create_user_config {
    allow_admin_create_user_only = false
    
    invite_message_template {
      email_subject = "Your ${local.pool_name} account"
      email_message = "Your username is {username} and temporary password is {####}"
      sms_message   = "Your username is {username} and temporary password is {####}"
    }
  }

  # Verification message
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "Verify your email for ${local.pool_name}"
    email_message        = "Your verification code is {####}"
  }

  # Schema (custom attributes)
  dynamic "schema" {
    for_each = local.custom_attributes
    content {
      name                     = schema.key
      attribute_data_type      = schema.value.type
      mutable                  = schema.value.mutable
      required                 = false
      developer_only_attribute = false

      dynamic "string_attribute_constraints" {
        for_each = schema.value.type == "String" ? [1] : []
        content {
          min_length = lookup(schema.value, "min_length", 0)
          max_length = lookup(schema.value, "max_length", 2048)
        }
      }

      dynamic "number_attribute_constraints" {
        for_each = schema.value.type == "Number" ? [1] : []
        content {
          min_value = lookup(schema.value, "min_value", null)
          max_value = lookup(schema.value, "max_value", null)
        }
      }
    }
  }

  # Lambda triggers
  lambda_config {
    pre_sign_up                    = lookup(local.lambda_triggers, "pre_sign_up", null)
    post_confirmation              = lookup(local.lambda_triggers, "post_confirmation", null)
    pre_authentication             = lookup(local.lambda_triggers, "pre_authentication", null)
    post_authentication            = lookup(local.lambda_triggers, "post_authentication", null)
    pre_token_generation           = lookup(local.lambda_triggers, "pre_token_generation", null)
    user_migration                 = lookup(local.lambda_triggers, "user_migration", null)
    custom_message                 = lookup(local.lambda_triggers, "custom_message", null)
  }

  tags = { Name = local.pool_name }
}

################################################################################
# User Pool Domain
################################################################################

resource "aws_cognito_user_pool_domain" "main" {
  domain          = local.custom_domain != null ? local.custom_domain : local.pool_name
  user_pool_id    = aws_cognito_user_pool.main.id
  certificate_arn = local.custom_domain_cert
}

# Route53 record for custom domain
resource "aws_route53_record" "cognito" {
  count   = local.custom_domain != null ? 1 : 0
  zone_id = local.hosted_zone_id
  name    = local.custom_domain
  type    = "A"

  alias {
    name                   = aws_cognito_user_pool_domain.main.cloudfront_distribution_arn
    zone_id                = "Z2FDTNDATAQYW2" # CloudFront zone ID
    evaluate_target_health = false
  }
}

################################################################################
# App Clients
################################################################################

resource "aws_cognito_user_pool_client" "clients" {
  for_each = local.app_clients

  name         = "${local.pool_name}-${each.key}"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret                      = each.value.generate_secret
  explicit_auth_flows                  = each.value.explicit_auth_flows
  supported_identity_providers         = each.value.supported_identity_providers
  callback_urls                        = lookup(each.value, "callback_urls", null)
  logout_urls                          = lookup(each.value, "logout_urls", null)
  allowed_oauth_flows                  = lookup(each.value, "allowed_oauth_flows", null)
  allowed_oauth_scopes                 = lookup(each.value, "allowed_oauth_scopes", null)
  allowed_oauth_flows_user_pool_client = lookup(each.value, "allowed_oauth_flows_user_pool_client", false)

  access_token_validity  = lookup(each.value, "access_token_validity", 60)
  id_token_validity      = lookup(each.value, "id_token_validity", 60)
  refresh_token_validity = lookup(each.value, "refresh_token_validity", 30)

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true
}

################################################################################
# Social Identity Providers
################################################################################

resource "aws_cognito_identity_provider" "google" {
  count         = contains(keys(local.social_providers), "google") ? 1 : 0
  user_pool_id  = aws_cognito_user_pool.main.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id        = local.social_providers.google.client_id
    client_secret    = local.social_providers.google.client_secret
    authorize_scopes = join(" ", local.social_providers.google.scopes)
  }

  attribute_mapping = {
    email    = "email"
    username = "sub"
  }
}

resource "aws_cognito_identity_provider" "facebook" {
  count         = contains(keys(local.social_providers), "facebook") ? 1 : 0
  user_pool_id  = aws_cognito_user_pool.main.id
  provider_name = "Facebook"
  provider_type = "Facebook"

  provider_details = {
    client_id        = local.social_providers.facebook.client_id
    client_secret    = local.social_providers.facebook.client_secret
    authorize_scopes = join(",", local.social_providers.facebook.scopes)
  }

  attribute_mapping = {
    email    = "email"
    username = "id"
  }
}

################################################################################
# Identity Pool (Optional)
################################################################################

resource "aws_cognito_identity_pool" "main" {
  count                            = local.enable_identity_pool ? 1 : 0
  identity_pool_name               = replace(local.pool_name, "-", "_")
  allow_unauthenticated_identities = false

  cognito_identity_providers {
    client_id               = aws_cognito_user_pool_client.clients["web"].id
    provider_name           = aws_cognito_user_pool.main.endpoint
    server_side_token_check = true
  }

  tags = { Name = local.pool_name }
}

resource "aws_iam_role" "authenticated" {
  count = local.enable_identity_pool ? 1 : 0
  name  = "${local.pool_name}-authenticated"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = "cognito-identity.amazonaws.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.main[0].id
        }
        "ForAnyValue:StringLike" = {
          "cognito-identity.amazonaws.com:amr" = "authenticated"
        }
      }
    }]
  })

  tags = { Name = "${local.pool_name}-authenticated" }
}

resource "aws_iam_role_policy" "authenticated" {
  count = local.enable_identity_pool ? 1 : 0
  name  = "authenticated-policy"
  role  = aws_iam_role.authenticated[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
  count            = local.enable_identity_pool ? 1 : 0
  identity_pool_id = aws_cognito_identity_pool.main[0].id

  roles = {
    authenticated = aws_iam_role.authenticated[0].arn
  }
}

################################################################################
# Outputs
################################################################################

output "user_pool_id" {
  value = aws_cognito_user_pool.main.id
}

output "user_pool_arn" {
  value = aws_cognito_user_pool.main.arn
}

output "user_pool_endpoint" {
  value = aws_cognito_user_pool.main.endpoint
}

output "user_pool_domain" {
  value = local.custom_domain != null ? "https://${local.custom_domain}" : "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.name}.amazoncognito.com"
}

output "client_ids" {
  value = { for k, v in aws_cognito_user_pool_client.clients : k => v.id }
}

output "identity_pool_id" {
  value = local.enable_identity_pool ? aws_cognito_identity_pool.main[0].id : null
}

output "hosted_ui_url" {
  value = "${local.custom_domain != null ? "https://${local.custom_domain}" : "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.name}.amazoncognito.com"}/login?client_id=${aws_cognito_user_pool_client.clients["web"].id}&response_type=code&redirect_uri=${urlencode(local.app_clients.web.callback_urls[0])}"
}
