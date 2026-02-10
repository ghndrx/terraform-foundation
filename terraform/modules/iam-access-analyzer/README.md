# IAM Access Analyzer Module

Automatically analyzes resource policies to identify unintended external access to your AWS resources.

## Features

- **External Access Analysis**: Identifies public and cross-account access to:
  - S3 buckets
  - IAM roles
  - KMS keys
  - Lambda functions
  - SQS queues
  - Secrets Manager secrets

- **Unused Access Analysis** (optional): Identifies:
  - Unused IAM roles
  - Unused access keys
  - Unused permissions in policies

- **Archive Rules**: Suppress known-good access patterns:
  - Trusted organization
  - Trusted accounts
  - Trusted principals
  - Custom filter rules

- **Notifications**: Alert on new findings via:
  - SNS email notifications
  - EventBridge rules
  - CloudWatch alarms

## Usage

### Basic Account-Level Analyzer

```hcl
module "access_analyzer" {
  source = "../modules/iam-access-analyzer"
  
  name = "my-account-analyzer"
  type = "ACCOUNT"
}
```

### Organization-Level Analyzer

```hcl
module "access_analyzer" {
  source = "../modules/iam-access-analyzer"
  
  name = "org-analyzer"
  type = "ORGANIZATION"
  
  # Trust your organization
  archive_trusted_organization = "o-xxxxxxxxxx"
}
```

### With Unused Access Analysis

```hcl
module "access_analyzer" {
  source = "../modules/iam-access-analyzer"
  
  name                   = "comprehensive-analyzer"
  type                   = "ACCOUNT"
  enable_unused_access   = true
  unused_access_age_days = 90
}
```

### With Notifications

```hcl
module "access_analyzer" {
  source = "../modules/iam-access-analyzer"
  
  name                     = "monitored-analyzer"
  type                     = "ACCOUNT"
  enable_sns_notifications = true
  notification_emails      = ["security@example.com"]
}
```

### With Trusted Accounts

```hcl
module "access_analyzer" {
  source = "../modules/iam-access-analyzer"
  
  name = "multi-account-analyzer"
  type = "ACCOUNT"
  
  archive_trusted_accounts = [
    "111111111111",  # Shared services
    "222222222222",  # Security account
  ]
}
```

### With Custom Archive Rules

```hcl
module "access_analyzer" {
  source = "../modules/iam-access-analyzer"
  
  name = "custom-analyzer"
  type = "ACCOUNT"
  
  archive_rules = {
    s3_cloudfront = {
      description = "Allow CloudFront OAI access to S3"
      filter_criteria = [
        {
          criterion = "resourceType"
          eq        = ["AWS::S3::Bucket"]
        },
        {
          criterion = "principal.AWS"
          contains  = ["arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity"]
        }
      ]
    }
  }
}
```

## Variables

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string | `"default-analyzer"` | Access Analyzer name |
| `type` | string | `"ACCOUNT"` | Analyzer type: ACCOUNT or ORGANIZATION |
| `enable_unused_access` | bool | `false` | Enable unused access analyzer |
| `unused_access_age_days` | number | `90` | Days before flagging unused access |
| `enable_sns_notifications` | bool | `false` | Create SNS topic for findings |
| `sns_topic_arn` | string | `""` | Existing SNS topic ARN |
| `notification_emails` | list(string) | `[]` | Email addresses for notifications |
| `archive_trusted_organization` | string | `""` | Organization ID to trust |
| `archive_trusted_accounts` | list(string) | `[]` | Account IDs to trust |
| `archive_trusted_principals` | list(string) | `[]` | Principal ARNs to trust |
| `archive_rules` | map(object) | `{}` | Custom archive rules |
| `enable_eventbridge` | bool | `false` | Enable EventBridge rule |
| `tags` | map(string) | `{}` | Resource tags |

## Outputs

| Name | Description |
|------|-------------|
| `analyzer_arn` | Access Analyzer ARN |
| `analyzer_id` | Access Analyzer ID |
| `analyzer_name` | Access Analyzer name |
| `unused_access_analyzer_arn` | Unused Access Analyzer ARN |
| `sns_topic_arn` | SNS topic ARN for notifications |
| `eventbridge_rule_arn` | EventBridge rule ARN |
| `archive_rules` | Created archive rules |

## Best Practices

1. **Start with ACCOUNT type** - Easier to manage, no org admin required
2. **Enable notifications** - Don't let findings go unnoticed
3. **Review findings weekly** - Prioritize PUBLIC access findings
4. **Archive known-good patterns** - Reduce noise from trusted cross-account access
5. **Enable unused access** - Identify over-privileged roles and users

## Finding Types

| Type | Severity | Description |
|------|----------|-------------|
| `PublicAccess` | Critical | Resource is publicly accessible |
| `CrossAccountAccess` | High | External account has access |
| `UnusedIAMRole` | Medium | IAM role hasn't been used |
| `UnusedPermission` | Medium | Permission hasn't been used |
| `UnusedAccessKey` | Medium | Access key hasn't been used |

## Related Modules

- `security-hub` - Aggregates Access Analyzer findings
- `config-rules` - Compliance monitoring
- `guardduty` - Threat detection
