# AWS Macie Module

Sensitive data discovery and classification for S3 using Amazon Macie.

## Features

- **Automated S3 Scanning**: Discover sensitive data in S3 buckets
- **Custom Data Identifiers**: Define regex patterns for organization-specific data
- **Classification Jobs**: Schedule or one-time scanning of specific buckets
- **SNS Alerts**: Real-time notifications for sensitive data findings
- **S3 Export**: Archive findings for compliance and audit
- **Organization Support**: Delegated admin configuration for AWS Organizations

## Usage

### Basic Setup

```hcl
module "macie" {
  source = "../modules/macie"
  name   = "data-discovery"

  # Enable with defaults
  enable = true
}
```

### With SNS Alerts

```hcl
module "macie" {
  source = "../modules/macie"
  name   = "data-discovery"

  enable_sns_alerts        = true
  alert_email              = "security@example.com"
  alert_severity_threshold = "MEDIUM"  # MEDIUM or HIGH findings only
}
```

### With Classification Jobs

```hcl
module "macie" {
  source = "../modules/macie"
  name   = "data-discovery"

  classification_jobs = {
    pii-scan = {
      description         = "Scan PII data buckets"
      bucket_names        = ["customer-data-bucket", "hr-documents"]
      sampling_percentage = 100
      initial_run         = true
    }

    financial-audit = {
      description         = "Weekly financial data scan"
      bucket_names        = ["finance-bucket"]
      schedule            = "weekly"
      sampling_percentage = 50
    }
  }
}
```

### With Custom Data Identifiers

```hcl
module "macie" {
  source = "../modules/macie"
  name   = "data-discovery"

  custom_data_identifiers = {
    api_key = {
      regex       = "(api[_-]?key|apikey)[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9]{20,}"
      keywords    = ["api_key", "apikey", "api-key"]
      description = "API key patterns in code"
    }

    internal_id = {
      regex       = "ACME-[0-9]{8}-[A-Z]{4}"
      keywords    = ["acme", "internal"]
      description = "Internal ACME ID format"
    }

    aws_access_key = {
      regex       = "AKIA[0-9A-Z]{16}"
      keywords    = ["aws", "access", "key"]
      description = "AWS Access Key ID pattern"
    }
  }

  enable_sns_alerts = true
  alert_email       = "security@example.com"
}
```

### Full Configuration

```hcl
module "macie" {
  source = "../modules/macie"
  name   = "data-discovery"

  # Core settings
  enable                        = true
  finding_publishing_frequency  = "FIFTEEN_MINUTES"

  # Auto-discovery (scans all buckets)
  enable_auto_discovery = true
  exclude_buckets       = ["logs-bucket", "temp-bucket"]

  # Classification jobs
  classification_jobs = {
    compliance-scan = {
      description  = "Compliance data scan"
      bucket_names = ["compliance-data"]
    }
  }

  # Custom patterns
  custom_data_identifiers = {
    secret_key = {
      regex       = "SECRET[_-]?KEY[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9]{32,}"
      keywords    = ["secret", "key"]
      description = "Secret key patterns"
    }
  }

  # Alerting
  enable_sns_alerts        = true
  alert_email              = "security@example.com"
  alert_severity_threshold = "MEDIUM"

  # Export findings
  enable_s3_export = true

  # Organization admin
  is_organization_admin            = true
  auto_enable_organization_members = true

  tags = {
    Environment = "production"
    Compliance  = "true"
  }
}
```

## Variables

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `name` | Name prefix for resources | `string` | required |
| `enable` | Enable Macie | `bool` | `true` |
| `finding_publishing_frequency` | Publishing frequency | `string` | `"FIFTEEN_MINUTES"` |
| `status` | Account status (ENABLED/PAUSED) | `string` | `"ENABLED"` |
| `enable_auto_discovery` | Enable auto S3 scanning | `bool` | `false` |
| `auto_discovery_buckets` | Specific buckets to scan | `list(string)` | `[]` |
| `exclude_buckets` | Buckets to exclude | `list(string)` | `[]` |
| `classification_jobs` | Job configurations | `map(object)` | `{}` |
| `custom_data_identifiers` | Custom regex patterns | `map(object)` | `{}` |
| `enable_sns_alerts` | Enable SNS notifications | `bool` | `false` |
| `alert_email` | Email for alerts | `string` | `""` |
| `alert_severity_threshold` | Minimum alert severity | `string` | `"MEDIUM"` |
| `enable_s3_export` | Export findings to S3 | `bool` | `false` |
| `is_organization_admin` | Enable org admin features | `bool` | `false` |

## Outputs

| Name | Description |
|------|-------------|
| `account_id` | Macie account ID |
| `account_status` | Macie status |
| `sns_topic_arn` | SNS topic for alerts |
| `export_bucket` | S3 bucket for exports |
| `custom_data_identifiers` | Custom identifier details |
| `classification_jobs` | Job details |
| `enabled_features` | Summary of enabled features |

## Data Types Detected

Macie automatically detects:

- **PII**: Names, addresses, SSNs, passport numbers
- **Financial**: Credit cards, bank accounts
- **Credentials**: AWS keys, passwords, API keys
- **Health**: HIPAA-related data
- **Custom**: Your custom patterns

## Cost Considerations

Macie pricing is based on:
- Number of S3 buckets evaluated
- Volume of data scanned
- Number of sensitive data findings

Use `sampling_percentage` in classification jobs to control costs.

## Integration with Other Modules

```hcl
# Combine with GuardDuty for comprehensive security
module "guardduty" {
  source = "../modules/guardduty"
  name   = "main"
  
  enable_sns_alerts = true
  alert_sns_topic_arn = module.macie.sns_topic_arn  # Share SNS topic
}

# Export to same Security Hub
module "security_hub" {
  source = "../modules/security-hub"
  
  # Macie findings automatically integrate with Security Hub
}
```
