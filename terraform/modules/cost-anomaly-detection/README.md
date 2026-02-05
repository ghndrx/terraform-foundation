# Cost Anomaly Detection Module

ML-powered cost anomaly detection for AWS using Cost Explorer Anomaly Detection.

## Overview

AWS Cost Anomaly Detection uses machine learning to identify unusual spending patterns that might not trigger traditional budget alerts. This module complements `budget-alerts` by catching:

- Unexpected spikes in service usage
- New services being used without authorization
- Gradual cost drift that compounds over time
- Anomalies specific to individual linked accounts

## Features

- **Flexible Monitoring**: Account-level, service-level, or custom (Cost Category) monitors
- **Smart Thresholds**: Alert on percentage change OR absolute impact (whichever triggers first)
- **Service-Specific Monitors**: Different thresholds for different services
- **Multi-Channel Alerts**: SNS topics + direct email subscriptions
- **Encryption**: Optional KMS encryption for SNS topic

## Usage

### Basic Setup

```hcl
module "cost_anomaly" {
  source = "../modules/cost-anomaly-detection"

  name_prefix    = "prod"
  alert_emails   = ["finops@example.com", "oncall@example.com"]

  # Alert when anomaly exceeds 10% OR $100
  threshold_percentage = 10
  threshold_absolute   = 100
}
```

### With Service-Specific Monitors

```hcl
module "cost_anomaly" {
  source = "../modules/cost-anomaly-detection"

  name_prefix    = "prod"
  alert_emails   = ["finops@example.com"]

  threshold_percentage = 10
  threshold_absolute   = 100

  # Additional monitors for critical services with custom thresholds
  service_monitors = {
    "Amazon Elastic Compute Cloud - Compute" = {
      threshold_percentage = 15
      threshold_absolute   = 500
    }
    "Amazon Relational Database Service" = {
      threshold_percentage = 20
      threshold_absolute   = 200
    }
    "Amazon SageMaker" = {
      threshold_percentage = 25
      threshold_absolute   = 1000
    }
  }
}
```

### Multi-Account with Cost Categories

```hcl
module "cost_anomaly" {
  source = "../modules/cost-anomaly-detection"

  name_prefix = "enterprise"

  # Use CUSTOM monitor for Cost Category filtering
  monitor_type         = "CUSTOM"
  cost_category_name   = "Environment"
  cost_category_values = ["Production"]

  threshold_percentage = 5
  threshold_absolute   = 250

  alert_emails = ["finops@example.com"]
}
```

### Linked Account Monitoring

```hcl
module "cost_anomaly" {
  source = "../modules/cost-anomaly-detection"

  name_prefix       = "org"
  monitor_dimension = "LINKED_ACCOUNT"

  threshold_percentage = 15
  threshold_absolute   = 100

  alert_frequency = "IMMEDIATE"

  alert_emails = ["finops@example.com"]
}
```

## How It Works

1. **Monitors** continuously analyze your AWS spending patterns using ML
2. **Anomalies** are detected when spending deviates significantly from the baseline
3. **Subscriptions** evaluate anomalies against your thresholds
4. **Alerts** are sent via SNS/email when thresholds are exceeded

### Alert Frequency Options

| Frequency | Description |
|-----------|-------------|
| `IMMEDIATE` | Alert as soon as anomaly is detected (may be noisy) |
| `DAILY` | Aggregate anomalies and send daily summary |
| `WEEKLY` | Weekly anomaly summary |

### Threshold Logic

Alerts trigger when EITHER condition is met:
- Impact percentage >= `threshold_percentage`
- Impact amount >= `threshold_absolute`

This prevents both small-percentage large-dollar anomalies AND large-percentage small-dollar anomalies from being missed.

## Integration with Budget Alerts

| Scenario | Budget Alerts | Anomaly Detection |
|----------|--------------|-------------------|
| Spending hits $1000 budget | ✅ Alerts | ❌ No alert |
| Sudden 50% spike ($200→$300) | ❌ Under budget | ✅ Anomaly detected |
| Gradual drift over weeks | ❌ Each day under | ✅ Pattern detected |
| New service unexpected use | ❌ May be under budget | ✅ New baseline alert |

**Recommendation**: Use both modules together for comprehensive cost monitoring.

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5 |
| aws | >= 5.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name_prefix | Prefix for resource names | `string` | n/a | yes |
| alert_emails | Email addresses for SNS notifications | `list(string)` | `[]` | no |
| direct_email_subscribers | Direct email subscribers (bypasses SNS) | `list(string)` | `[]` | no |
| monitor_type | DIMENSIONAL or CUSTOM | `string` | `"DIMENSIONAL"` | no |
| monitor_dimension | SERVICE or LINKED_ACCOUNT | `string` | `"SERVICE"` | no |
| cost_category_name | Cost Category for CUSTOM monitors | `string` | `null` | no |
| cost_category_values | Values for Cost Category filter | `list(string)` | `[]` | no |
| alert_frequency | DAILY, IMMEDIATE, or WEEKLY | `string` | `"DAILY"` | no |
| threshold_percentage | Impact percentage threshold | `number` | `10` | no |
| threshold_absolute | Impact amount threshold (USD) | `number` | `100` | no |
| service_monitors | Service-specific monitors | `map(object)` | `{}` | no |
| kms_key_id | KMS key for SNS encryption | `string` | `null` | no |
| tags | Resource tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| monitor_arn | ARN of the main anomaly monitor |
| monitor_id | ID of the main anomaly monitor |
| subscription_arn | ARN of the anomaly subscription |
| subscription_id | ID of the anomaly subscription |
| sns_topic_arn | ARN of the SNS alert topic |
| service_monitor_arns | Map of service monitor ARNs |
| service_subscription_arns | Map of service subscription ARNs |

## Cost

AWS Cost Anomaly Detection is **free** to use. You only pay for:
- SNS notifications (minimal)
- Any custom monitoring integrations you add

## References

- [AWS Cost Anomaly Detection](https://docs.aws.amazon.com/cost-management/latest/userguide/manage-ad.html)
- [Terraform aws_ce_anomaly_monitor](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ce_anomaly_monitor)
- [AWS FinOps Best Practices](https://aws.amazon.com/aws-cost-management/aws-finops/)
