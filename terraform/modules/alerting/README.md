# alerting

Alerting Module

## Usage

```hcl
module "alerting" {
  source = "../modules/alerting"
  
  # Required variables
  name = ""

  # Optional: see variables.tf for all options
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0 |

## Inputs

| Name | Description | Type | Required |
|------|-------------|------|----------|
| name | Name prefix for alerting resources | `string` | yes |
| email_endpoints | Email addresses to receive alerts | `list(string)` | no |
| email_endpoints_critical | Email addresses for critical alerts only (uses email_endpoin... | `list(string)` | no |
| slack_webhook_url | Slack webhook URL for notifications | `string` | no |
| pagerduty_endpoint | PagerDuty Events API endpoint | `string` | no |
| enable_aws_health_events |  | `bool` | no |
| enable_guardduty_events |  | `bool` | no |
| enable_securityhub_events |  | `bool` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| critical_topic_arn | SNS topic for critical alerts |
| warning_topic_arn | SNS topic for warning alerts |
| info_topic_arn | SNS topic for info alerts |
| topics |  |

## License

Apache 2.0 - See LICENSE for details.
