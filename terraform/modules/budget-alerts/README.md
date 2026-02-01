# budget-alerts

Budget Alerts Module

## Usage

```hcl
module "budget_alerts" {
  source = "../modules/budget-alerts"
  
  # Required variables
  monthly_budget = ""

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
| name_prefix | Prefix for budget names | `string` | no |
| monthly_budget | Monthly budget amount in USD | `number` | yes |
| currency | Budget currency | `string` | no |
| alert_emails | Email addresses for budget alerts | `list(string)` | no |
| alert_sns_topic_arn | SNS topic ARN for alerts (creates one if empty) | `string` | no |
| alert_thresholds | Alert thresholds as percentage of budget | `list(number)` | no |
| forecast_alert_threshold | Alert when forecasted spend exceeds this percentage | `number` | no |
| service_budgets |  | `map(number)` | no |
| enable_anomaly_detection | Enable AWS Cost Anomaly Detection | `bool` | no |
| anomaly_threshold_percentage | Anomaly alert threshold as percentage above expected | `number` | no |
| anomaly_threshold_absolute | Minimum absolute dollar amount for anomaly alerts | `number` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| monthly_budget_id | Monthly budget ID |
| service_budget_ids |  |
| sns_topic_arn | SNS topic ARN for alerts |
| anomaly_monitor_arn | Cost Anomaly Monitor ARN |
| budget_summary |  |

## License

Apache 2.0 - See LICENSE for details.
