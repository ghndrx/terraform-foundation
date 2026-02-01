# cloudtrail

CloudTrail Module

## Usage

```hcl
module "cloudtrail" {
  source = "../modules/cloudtrail"
  
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
| name | Trail name | `string` | yes |
| s3_bucket_name | S3 bucket for logs (created if empty) | `string` | no |
| is_multi_region | Enable multi-region trail | `bool` | no |
| is_organization_trail | Organization-wide trail (requires org management account) | `bool` | no |
| enable_log_file_validation | Enable log file integrity validation | `bool` | no |
| include_global_service_events | Include global service events (IAM, STS, CloudFront) | `bool` | no |
| enable_cloudwatch_logs | Send logs to CloudWatch Logs | `bool` | no |
| cloudwatch_log_retention_days | CloudWatch log retention in days | `number` | no |
| enable_insights | Enable CloudTrail Insights (additional cost) | `bool` | no |
| insight_selectors | Insight types to enable | `list(string)` | no |
| enable_data_events | Enable data events logging | `bool` | no |
| data_event_s3_buckets | S3 bucket ARNs for data events (empty = all buckets) | `list(string)` | no |
| data_event_lambda_functions | Lambda function ARNs for data events (empty = all functions) | `list(string)` | no |
| data_event_dynamodb_tables | DynamoDB table ARNs for data events | `list(string)` | no |
| kms_key_arn | KMS key ARN for encryption (created if empty) | `string` | no |

*...and 3 more variables. See `variables.tf` for complete list.*

## Outputs

| Name | Description |
|------|-------------|
| trail_arn | CloudTrail ARN |
| trail_name | CloudTrail name |
| s3_bucket | S3 bucket for CloudTrail logs |
| kms_key_arn | KMS key ARN for encryption |
| cloudwatch_log_group | CloudWatch Logs group |
| home_region | Trail home region |

## License

Apache 2.0 - See LICENSE for details.
