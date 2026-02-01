# cloudwatch-dashboard

CloudWatch Dashboard Module

## Usage

```hcl
module "cloudwatch_dashboard" {
  source = "../modules/cloudwatch-dashboard"
  
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
| name | Dashboard name | `string` | yes |
| ecs_clusters | ECS cluster names to monitor | `list(string)` | no |
| ecs_services | ECS service names to monitor | `list(string)` | no |
| rds_instances | RDS instance identifiers | `list(string)` | no |
| lambda_functions | Lambda function names | `list(string)` | no |
| alb_arns | ALB ARN suffixes (app/name/id) | `list(string)` | no |
| api_gateway_apis | API Gateway API IDs | `list(string)` | no |
| sqs_queues | SQS queue names | `list(string)` | no |
| dynamodb_tables | DynamoDB table names | `list(string)` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| dashboard_name |  |
| dashboard_arn |  |

## License

Apache 2.0 - See LICENSE for details.
