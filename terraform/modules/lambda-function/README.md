# lambda-function

Lambda Function Module

## Usage

```hcl
module "lambda_function" {
  source = "../modules/lambda-function"
  
  # Required variables
  name = ""
  vpc_config = ""
  function_url = ""

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
| name | Function name | `string` | yes |
| description | Function description | `string` | no |
| runtime | Lambda runtime | `string` | no |
| handler | Function handler | `string` | no |
| architectures | CPU architecture (arm64 or x86_64) | `list(string)` | no |
| memory_size | Memory in MB (128-10240) | `number` | no |
| timeout | Timeout in seconds (max 900) | `number` | no |
| reserved_concurrent_executions | Reserved concurrency (-1 = unreserved) | `number` | no |
| source_dir | Local source directory to zip | `string` | no |
| source_file | Single source file to deploy | `string` | no |
| s3_bucket | S3 bucket containing deployment package | `string` | no |
| s3_key | S3 key for deployment package | `string` | no |
| image_uri | Container image URI | `string` | no |
| vpc_config |  | `object({` | yes |
| environment |  | `map(string)` | no |

*...and 12 more variables. See `variables.tf` for complete list.*

## Outputs

| Name | Description |
|------|-------------|
| function_name | Function name |
| function_arn | Function ARN |
| invoke_arn | Invoke ARN (for API Gateway) |
| qualified_arn | Qualified ARN (includes version) |
| role_arn | IAM role ARN |
| role_name | IAM role name |
| log_group_name | CloudWatch log group name |
| function_url | Function URL |
| version | Published version |

## License

Apache 2.0 - See LICENSE for details.
