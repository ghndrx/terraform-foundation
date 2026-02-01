# vpc-endpoints

VPC Endpoints Module

## Usage

```hcl
module "vpc_endpoints" {
  source = "../modules/vpc-endpoints"
  
  # Required variables
  vpc_id = ""
  private_subnet_ids = ""
  private_route_table_ids = ""
  region = ""

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
| vpc_id |  | `string` | yes |
| private_subnet_ids |  | `list(string)` | yes |
| private_route_table_ids |  | `list(string)` | yes |
| region |  | `string` | yes |
| name_prefix |  | `string` | no |
| enable_s3_endpoint |  | `bool` | no |
| enable_dynamodb_endpoint |  | `bool` | no |
| enable_ecr_endpoints | ECR API + DKR endpoints for container pulls without NAT | `bool` | no |
| enable_secrets_manager_endpoint | Secrets Manager endpoint for secret retrieval without NAT | `bool` | no |
| enable_ssm_endpoints | SSM, SSM Messages, EC2 Messages for Session Manager | `bool` | no |
| enable_logs_endpoint | CloudWatch Logs endpoint | `bool` | no |
| enable_kms_endpoint | KMS endpoint for encryption operations | `bool` | no |
| enable_sts_endpoint | STS endpoint for IAM role assumption | `bool` | no |
| enable_eks_endpoint | EKS endpoint for kubectl without public access | `bool` | no |

## Outputs

| Name | Description |
|------|-------------|
| s3_endpoint_id |  |
| dynamodb_endpoint_id |  |
| endpoints_security_group_id |  |
| enabled_endpoints |  |

## License

Apache 2.0 - See LICENSE for details.
