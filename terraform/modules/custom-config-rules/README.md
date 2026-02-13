# Custom AWS Config Rules Module

Lambda-backed custom compliance rules for organization-specific checks that go beyond AWS managed rules.

## Features

### Pre-built Custom Rules (all opt-in)

| Rule | Description | Parameters |
|------|-------------|------------|
| `enable_unused_iam_roles_check` | Detects IAM roles not used in N days | `unused_iam_roles_max_days` (default: 90) |
| `enable_secrets_rotation_check` | Ensures Secrets Manager secrets have rotation enabled | `secrets_rotation_max_days` (default: 90) |
| `enable_required_tags_check` | Validates EC2 instances have required tags | `required_tags` (default: ["Environment", "Owner"]) |
| `enable_lambda_dlq_check` | Ensures Lambda functions have DLQs configured | - |
| `enable_s3_lifecycle_check` | Validates S3 buckets have lifecycle policies | - |
| `enable_ebs_snapshot_check` | Checks EBS volumes have recent snapshots | `ebs_snapshot_max_age_days` (default: 7) |
| `enable_rds_backup_check` | Validates RDS backup retention meets minimum | `rds_backup_min_retention` (default: 7) |

### User-Defined Custom Rules

Define your own rules using Python Lambda functions:

```hcl
custom_rules = [
  {
    name           = "my-custom-check"
    description    = "Custom compliance check"
    resource_types = ["AWS::EC2::Instance"]
    source_code    = file("${path.module}/rules/my_custom_check.py")
    input_parameters = {
      threshold = "100"
    }
  }
]
```

## Usage

### Basic - Enable Pre-built Rules

```hcl
module "custom_config_rules" {
  source = "../modules/custom-config-rules"
  
  # Enable specific checks
  enable_unused_iam_roles_check = true
  enable_secrets_rotation_check = true
  enable_required_tags_check    = true
  
  # Customize tag requirements
  required_tags = ["Environment", "Owner", "CostCenter", "Project"]
  
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### Advanced - With Custom Rules

```hcl
module "custom_config_rules" {
  source = "../modules/custom-config-rules"
  
  # Pre-built rules
  enable_lambda_dlq_check   = true
  enable_s3_lifecycle_check = true
  enable_rds_backup_check   = true
  rds_backup_min_retention  = 14
  
  # User-defined custom rules
  custom_rules = [
    {
      name           = "ec2-instance-type-check"
      description    = "Ensure EC2 instances use approved instance types"
      resource_types = ["AWS::EC2::Instance"]
      source_code    = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone

APPROVED_TYPES = ['t3.micro', 't3.small', 't3.medium', 'm5.large', 'm5.xlarge']

def lambda_handler(event, context):
    config = boto3.client('config')
    ec2 = boto3.client('ec2')
    
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    approved = json.loads(rule_parameters.get('approvedTypes', json.dumps(APPROVED_TYPES)))
    
    result_token = event['resultToken']
    evaluations = []
    
    instances = ec2.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            if instance['State']['Name'] == 'terminated':
                continue
                
            instance_type = instance['InstanceType']
            compliance = 'COMPLIANT' if instance_type in approved else 'NON_COMPLIANT'
            annotation = f"Instance type: {instance_type}"
            
            evaluations.append({
                'ComplianceResourceType': 'AWS::EC2::Instance',
                'ComplianceResourceId': instance['InstanceId'],
                'ComplianceType': compliance,
                'Annotation': annotation,
                'OrderingTimestamp': datetime.now(timezone.utc)
            })
    
    if evaluations:
        config.put_evaluations(Evaluations=evaluations, ResultToken=result_token)
    
    return {'status': 'success'}
PYTHON
      input_parameters = {
        approvedTypes = jsonencode(["t3.micro", "t3.small", "m5.large"])
      }
    }
  ]
  
  tags = var.tags
}
```

### Disable All Rules

```hcl
module "custom_config_rules" {
  source = "../modules/custom-config-rules"
  
  enabled = false  # Master toggle - no resources created
}
```

## Requirements

- AWS Config must be enabled (use the `config-rules` module first)
- Python 3.12 runtime (configurable via `lambda_runtime`)

## Writing Custom Rules

Custom rules must:

1. Accept `event` and `context` parameters
2. Parse `event['ruleParameters']` for any input parameters
3. Use `event['resultToken']` when calling `put_evaluations`
4. Return evaluations with valid `ComplianceType`: `COMPLIANT`, `NON_COMPLIANT`, or `NOT_APPLICABLE`

### Template

```python
import boto3
import json
from datetime import datetime, timezone

def lambda_handler(event, context):
    config = boto3.client('config')
    
    # Parse parameters
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    result_token = event['resultToken']
    
    evaluations = []
    
    # Your compliance logic here...
    
    evaluations.append({
        'ComplianceResourceType': 'AWS::EC2::Instance',  # Resource type
        'ComplianceResourceId': 'i-1234567890abcdef0',   # Resource ID
        'ComplianceType': 'COMPLIANT',                    # or NON_COMPLIANT
        'Annotation': 'Reason for compliance status',    # Max 255 chars
        'OrderingTimestamp': datetime.now(timezone.utc)
    })
    
    # Submit evaluations (batch of 100 max)
    config.put_evaluations(
        Evaluations=evaluations,
        ResultToken=result_token
    )
    
    return {'status': 'success'}
```

## Outputs

| Name | Description |
|------|-------------|
| `lambda_role_arn` | IAM role ARN used by Lambda functions |
| `enabled_prebuilt_rules` | Map of pre-built rules and their enabled status |
| `custom_rules` | List of user-defined custom rule names |
| `rule_arns` | Map of all Config rule names to their ARNs |

## Notes

- All rules run on a scheduled basis (default: every 24 hours)
- Lambda functions are created only for enabled rules
- IAM permissions are scoped to the minimum required for each rule type
- Annotations are truncated to 255 characters (AWS limit)
