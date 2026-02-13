################################################################################
# Custom AWS Config Rules Module
#
# Lambda-backed custom compliance rules for organization-specific checks:
# - Unused IAM roles detection
# - Secrets Manager rotation check
# - EC2 instances without required tags
# - Lambda functions without dead letter queues
# - S3 buckets without lifecycle policies
# - EBS volumes without snapshots
# - User-defined custom rules
#
# All rules are OPT-IN via variables.
#
# Usage:
#   module "custom_config_rules" {
#     source = "../modules/custom-config-rules"
#     
#     enable_unused_iam_roles_check     = true
#     enable_secrets_rotation_check     = true
#     enable_required_tags_check        = true
#     required_tags                     = ["Environment", "Owner", "CostCenter"]
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

################################################################################
# Variables
################################################################################

variable "enabled" {
  type        = bool
  default     = true
  description = "Master toggle for the custom config rules module"
}

# Pre-built Custom Rules Toggles
variable "enable_unused_iam_roles_check" {
  type        = bool
  default     = false
  description = "Check for IAM roles not used in the last N days"
}

variable "unused_iam_roles_max_days" {
  type        = number
  default     = 90
  description = "Days without usage before IAM role is flagged as unused"
}

variable "enable_secrets_rotation_check" {
  type        = bool
  default     = false
  description = "Check Secrets Manager secrets have rotation enabled"
}

variable "secrets_rotation_max_days" {
  type        = number
  default     = 90
  description = "Maximum days between secret rotations"
}

variable "enable_required_tags_check" {
  type        = bool
  default     = false
  description = "Check EC2 instances have required tags"
}

variable "required_tags" {
  type        = list(string)
  default     = ["Environment", "Owner"]
  description = "List of required tag keys for EC2 instances"
}

variable "enable_lambda_dlq_check" {
  type        = bool
  default     = false
  description = "Check Lambda functions have dead letter queues configured"
}

variable "enable_s3_lifecycle_check" {
  type        = bool
  default     = false
  description = "Check S3 buckets have lifecycle policies"
}

variable "enable_ebs_snapshot_check" {
  type        = bool
  default     = false
  description = "Check EBS volumes have recent snapshots"
}

variable "ebs_snapshot_max_age_days" {
  type        = number
  default     = 7
  description = "Maximum age of most recent EBS snapshot in days"
}

variable "enable_rds_backup_check" {
  type        = bool
  default     = false
  description = "Check RDS instances have backup retention > 0"
}

variable "rds_backup_min_retention" {
  type        = number
  default     = 7
  description = "Minimum backup retention period for RDS instances"
}

# User-defined Custom Rules
variable "custom_rules" {
  type = list(object({
    name              = string
    description       = string
    resource_types    = list(string)
    source_code       = string # Python code as string
    input_parameters  = optional(map(string), {})
    maximum_frequency = optional(string, "TwentyFour_Hours")
  }))
  default     = []
  description = "List of user-defined custom Config rules"
}

variable "lambda_runtime" {
  type        = string
  default     = "python3.12"
  description = "Lambda runtime for custom rule functions"
}

variable "lambda_timeout" {
  type        = number
  default     = 60
  description = "Lambda timeout in seconds"
}

variable "lambda_memory" {
  type        = number
  default     = 256
  description = "Lambda memory in MB"
}

variable "sns_topic_arn" {
  type        = string
  default     = ""
  description = "SNS topic ARN for non-compliant notifications"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  # Count of enabled pre-built rules
  prebuilt_rules_count = (
    (var.enable_unused_iam_roles_check ? 1 : 0) +
    (var.enable_secrets_rotation_check ? 1 : 0) +
    (var.enable_required_tags_check ? 1 : 0) +
    (var.enable_lambda_dlq_check ? 1 : 0) +
    (var.enable_s3_lifecycle_check ? 1 : 0) +
    (var.enable_ebs_snapshot_check ? 1 : 0) +
    (var.enable_rds_backup_check ? 1 : 0)
  )

  any_rules_enabled = var.enabled && (local.prebuilt_rules_count > 0 || length(var.custom_rules) > 0)
}

################################################################################
# IAM Role for Lambda Config Rules
################################################################################

resource "aws_iam_role" "config_lambda" {
  count = local.any_rules_enabled ? 1 : 0
  name  = "CustomConfigRulesLambdaRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "CustomConfigRulesLambdaRole" })
}

resource "aws_iam_role_policy" "config_lambda" {
  count = local.any_rules_enabled ? 1 : 0
  name  = "custom-config-rules-policy"
  role  = aws_iam_role.config_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "config:PutEvaluations"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:ListRoles",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails"
        ]
        Resource = "*"
        Condition = {
          Bool = { "aws:SecureTransport" = "true" }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetLifecycleConfiguration",
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# Pre-built Rule: Unused IAM Roles
################################################################################

locals {
  unused_iam_roles_code = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone, timedelta

def lambda_handler(event, context):
    config = boto3.client('config')
    iam = boto3.client('iam')
    
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    max_days = int(rule_parameters.get('maxDays', 90))
    
    invoking_event = json.loads(event['invokingEvent'])
    result_token = event['resultToken']
    
    evaluations = []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=max_days)
    
    roles = iam.list_roles()['Roles']
    
    for role in roles:
        role_name = role['RoleName']
        
        # Skip service-linked roles
        if role['Path'].startswith('/aws-service-role/'):
            continue
        
        try:
            job_id = iam.generate_service_last_accessed_details(Arn=role['Arn'])['JobId']
            
            import time
            for _ in range(10):
                details = iam.get_service_last_accessed_details(JobId=job_id)
                if details['JobStatus'] == 'COMPLETED':
                    break
                time.sleep(1)
            
            last_accessed = None
            for service in details.get('ServicesLastAccessed', []):
                if 'LastAuthenticated' in service:
                    if last_accessed is None or service['LastAuthenticated'] > last_accessed:
                        last_accessed = service['LastAuthenticated']
            
            if last_accessed is None:
                # Never used - check creation date
                if role['CreateDate'].replace(tzinfo=timezone.utc) < cutoff_date:
                    compliance = 'NON_COMPLIANT'
                    annotation = f"IAM role never used and created over {max_days} days ago"
                else:
                    compliance = 'COMPLIANT'
                    annotation = "Role recently created, monitoring"
            elif last_accessed < cutoff_date:
                compliance = 'NON_COMPLIANT'
                annotation = f"IAM role not used in over {max_days} days"
            else:
                compliance = 'COMPLIANT'
                annotation = "Role used recently"
        except Exception as e:
            compliance = 'NOT_APPLICABLE'
            annotation = str(e)
        
        evaluations.append({
            'ComplianceResourceType': 'AWS::IAM::Role',
            'ComplianceResourceId': role_name,
            'ComplianceType': compliance,
            'Annotation': annotation[:255],
            'OrderingTimestamp': datetime.now(timezone.utc)
        })
    
    # Submit in batches of 100
    for i in range(0, len(evaluations), 100):
        config.put_evaluations(
            Evaluations=evaluations[i:i+100],
            ResultToken=result_token
        )
    
    return {'status': 'success', 'evaluated': len(evaluations)}
PYTHON
}

data "archive_file" "unused_iam_roles" {
  count       = var.enabled && var.enable_unused_iam_roles_check ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.lambda/unused_iam_roles.zip"

  source {
    content  = local.unused_iam_roles_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "unused_iam_roles" {
  count         = var.enabled && var.enable_unused_iam_roles_check ? 1 : 0
  function_name = "config-rule-unused-iam-roles"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = 300 # Longer timeout for IAM analysis
  memory_size   = var.lambda_memory

  filename         = data.archive_file.unused_iam_roles[0].output_path
  source_code_hash = data.archive_file.unused_iam_roles[0].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-unused-iam-roles" })
}

resource "aws_lambda_permission" "unused_iam_roles" {
  count          = var.enabled && var.enable_unused_iam_roles_check ? 1 : 0
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.unused_iam_roles[0].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "unused_iam_roles" {
  count       = var.enabled && var.enable_unused_iam_roles_check ? 1 : 0
  name        = "custom-unused-iam-roles"
  description = "Checks for IAM roles not used in the last ${var.unused_iam_roles_max_days} days"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.unused_iam_roles[0].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  input_parameters = jsonencode({
    maxDays = tostring(var.unused_iam_roles_max_days)
  })

  depends_on = [aws_lambda_permission.unused_iam_roles]
  tags       = var.tags
}

################################################################################
# Pre-built Rule: Secrets Manager Rotation Check
################################################################################

locals {
  secrets_rotation_code = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone, timedelta

def lambda_handler(event, context):
    config = boto3.client('config')
    sm = boto3.client('secretsmanager')
    
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    max_days = int(rule_parameters.get('maxDays', 90))
    
    result_token = event['resultToken']
    evaluations = []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=max_days)
    
    paginator = sm.get_paginator('list_secrets')
    for page in paginator.paginate():
        for secret in page['SecretList']:
            secret_name = secret['Name']
            
            try:
                detail = sm.describe_secret(SecretId=secret['ARN'])
                
                if not detail.get('RotationEnabled', False):
                    compliance = 'NON_COMPLIANT'
                    annotation = "Secret does not have rotation enabled"
                elif 'LastRotatedDate' not in detail:
                    compliance = 'NON_COMPLIANT'
                    annotation = "Secret has rotation enabled but has never been rotated"
                elif detail['LastRotatedDate'].replace(tzinfo=timezone.utc) < cutoff_date:
                    compliance = 'NON_COMPLIANT'
                    annotation = f"Secret not rotated in over {max_days} days"
                else:
                    compliance = 'COMPLIANT'
                    annotation = "Secret rotation is enabled and recent"
                    
            except Exception as e:
                compliance = 'NOT_APPLICABLE'
                annotation = str(e)[:255]
            
            evaluations.append({
                'ComplianceResourceType': 'AWS::SecretsManager::Secret',
                'ComplianceResourceId': secret_name,
                'ComplianceType': compliance,
                'Annotation': annotation[:255],
                'OrderingTimestamp': datetime.now(timezone.utc)
            })
    
    for i in range(0, len(evaluations), 100):
        config.put_evaluations(
            Evaluations=evaluations[i:i+100],
            ResultToken=result_token
        )
    
    return {'status': 'success', 'evaluated': len(evaluations)}
PYTHON
}

data "archive_file" "secrets_rotation" {
  count       = var.enabled && var.enable_secrets_rotation_check ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.lambda/secrets_rotation.zip"

  source {
    content  = local.secrets_rotation_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "secrets_rotation" {
  count         = var.enabled && var.enable_secrets_rotation_check ? 1 : 0
  function_name = "config-rule-secrets-rotation"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.secrets_rotation[0].output_path
  source_code_hash = data.archive_file.secrets_rotation[0].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-secrets-rotation" })
}

resource "aws_lambda_permission" "secrets_rotation" {
  count          = var.enabled && var.enable_secrets_rotation_check ? 1 : 0
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.secrets_rotation[0].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "secrets_rotation" {
  count       = var.enabled && var.enable_secrets_rotation_check ? 1 : 0
  name        = "custom-secrets-rotation"
  description = "Checks that Secrets Manager secrets have rotation enabled"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.secrets_rotation[0].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  input_parameters = jsonencode({
    maxDays = tostring(var.secrets_rotation_max_days)
  })

  depends_on = [aws_lambda_permission.secrets_rotation]
  tags       = var.tags
}

################################################################################
# Pre-built Rule: Required Tags Check
################################################################################

locals {
  required_tags_code = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone

def lambda_handler(event, context):
    config = boto3.client('config')
    ec2 = boto3.client('ec2')
    
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    required_tags = json.loads(rule_parameters.get('requiredTags', '["Environment", "Owner"]'))
    
    result_token = event['resultToken']
    evaluations = []
    
    paginator = ec2.get_paginator('describe_instances')
    for page in paginator.paginate():
        for reservation in page['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                
                # Skip terminated instances
                if instance['State']['Name'] == 'terminated':
                    continue
                
                instance_tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
                missing_tags = [t for t in required_tags if t not in instance_tags]
                
                if missing_tags:
                    compliance = 'NON_COMPLIANT'
                    annotation = f"Missing required tags: {', '.join(missing_tags)}"
                else:
                    compliance = 'COMPLIANT'
                    annotation = "All required tags present"
                
                evaluations.append({
                    'ComplianceResourceType': 'AWS::EC2::Instance',
                    'ComplianceResourceId': instance_id,
                    'ComplianceType': compliance,
                    'Annotation': annotation[:255],
                    'OrderingTimestamp': datetime.now(timezone.utc)
                })
    
    if evaluations:
        for i in range(0, len(evaluations), 100):
            config.put_evaluations(
                Evaluations=evaluations[i:i+100],
                ResultToken=result_token
            )
    else:
        config.put_evaluations(
            Evaluations=[{
                'ComplianceResourceType': 'AWS::::Account',
                'ComplianceResourceId': context.invoked_function_arn.split(':')[4],
                'ComplianceType': 'NOT_APPLICABLE',
                'Annotation': 'No EC2 instances found',
                'OrderingTimestamp': datetime.now(timezone.utc)
            }],
            ResultToken=result_token
        )
    
    return {'status': 'success', 'evaluated': len(evaluations)}
PYTHON
}

data "archive_file" "required_tags" {
  count       = var.enabled && var.enable_required_tags_check ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.lambda/required_tags.zip"

  source {
    content  = local.required_tags_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "required_tags" {
  count         = var.enabled && var.enable_required_tags_check ? 1 : 0
  function_name = "config-rule-required-tags"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.required_tags[0].output_path
  source_code_hash = data.archive_file.required_tags[0].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-required-tags" })
}

resource "aws_lambda_permission" "required_tags" {
  count          = var.enabled && var.enable_required_tags_check ? 1 : 0
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.required_tags[0].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "required_tags" {
  count       = var.enabled && var.enable_required_tags_check ? 1 : 0
  name        = "custom-required-tags"
  description = "Checks EC2 instances have required tags: ${join(", ", var.required_tags)}"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.required_tags[0].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  input_parameters = jsonencode({
    requiredTags = jsonencode(var.required_tags)
  })

  depends_on = [aws_lambda_permission.required_tags]
  tags       = var.tags
}

################################################################################
# Pre-built Rule: Lambda DLQ Check
################################################################################

locals {
  lambda_dlq_code = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone

def lambda_handler(event, context):
    config = boto3.client('config')
    lambda_client = boto3.client('lambda')
    
    result_token = event['resultToken']
    evaluations = []
    
    paginator = lambda_client.get_paginator('list_functions')
    for page in paginator.paginate():
        for func in page['Functions']:
            function_name = func['FunctionName']
            
            # Skip this config rule function itself
            if 'config-rule' in function_name:
                continue
            
            try:
                config_detail = lambda_client.get_function_configuration(
                    FunctionName=function_name
                )
                
                dlq_config = config_detail.get('DeadLetterConfig', {})
                
                if dlq_config.get('TargetArn'):
                    compliance = 'COMPLIANT'
                    annotation = "Dead letter queue configured"
                else:
                    compliance = 'NON_COMPLIANT'
                    annotation = "No dead letter queue configured"
                    
            except Exception as e:
                compliance = 'NOT_APPLICABLE'
                annotation = str(e)[:255]
            
            evaluations.append({
                'ComplianceResourceType': 'AWS::Lambda::Function',
                'ComplianceResourceId': function_name,
                'ComplianceType': compliance,
                'Annotation': annotation[:255],
                'OrderingTimestamp': datetime.now(timezone.utc)
            })
    
    if evaluations:
        for i in range(0, len(evaluations), 100):
            config.put_evaluations(
                Evaluations=evaluations[i:i+100],
                ResultToken=result_token
            )
    
    return {'status': 'success', 'evaluated': len(evaluations)}
PYTHON
}

data "archive_file" "lambda_dlq" {
  count       = var.enabled && var.enable_lambda_dlq_check ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.lambda/lambda_dlq.zip"

  source {
    content  = local.lambda_dlq_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "lambda_dlq" {
  count         = var.enabled && var.enable_lambda_dlq_check ? 1 : 0
  function_name = "config-rule-lambda-dlq"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.lambda_dlq[0].output_path
  source_code_hash = data.archive_file.lambda_dlq[0].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-lambda-dlq" })
}

resource "aws_lambda_permission" "lambda_dlq" {
  count          = var.enabled && var.enable_lambda_dlq_check ? 1 : 0
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.lambda_dlq[0].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "lambda_dlq" {
  count       = var.enabled && var.enable_lambda_dlq_check ? 1 : 0
  name        = "custom-lambda-dlq-check"
  description = "Checks Lambda functions have dead letter queues configured"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.lambda_dlq[0].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  depends_on = [aws_lambda_permission.lambda_dlq]
  tags       = var.tags
}

################################################################################
# Pre-built Rule: S3 Lifecycle Check
################################################################################

locals {
  s3_lifecycle_code = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone

def lambda_handler(event, context):
    config = boto3.client('config')
    s3 = boto3.client('s3')
    
    result_token = event['resultToken']
    evaluations = []
    
    buckets = s3.list_buckets()['Buckets']
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        
        try:
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                rules = lifecycle.get('Rules', [])
                
                if rules:
                    compliance = 'COMPLIANT'
                    annotation = f"Lifecycle policy configured with {len(rules)} rule(s)"
                else:
                    compliance = 'NON_COMPLIANT'
                    annotation = "Lifecycle configuration exists but has no rules"
            except s3.exceptions.ClientError as e:
                if 'NoSuchLifecycleConfiguration' in str(e):
                    compliance = 'NON_COMPLIANT'
                    annotation = "No lifecycle policy configured"
                else:
                    raise
                    
        except Exception as e:
            compliance = 'NOT_APPLICABLE'
            annotation = str(e)[:255]
        
        evaluations.append({
            'ComplianceResourceType': 'AWS::S3::Bucket',
            'ComplianceResourceId': bucket_name,
            'ComplianceType': compliance,
            'Annotation': annotation[:255],
            'OrderingTimestamp': datetime.now(timezone.utc)
        })
    
    if evaluations:
        for i in range(0, len(evaluations), 100):
            config.put_evaluations(
                Evaluations=evaluations[i:i+100],
                ResultToken=result_token
            )
    
    return {'status': 'success', 'evaluated': len(evaluations)}
PYTHON
}

data "archive_file" "s3_lifecycle" {
  count       = var.enabled && var.enable_s3_lifecycle_check ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.lambda/s3_lifecycle.zip"

  source {
    content  = local.s3_lifecycle_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "s3_lifecycle" {
  count         = var.enabled && var.enable_s3_lifecycle_check ? 1 : 0
  function_name = "config-rule-s3-lifecycle"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.s3_lifecycle[0].output_path
  source_code_hash = data.archive_file.s3_lifecycle[0].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-s3-lifecycle" })
}

resource "aws_lambda_permission" "s3_lifecycle" {
  count          = var.enabled && var.enable_s3_lifecycle_check ? 1 : 0
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.s3_lifecycle[0].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "s3_lifecycle" {
  count       = var.enabled && var.enable_s3_lifecycle_check ? 1 : 0
  name        = "custom-s3-lifecycle"
  description = "Checks S3 buckets have lifecycle policies configured"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.s3_lifecycle[0].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  depends_on = [aws_lambda_permission.s3_lifecycle]
  tags       = var.tags
}

################################################################################
# Pre-built Rule: EBS Snapshot Check
################################################################################

locals {
  ebs_snapshot_code = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone, timedelta

def lambda_handler(event, context):
    config = boto3.client('config')
    ec2 = boto3.client('ec2')
    
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    max_age_days = int(rule_parameters.get('maxAgeDays', 7))
    
    result_token = event['resultToken']
    evaluations = []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    
    # Get all volumes
    volumes = ec2.describe_volumes()['Volumes']
    
    for volume in volumes:
        volume_id = volume['VolumeId']
        
        try:
            # Get snapshots for this volume
            snapshots = ec2.describe_snapshots(
                Filters=[{'Name': 'volume-id', 'Values': [volume_id]}],
                OwnerIds=['self']
            )['Snapshots']
            
            if not snapshots:
                compliance = 'NON_COMPLIANT'
                annotation = "No snapshots exist for this volume"
            else:
                # Find most recent snapshot
                latest_snapshot = max(snapshots, key=lambda x: x['StartTime'])
                
                if latest_snapshot['StartTime'].replace(tzinfo=timezone.utc) < cutoff_date:
                    compliance = 'NON_COMPLIANT'
                    annotation = f"Most recent snapshot is older than {max_age_days} days"
                else:
                    compliance = 'COMPLIANT'
                    annotation = f"Recent snapshot exists ({latest_snapshot['SnapshotId']})"
                    
        except Exception as e:
            compliance = 'NOT_APPLICABLE'
            annotation = str(e)[:255]
        
        evaluations.append({
            'ComplianceResourceType': 'AWS::EC2::Volume',
            'ComplianceResourceId': volume_id,
            'ComplianceType': compliance,
            'Annotation': annotation[:255],
            'OrderingTimestamp': datetime.now(timezone.utc)
        })
    
    if evaluations:
        for i in range(0, len(evaluations), 100):
            config.put_evaluations(
                Evaluations=evaluations[i:i+100],
                ResultToken=result_token
            )
    
    return {'status': 'success', 'evaluated': len(evaluations)}
PYTHON
}

data "archive_file" "ebs_snapshot" {
  count       = var.enabled && var.enable_ebs_snapshot_check ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.lambda/ebs_snapshot.zip"

  source {
    content  = local.ebs_snapshot_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "ebs_snapshot" {
  count         = var.enabled && var.enable_ebs_snapshot_check ? 1 : 0
  function_name = "config-rule-ebs-snapshot"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.ebs_snapshot[0].output_path
  source_code_hash = data.archive_file.ebs_snapshot[0].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-ebs-snapshot" })
}

resource "aws_lambda_permission" "ebs_snapshot" {
  count          = var.enabled && var.enable_ebs_snapshot_check ? 1 : 0
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.ebs_snapshot[0].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "ebs_snapshot" {
  count       = var.enabled && var.enable_ebs_snapshot_check ? 1 : 0
  name        = "custom-ebs-snapshot-age"
  description = "Checks EBS volumes have snapshots within the last ${var.ebs_snapshot_max_age_days} days"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.ebs_snapshot[0].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  input_parameters = jsonencode({
    maxAgeDays = tostring(var.ebs_snapshot_max_age_days)
  })

  depends_on = [aws_lambda_permission.ebs_snapshot]
  tags       = var.tags
}

################################################################################
# Pre-built Rule: RDS Backup Check
################################################################################

locals {
  rds_backup_code = <<-PYTHON
import boto3
import json
from datetime import datetime, timezone

def lambda_handler(event, context):
    config = boto3.client('config')
    rds = boto3.client('rds')
    
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    min_retention = int(rule_parameters.get('minRetention', 7))
    
    result_token = event['resultToken']
    evaluations = []
    
    paginator = rds.get_paginator('describe_db_instances')
    for page in paginator.paginate():
        for db in page['DBInstances']:
            db_id = db['DBInstanceIdentifier']
            
            retention = db.get('BackupRetentionPeriod', 0)
            
            if retention == 0:
                compliance = 'NON_COMPLIANT'
                annotation = "Automated backups are disabled (retention = 0)"
            elif retention < min_retention:
                compliance = 'NON_COMPLIANT'
                annotation = f"Backup retention ({retention} days) is below minimum ({min_retention} days)"
            else:
                compliance = 'COMPLIANT'
                annotation = f"Backup retention is {retention} days"
            
            evaluations.append({
                'ComplianceResourceType': 'AWS::RDS::DBInstance',
                'ComplianceResourceId': db_id,
                'ComplianceType': compliance,
                'Annotation': annotation[:255],
                'OrderingTimestamp': datetime.now(timezone.utc)
            })
    
    if evaluations:
        for i in range(0, len(evaluations), 100):
            config.put_evaluations(
                Evaluations=evaluations[i:i+100],
                ResultToken=result_token
            )
    
    return {'status': 'success', 'evaluated': len(evaluations)}
PYTHON
}

data "archive_file" "rds_backup" {
  count       = var.enabled && var.enable_rds_backup_check ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.lambda/rds_backup.zip"

  source {
    content  = local.rds_backup_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "rds_backup" {
  count         = var.enabled && var.enable_rds_backup_check ? 1 : 0
  function_name = "config-rule-rds-backup"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.rds_backup[0].output_path
  source_code_hash = data.archive_file.rds_backup[0].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-rds-backup" })
}

resource "aws_lambda_permission" "rds_backup" {
  count          = var.enabled && var.enable_rds_backup_check ? 1 : 0
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.rds_backup[0].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "rds_backup" {
  count       = var.enabled && var.enable_rds_backup_check ? 1 : 0
  name        = "custom-rds-backup-retention"
  description = "Checks RDS instances have backup retention >= ${var.rds_backup_min_retention} days"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.rds_backup[0].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  input_parameters = jsonencode({
    minRetention = tostring(var.rds_backup_min_retention)
  })

  depends_on = [aws_lambda_permission.rds_backup]
  tags       = var.tags
}

################################################################################
# User-defined Custom Rules
################################################################################

data "archive_file" "custom" {
  for_each    = var.enabled ? { for idx, rule in var.custom_rules : rule.name => rule } : {}
  type        = "zip"
  output_path = "${path.module}/.lambda/custom_${each.key}.zip"

  source {
    content  = each.value.source_code
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "custom" {
  for_each      = var.enabled ? { for idx, rule in var.custom_rules : rule.name => rule } : {}
  function_name = "config-rule-custom-${each.key}"
  role          = aws_iam_role.config_lambda[0].arn
  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.custom[each.key].output_path
  source_code_hash = data.archive_file.custom[each.key].output_base64sha256

  tags = merge(var.tags, { Name = "config-rule-custom-${each.key}" })
}

resource "aws_lambda_permission" "custom" {
  for_each       = var.enabled ? { for idx, rule in var.custom_rules : rule.name => rule } : {}
  statement_id   = "AllowConfigInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.custom[each.key].function_name
  principal      = "config.amazonaws.com"
  source_account = local.account_id
}

resource "aws_config_config_rule" "custom" {
  for_each    = var.enabled ? { for idx, rule in var.custom_rules : rule.name => rule } : {}
  name        = "custom-${each.key}"
  description = each.value.description

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.custom[each.key].arn

    source_detail {
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = each.value.maximum_frequency
    }
  }

  input_parameters = length(each.value.input_parameters) > 0 ? jsonencode(each.value.input_parameters) : null

  depends_on = [aws_lambda_permission.custom]
  tags       = var.tags
}

################################################################################
# Outputs
################################################################################

output "lambda_role_arn" {
  value       = local.any_rules_enabled ? aws_iam_role.config_lambda[0].arn : null
  description = "IAM role ARN for Config rule Lambda functions"
}

output "enabled_prebuilt_rules" {
  value = {
    unused_iam_roles = var.enable_unused_iam_roles_check
    secrets_rotation = var.enable_secrets_rotation_check
    required_tags    = var.enable_required_tags_check
    lambda_dlq       = var.enable_lambda_dlq_check
    s3_lifecycle     = var.enable_s3_lifecycle_check
    ebs_snapshot     = var.enable_ebs_snapshot_check
    rds_backup       = var.enable_rds_backup_check
  }
  description = "Map of enabled pre-built custom rules"
}

output "custom_rules" {
  value       = [for rule in var.custom_rules : rule.name]
  description = "List of user-defined custom rule names"
}

output "rule_arns" {
  value = merge(
    var.enable_unused_iam_roles_check ? { unused_iam_roles = aws_config_config_rule.unused_iam_roles[0].arn } : {},
    var.enable_secrets_rotation_check ? { secrets_rotation = aws_config_config_rule.secrets_rotation[0].arn } : {},
    var.enable_required_tags_check ? { required_tags = aws_config_config_rule.required_tags[0].arn } : {},
    var.enable_lambda_dlq_check ? { lambda_dlq = aws_config_config_rule.lambda_dlq[0].arn } : {},
    var.enable_s3_lifecycle_check ? { s3_lifecycle = aws_config_config_rule.s3_lifecycle[0].arn } : {},
    var.enable_ebs_snapshot_check ? { ebs_snapshot = aws_config_config_rule.ebs_snapshot[0].arn } : {},
    var.enable_rds_backup_check ? { rds_backup = aws_config_config_rule.rds_backup[0].arn } : {},
    { for name, rule in aws_config_config_rule.custom : name => rule.arn }
  )
  description = "Map of Config rule names to ARNs"
}
