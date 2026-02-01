################################################################################
# Alerting Module
#
# Centralized alerting infrastructure:
# - SNS topics by severity (critical, warning, info)
# - Subscriptions (email, Slack, PagerDuty)
# - CloudWatch composite alarms
# - EventBridge rules for AWS events
#
# Usage:
#   module "alerting" {
#     source = "../modules/alerting"
#     name   = "myproject-prod"
#     
#     email_endpoints = ["ops@example.com"]
#     slack_webhook_url = "https://hooks.slack.com/..."
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "name" {
  type        = string
  description = "Name prefix for alerting resources"
}

variable "email_endpoints" {
  type        = list(string)
  default     = []
  description = "Email addresses to receive alerts"
}

variable "email_endpoints_critical" {
  type        = list(string)
  default     = []
  description = "Email addresses for critical alerts only (uses email_endpoints if empty)"
}

variable "slack_webhook_url" {
  type        = string
  default     = ""
  description = "Slack webhook URL for notifications"
  sensitive   = true
}

variable "pagerduty_endpoint" {
  type        = string
  default     = ""
  description = "PagerDuty Events API endpoint"
  sensitive   = true
}

variable "enable_aws_health_events" {
  type    = bool
  default = true
}

variable "enable_guardduty_events" {
  type    = bool
  default = true
}

variable "enable_securityhub_events" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# SNS Topics by Severity
################################################################################

resource "aws_sns_topic" "critical" {
  name              = "${var.name}-alerts-critical"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, { Name = "${var.name}-critical", Severity = "critical" })
}

resource "aws_sns_topic" "warning" {
  name              = "${var.name}-alerts-warning"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, { Name = "${var.name}-warning", Severity = "warning" })
}

resource "aws_sns_topic" "info" {
  name              = "${var.name}-alerts-info"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, { Name = "${var.name}-info", Severity = "info" })
}

################################################################################
# SNS Topic Policies
################################################################################

data "aws_iam_policy_document" "sns_policy" {
  statement {
    sid    = "AllowCloudWatchAlarms"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alarm:*"]
    }
  }

  statement {
    sid    = "AllowEventBridge"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = ["*"]
  }
}

resource "aws_sns_topic_policy" "critical" {
  arn    = aws_sns_topic.critical.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

resource "aws_sns_topic_policy" "warning" {
  arn    = aws_sns_topic.warning.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

resource "aws_sns_topic_policy" "info" {
  arn    = aws_sns_topic.info.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

################################################################################
# Email Subscriptions
################################################################################

resource "aws_sns_topic_subscription" "critical_email" {
  for_each = toset(length(var.email_endpoints_critical) > 0 ? var.email_endpoints_critical : var.email_endpoints)

  topic_arn = aws_sns_topic.critical.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_sns_topic_subscription" "warning_email" {
  for_each = toset(var.email_endpoints)

  topic_arn = aws_sns_topic.warning.arn
  protocol  = "email"
  endpoint  = each.value
}

################################################################################
# Slack Integration (via Lambda)
################################################################################

data "archive_file" "slack_notifier" {
  count       = var.slack_webhook_url != "" ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/slack_notifier.zip"

  source {
    content = <<-PYTHON
import json
import urllib.request
import os

def handler(event, context):
    webhook_url = os.environ['SLACK_WEBHOOK_URL']
    
    for record in event.get('Records', []):
        message = json.loads(record['Sns']['Message'])
        
        # Parse CloudWatch Alarm
        if 'AlarmName' in message:
            color = '#FF0000' if message['NewStateValue'] == 'ALARM' else '#36a64f'
            text = f"*{message['AlarmName']}*\n{message['AlarmDescription']}\n\nState: {message['NewStateValue']}\nReason: {message['NewStateReason']}"
        else:
            text = json.dumps(message, indent=2)
            color = '#FFA500'
        
        payload = {
            'attachments': [{
                'color': color,
                'text': text,
                'footer': f"AWS | {message.get('Region', 'Unknown Region')}",
            }]
        }
        
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req)
    
    return {'statusCode': 200}
PYTHON
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "slack_notifier" {
  count            = var.slack_webhook_url != "" ? 1 : 0
  filename         = data.archive_file.slack_notifier[0].output_path
  source_code_hash = data.archive_file.slack_notifier[0].output_base64sha256
  function_name    = "${var.name}-slack-notifier"
  role             = aws_iam_role.slack_notifier[0].arn
  handler          = "lambda_function.handler"
  runtime          = "python3.12"
  timeout          = 30

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-slack-notifier" })
}

resource "aws_iam_role" "slack_notifier" {
  count = var.slack_webhook_url != "" ? 1 : 0
  name  = "${var.name}-slack-notifier"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name}-slack-notifier" })
}

resource "aws_iam_role_policy_attachment" "slack_notifier" {
  count      = var.slack_webhook_url != "" ? 1 : 0
  role       = aws_iam_role.slack_notifier[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_permission" "slack_critical" {
  count         = var.slack_webhook_url != "" ? 1 : 0
  statement_id  = "AllowSNSCritical"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_notifier[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.critical.arn
}

resource "aws_lambda_permission" "slack_warning" {
  count         = var.slack_webhook_url != "" ? 1 : 0
  statement_id  = "AllowSNSWarning"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_notifier[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.warning.arn
}

resource "aws_sns_topic_subscription" "slack_critical" {
  count     = var.slack_webhook_url != "" ? 1 : 0
  topic_arn = aws_sns_topic.critical.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_notifier[0].arn
}

resource "aws_sns_topic_subscription" "slack_warning" {
  count     = var.slack_webhook_url != "" ? 1 : 0
  topic_arn = aws_sns_topic.warning.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_notifier[0].arn
}

################################################################################
# EventBridge Rules - AWS Health Events
################################################################################

resource "aws_cloudwatch_event_rule" "health" {
  count       = var.enable_aws_health_events ? 1 : 0
  name        = "${var.name}-health-events"
  description = "Capture AWS Health events"

  event_pattern = jsonencode({
    source      = ["aws.health"]
    detail-type = ["AWS Health Event"]
  })

  tags = merge(var.tags, { Name = "${var.name}-health" })
}

resource "aws_cloudwatch_event_target" "health" {
  count     = var.enable_aws_health_events ? 1 : 0
  rule      = aws_cloudwatch_event_rule.health[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.warning.arn
}

################################################################################
# EventBridge Rules - GuardDuty Findings
################################################################################

resource "aws_cloudwatch_event_rule" "guardduty" {
  count       = var.enable_guardduty_events ? 1 : 0
  name        = "${var.name}-guardduty-findings"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }] # Medium and above
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-guardduty" })
}

resource "aws_cloudwatch_event_target" "guardduty_critical" {
  count     = var.enable_guardduty_events ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty[0].name
  target_id = "SendToSNSCritical"
  arn       = aws_sns_topic.critical.arn

  input_transformer {
    input_paths = {
      severity = "$.detail.severity"
      title    = "$.detail.title"
      type     = "$.detail.type"
      region   = "$.region"
    }
    input_template = <<-EOF
      {
        "AlarmName": "GuardDuty Finding",
        "AlarmDescription": "<title>",
        "NewStateValue": "ALARM",
        "NewStateReason": "Type: <type>, Severity: <severity>",
        "Region": "<region>"
      }
    EOF
  }
}

################################################################################
# EventBridge Rules - Security Hub
################################################################################

resource "aws_cloudwatch_event_rule" "securityhub" {
  count       = var.enable_securityhub_events ? 1 : 0
  name        = "${var.name}-securityhub-findings"
  description = "Capture Security Hub findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
      }
    }
  })

  tags = merge(var.tags, { Name = "${var.name}-securityhub" })
}

resource "aws_cloudwatch_event_target" "securityhub" {
  count     = var.enable_securityhub_events ? 1 : 0
  rule      = aws_cloudwatch_event_rule.securityhub[0].name
  target_id = "SendToSNSCritical"
  arn       = aws_sns_topic.critical.arn
}

################################################################################
# Outputs
################################################################################

output "critical_topic_arn" {
  value       = aws_sns_topic.critical.arn
  description = "SNS topic for critical alerts"
}

output "warning_topic_arn" {
  value       = aws_sns_topic.warning.arn
  description = "SNS topic for warning alerts"
}

output "info_topic_arn" {
  value       = aws_sns_topic.info.arn
  description = "SNS topic for info alerts"
}

output "topics" {
  value = {
    critical = aws_sns_topic.critical.arn
    warning  = aws_sns_topic.warning.arn
    info     = aws_sns_topic.info.arn
  }
}
