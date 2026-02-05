################################################################################
# Outputs
################################################################################

output "monitor_arn" {
  description = "ARN of the main cost anomaly monitor"
  value       = aws_ce_anomaly_monitor.main.arn
}

output "monitor_id" {
  description = "ID of the main cost anomaly monitor"
  value       = aws_ce_anomaly_monitor.main.id
}

output "subscription_arn" {
  description = "ARN of the cost anomaly subscription"
  value       = aws_ce_anomaly_subscription.main.arn
}

output "subscription_id" {
  description = "ID of the cost anomaly subscription"
  value       = aws_ce_anomaly_subscription.main.id
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for anomaly alerts"
  value       = aws_sns_topic.anomaly_alerts.arn
}

output "service_monitor_arns" {
  description = "Map of service-specific monitor ARNs"
  value       = { for k, v in aws_ce_anomaly_monitor.service : k => v.arn }
}

output "service_subscription_arns" {
  description = "Map of service-specific subscription ARNs"
  value       = { for k, v in aws_ce_anomaly_subscription.service : k => v.arn }
}
