################################################################################
# Tenant Budget - Outputs
################################################################################

output "budget_id" {
  value       = aws_budgets_budget.this.id
  description = "Budget ID"
}

output "budget_name" {
  value       = aws_budgets_budget.this.name
  description = "Budget name"
}

output "budget_limit" {
  value       = var.budget_limit
  description = "Budget limit in USD"
}

output "sns_topic_arn" {
  value       = var.create_sns_topic ? aws_sns_topic.budget[0].arn : var.sns_topic_arn
  description = "SNS topic ARN for budget alerts"
}

output "alert_thresholds" {
  value       = var.alert_thresholds
  description = "Configured alert thresholds"
}
