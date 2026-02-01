################################################################################
# GitHub OIDC Module - Outputs
################################################################################

output "provider_arn" {
  value       = local.provider_arn
  description = "GitHub OIDC provider ARN"
}

output "provider_url" {
  value       = "https://token.actions.githubusercontent.com"
  description = "GitHub OIDC provider URL"
}

# Custom roles
output "role_arns" {
  value       = { for k, v in aws_iam_role.github : k => v.arn }
  description = "Map of custom role names to ARNs"
}

output "role_names" {
  value       = { for k, v in aws_iam_role.github : k => v.name }
  description = "Map of custom role key to IAM role names"
}

# Template roles
output "terraform_role_arn" {
  value       = local.tf_role_enabled ? aws_iam_role.terraform[0].arn : null
  description = "Terraform deploy role ARN"
}

output "terraform_role_name" {
  value       = local.tf_role_enabled ? aws_iam_role.terraform[0].name : null
  description = "Terraform deploy role name"
}

output "ecr_role_arn" {
  value       = local.ecr_role_enabled ? aws_iam_role.ecr[0].arn : null
  description = "ECR push role ARN"
}

output "ecr_role_name" {
  value       = local.ecr_role_enabled ? aws_iam_role.ecr[0].name : null
  description = "ECR push role name"
}

output "s3_deploy_role_arn" {
  value       = local.s3_role_enabled ? aws_iam_role.s3_deploy[0].arn : null
  description = "S3 deploy role ARN"
}

output "s3_deploy_role_name" {
  value       = local.s3_role_enabled ? aws_iam_role.s3_deploy[0].name : null
  description = "S3 deploy role name"
}

output "lambda_deploy_role_arn" {
  value       = local.lambda_role_enabled ? aws_iam_role.lambda_deploy[0].arn : null
  description = "Lambda deploy role ARN"
}

output "lambda_deploy_role_name" {
  value       = local.lambda_role_enabled ? aws_iam_role.lambda_deploy[0].name : null
  description = "Lambda deploy role name"
}

# All role ARNs combined
output "all_role_arns" {
  value = merge(
    { for k, v in aws_iam_role.github : k => v.arn },
    local.tf_role_enabled ? { terraform = aws_iam_role.terraform[0].arn } : {},
    local.ecr_role_enabled ? { ecr = aws_iam_role.ecr[0].arn } : {},
    local.s3_role_enabled ? { s3_deploy = aws_iam_role.s3_deploy[0].arn } : {},
    local.lambda_role_enabled ? { lambda_deploy = aws_iam_role.lambda_deploy[0].arn } : {}
  )
  description = "All role ARNs (custom + templates)"
}

# Security outputs
output "iam_path" {
  value       = var.path
  description = "IAM path used for roles (useful for permissions boundaries)"
}

output "security_recommendations" {
  value = {
    permissions_boundary_set = var.permissions_boundary != null
    max_session_limited      = var.max_session_hours_limit < 12
    wildcard_repos_denied    = var.deny_wildcard_repos
    cloudtrail_monitoring    = var.enable_cloudtrail_logging
  }
  description = "Security configuration status"
}

# Workflow configuration helper
output "github_actions_config" {
  value = {
    aws_region = local.region
    roles = merge(
      { for k, v in aws_iam_role.github : k => {
        arn  = v.arn
        name = v.name
      }},
      local.tf_role_enabled ? { terraform = {
        arn  = aws_iam_role.terraform[0].arn
        name = aws_iam_role.terraform[0].name
      }} : {},
      local.ecr_role_enabled ? { ecr = {
        arn  = aws_iam_role.ecr[0].arn
        name = aws_iam_role.ecr[0].name
      }} : {},
      local.s3_role_enabled ? { s3_deploy = {
        arn  = aws_iam_role.s3_deploy[0].arn
        name = aws_iam_role.s3_deploy[0].name
      }} : {},
      local.lambda_role_enabled ? { lambda_deploy = {
        arn  = aws_iam_role.lambda_deploy[0].arn
        name = aws_iam_role.lambda_deploy[0].name
      }} : {}
    )
  }
  description = "Configuration for GitHub Actions workflows"
}

# Example workflow snippets
output "workflow_examples" {
  value = {
    basic = <<-EOF
      # .github/workflows/deploy.yml
      permissions:
        id-token: write
        contents: read
      
      steps:
        - uses: aws-actions/configure-aws-credentials@v4
          with:
            role-to-assume: <ROLE_ARN>
            aws-region: ${local.region}
            role-session-name: github-actions-${"$"}{{ github.run_id }}
    EOF

    with_environment = <<-EOF
      # .github/workflows/deploy.yml
      jobs:
        deploy:
          runs-on: ubuntu-latest
          environment: production  # Requires approval if configured
          permissions:
            id-token: write
            contents: read
          steps:
            - uses: aws-actions/configure-aws-credentials@v4
              with:
                role-to-assume: <ROLE_ARN>
                aws-region: ${local.region}
    EOF
  }
  description = "Example GitHub Actions workflow snippets"
}
