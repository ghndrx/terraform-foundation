################################################################################
# Security Groups - Outputs
################################################################################

output "web_tier_sg_id" {
  value       = try(aws_security_group.web[0].id, null)
  description = "Web tier security group ID"
}

output "app_tier_sg_id" {
  value       = try(aws_security_group.app[0].id, null)
  description = "App tier security group ID"
}

output "db_tier_sg_id" {
  value       = try(aws_security_group.db[0].id, null)
  description = "Database tier security group ID"
}

output "bastion_sg_id" {
  value       = try(aws_security_group.bastion[0].id, null)
  description = "Bastion security group ID"
}

output "endpoints_sg_id" {
  value       = try(aws_security_group.endpoints[0].id, null)
  description = "VPC endpoints security group ID"
}

output "eks_cluster_sg_id" {
  value       = try(aws_security_group.eks_cluster[0].id, null)
  description = "EKS cluster security group ID"
}

output "eks_nodes_sg_id" {
  value       = try(aws_security_group.eks_nodes[0].id, null)
  description = "EKS nodes security group ID"
}

output "all_sg_ids" {
  value = {
    web       = try(aws_security_group.web[0].id, null)
    app       = try(aws_security_group.app[0].id, null)
    db        = try(aws_security_group.db[0].id, null)
    bastion   = try(aws_security_group.bastion[0].id, null)
    endpoints = try(aws_security_group.endpoints[0].id, null)
    eks_cluster = try(aws_security_group.eks_cluster[0].id, null)
    eks_nodes   = try(aws_security_group.eks_nodes[0].id, null)
  }
  description = "Map of all security group IDs"
}
