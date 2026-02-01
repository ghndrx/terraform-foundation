################################################################################
# Tenant VPC - Outputs
################################################################################

output "vpc_id" {
  value       = aws_vpc.this.id
  description = "VPC ID"
}

output "vpc_cidr" {
  value       = aws_vpc.this.cidr_block
  description = "VPC CIDR block"
}

output "public_subnet_ids" {
  value       = aws_subnet.public[*].id
  description = "Public subnet IDs"
}

output "private_subnet_ids" {
  value       = aws_subnet.private[*].id
  description = "Private subnet IDs"
}

output "public_route_table_id" {
  value       = try(aws_route_table.public[0].id, null)
  description = "Public route table ID"
}

output "private_route_table_id" {
  value       = try(aws_route_table.private[0].id, null)
  description = "Private route table ID"
}

output "nat_public_ip" {
  value = var.nat_mode == "gateway" ? (
    try(aws_eip.nat[0].public_ip, null)
  ) : (
    try(aws_instance.nat[0].public_ip, null)
  )
  description = "NAT Gateway/Instance public IP"
}

output "tgw_attachment_id" {
  value       = try(aws_ec2_transit_gateway_vpc_attachment.this[0].id, null)
  description = "Transit Gateway attachment ID"
}

output "flow_log_group" {
  value       = try(aws_cloudwatch_log_group.flow_logs[0].name, null)
  description = "Flow log CloudWatch log group"
}

output "azs" {
  value       = local.azs
  description = "Availability zones used"
}
