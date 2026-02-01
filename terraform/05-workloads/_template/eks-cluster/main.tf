################################################################################
# Workload: EKS Cluster
# 
# Deploys a managed Kubernetes cluster:
# - EKS cluster with managed node groups
# - Core addons (VPC CNI, CoreDNS, kube-proxy)
# - IRSA (IAM Roles for Service Accounts)
# - Cluster Autoscaler ready
# - AWS Load Balancer Controller ready
# - Optional Fargate profiles
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-eks/
#   Update locals and variables
#   terraform init -backend-config=../../00-bootstrap/backend.hcl
#   terraform apply
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }

  backend "s3" {
    key = "05-workloads/<TENANT>-eks/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  env    = "prod" # prod, staging, dev
  name   = "${local.tenant}-${local.env}"

  # EKS Version
  cluster_version = "1.29"

  # Node Groups
  node_groups = {
    general = {
      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND" # ON_DEMAND or SPOT
      min_size       = 2
      max_size       = 10
      desired_size   = 2
      disk_size      = 50
      labels = {
        role = "general"
      }
      taints = []
    }
    # Uncomment for spot instances
    # spot = {
    #   instance_types = ["t3.medium", "t3.large", "t3a.medium"]
    #   capacity_type  = "SPOT"
    #   min_size       = 0
    #   max_size       = 20
    #   desired_size   = 0
    #   disk_size      = 50
    #   labels = {
    #     role = "spot"
    #   }
    #   taints = [{
    #     key    = "spot"
    #     value  = "true"
    #     effect = "NO_SCHEDULE"
    #   }]
    # }
  }

  # Fargate (for serverless pods)
  enable_fargate = false
  fargate_namespaces = ["serverless"] # Namespaces to run on Fargate

  # Addons
  enable_cluster_autoscaler = true
  enable_aws_lb_controller  = true
  enable_ebs_csi_driver     = true
  enable_metrics_server     = true

  # Logging
  cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  log_retention_days = 30

  # Access
  cluster_endpoint_public  = true
  cluster_endpoint_private = true
  public_access_cidrs      = ["0.0.0.0/0"] # Restrict in production!

  # Admin access (IAM ARNs that can access cluster)
  admin_arns = [
    # "arn:aws:iam::123456789012:role/Admin",
    # "arn:aws:iam::123456789012:user/admin",
  ]
}

################################################################################
# Variables
################################################################################

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "state_bucket" {
  type = string
}

################################################################################
# Provider
################################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Tenant      = local.tenant
      Environment = local.env
      ManagedBy   = "terraform"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "02-network/terraform.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "tenant" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "04-tenants/${local.tenant}/terraform.tfstate"
    region = var.region
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

################################################################################
# KMS Key for Secrets Encryption
################################################################################

resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key for ${local.name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${local.name}-eks" }
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

################################################################################
# CloudWatch Log Group
################################################################################

resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${local.name}/cluster"
  retention_in_days = local.log_retention_days

  tags = { Name = "${local.name}-eks" }
}

################################################################################
# IAM - Cluster Role
################################################################################

resource "aws_iam_role" "cluster" {
  name = "${local.name}-eks-cluster"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-eks-cluster" }
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "cluster_vpc_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSVPCResourceController"
}

################################################################################
# IAM - Node Role
################################################################################

resource "aws_iam_role" "node" {
  name = "${local.name}-eks-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-eks-node" }
}

resource "aws_iam_role_policy_attachment" "node_policy" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr_policy" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "node_ssm_policy" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

################################################################################
# IAM - Fargate Role
################################################################################

resource "aws_iam_role" "fargate" {
  count = local.enable_fargate ? 1 : 0
  name  = "${local.name}-eks-fargate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "eks-fargate-pods.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name}-eks-fargate" }
}

resource "aws_iam_role_policy_attachment" "fargate_policy" {
  count      = local.enable_fargate ? 1 : 0
  role       = aws_iam_role.fargate[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}

################################################################################
# Security Groups
################################################################################

resource "aws_security_group" "cluster" {
  name        = "${local.name}-eks-cluster"
  description = "EKS cluster security group"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  tags = { Name = "${local.name}-eks-cluster" }
}

resource "aws_security_group_rule" "cluster_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cluster.id
  description       = "Allow all outbound"
}

resource "aws_security_group" "node" {
  name        = "${local.name}-eks-node"
  description = "EKS node security group"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  tags = {
    Name                                        = "${local.name}-eks-node"
    "kubernetes.io/cluster/${local.name}"       = "owned"
  }
}

resource "aws_security_group_rule" "node_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.node.id
  description       = "Allow all outbound"
}

resource "aws_security_group_rule" "node_ingress_self" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.node.id
  description              = "Node to node"
}

resource "aws_security_group_rule" "node_ingress_cluster" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.node.id
  description              = "Cluster to node (webhooks)"
}

resource "aws_security_group_rule" "node_ingress_cluster_kubelet" {
  type                     = "ingress"
  from_port                = 10250
  to_port                  = 10250
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.node.id
  description              = "Cluster to node (kubelet)"
}

resource "aws_security_group_rule" "cluster_ingress_node" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Node to cluster API"
}

################################################################################
# EKS Cluster
################################################################################

resource "aws_eks_cluster" "main" {
  name     = local.name
  version  = local.cluster_version
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = data.terraform_remote_state.network.outputs.private_subnet_ids
    endpoint_private_access = local.cluster_endpoint_private
    endpoint_public_access  = local.cluster_endpoint_public
    public_access_cidrs     = local.public_access_cidrs
    security_group_ids      = [aws_security_group.cluster.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = local.cluster_log_types

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_iam_role_policy_attachment.cluster_vpc_policy,
    aws_cloudwatch_log_group.eks,
  ]

  tags = { Name = local.name }
}

################################################################################
# EKS Addons
################################################################################

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "vpc-cni"

  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  tags = { Name = "${local.name}-vpc-cni" }
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "coredns"

  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_eks_node_group.main]

  tags = { Name = "${local.name}-coredns" }
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "kube-proxy"

  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  tags = { Name = "${local.name}-kube-proxy" }
}

resource "aws_eks_addon" "ebs_csi" {
  count        = local.enable_ebs_csi_driver ? 1 : 0
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "aws-ebs-csi-driver"

  service_account_role_arn = aws_iam_role.ebs_csi[0].arn

  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_eks_node_group.main]

  tags = { Name = "${local.name}-ebs-csi" }
}

################################################################################
# Node Groups
################################################################################

resource "aws_eks_node_group" "main" {
  for_each = local.node_groups

  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${local.name}-${each.key}"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = data.terraform_remote_state.network.outputs.private_subnet_ids

  instance_types = each.value.instance_types
  capacity_type  = each.value.capacity_type
  disk_size      = each.value.disk_size

  scaling_config {
    min_size     = each.value.min_size
    max_size     = each.value.max_size
    desired_size = each.value.desired_size
  }

  update_config {
    max_unavailable = 1
  }

  labels = merge(each.value.labels, {
    Tenant = local.tenant
  })

  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  # Launch template for security hardening
  launch_template {
    id      = aws_launch_template.node[each.key].id
    version = aws_launch_template.node[each.key].latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_policy,
    aws_iam_role_policy_attachment.node_cni_policy,
    aws_iam_role_policy_attachment.node_ecr_policy,
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }

  tags = { Name = "${local.name}-${each.key}" }
}

################################################################################
# Launch Template for Node Security Hardening
################################################################################

resource "aws_launch_template" "node" {
  for_each = local.node_groups

  name = "${local.name}-${each.key}"

  # IMDSv2 enforcement - critical security control
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Enforces IMDSv2
    http_put_response_hop_limit = 1           # Prevent container credential theft
    instance_metadata_tags      = "enabled"
  }

  # EBS encryption
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = each.value.disk_size
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  # Monitoring
  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name   = "${local.name}-${each.key}"
      Tenant = local.tenant
    }
  }

  tags = { Name = "${local.name}-${each.key}" }
}

################################################################################
# Fargate Profiles
################################################################################

resource "aws_eks_fargate_profile" "main" {
  for_each = local.enable_fargate ? toset(local.fargate_namespaces) : []

  cluster_name           = aws_eks_cluster.main.name
  fargate_profile_name   = "${local.name}-${each.key}"
  pod_execution_role_arn = aws_iam_role.fargate[0].arn
  subnet_ids             = data.terraform_remote_state.network.outputs.private_subnet_ids

  selector {
    namespace = each.key
    labels = {
      Tenant = local.tenant
    }
  }

  tags = { Name = "${local.name}-${each.key}" }
}

################################################################################
# OIDC Provider for IRSA
################################################################################

data "tls_certificate" "eks" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = { Name = "${local.name}-eks-oidc" }
}

################################################################################
# IRSA - EBS CSI Driver
################################################################################

resource "aws_iam_role" "ebs_csi" {
  count = local.enable_ebs_csi_driver ? 1 : 0
  name  = "${local.name}-ebs-csi"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks.arn
      }
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = { Name = "${local.name}-ebs-csi" }
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  count      = local.enable_ebs_csi_driver ? 1 : 0
  role       = aws_iam_role.ebs_csi[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

################################################################################
# IRSA - Cluster Autoscaler
################################################################################

resource "aws_iam_role" "cluster_autoscaler" {
  count = local.enable_cluster_autoscaler ? 1 : 0
  name  = "${local.name}-cluster-autoscaler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks.arn
      }
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:cluster-autoscaler"
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = { Name = "${local.name}-cluster-autoscaler" }
}

resource "aws_iam_role_policy" "cluster_autoscaler" {
  count = local.enable_cluster_autoscaler ? 1 : 0
  name  = "cluster-autoscaler"
  role  = aws_iam_role.cluster_autoscaler[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeScalingActivities",
          "autoscaling:DescribeTags",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:DescribeImages",
          "ec2:GetInstanceTypesFromInstanceRequirements",
          "eks:DescribeNodegroup"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "autoscaling:ResourceTag/k8s.io/cluster-autoscaler/${local.name}" = "owned"
          }
        }
      }
    ]
  })
}

################################################################################
# IRSA - AWS Load Balancer Controller
################################################################################

resource "aws_iam_role" "lb_controller" {
  count = local.enable_aws_lb_controller ? 1 : 0
  name  = "${local.name}-aws-lb-controller"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks.arn
      }
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = { Name = "${local.name}-aws-lb-controller" }
}

resource "aws_iam_role_policy" "lb_controller" {
  count = local.enable_aws_lb_controller ? 1 : 0
  name  = "aws-lb-controller"
  role  = aws_iam_role.lb_controller[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreateServiceLinkedRole"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = "elasticloadbalancing.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:DescribeUserPoolClient",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "shield:GetSubscriptionState",
          "shield:DescribeProtection",
          "shield:CreateProtection",
          "shield:DeleteProtection"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DeleteSecurityGroup"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:${data.aws_partition.current.partition}:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:${data.aws_partition.current.partition}:elasticloadbalancing:*:*:loadbalancer/app/*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:ModifyRule",
          "elasticloadbalancing:DeleteRule",
          "elasticloadbalancing:SetWebAcl",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:RemoveListenerCertificates"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# EKS Access Entries (K8s 1.29+)
################################################################################

resource "aws_eks_access_entry" "admins" {
  for_each = toset(local.admin_arns)

  cluster_name  = aws_eks_cluster.main.name
  principal_arn = each.value
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "admins" {
  for_each = toset(local.admin_arns)

  cluster_name  = aws_eks_cluster.main.name
  principal_arn = each.value
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.admins]
}

################################################################################
# Outputs
################################################################################

output "cluster_name" {
  value = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "cluster_ca_certificate" {
  value     = aws_eks_cluster.main.certificate_authority[0].data
  sensitive = true
}

output "cluster_version" {
  value = aws_eks_cluster.main.version
}

output "cluster_security_group_id" {
  value = aws_security_group.cluster.id
}

output "node_security_group_id" {
  value = aws_security_group.node.id
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.eks.arn
}

output "oidc_provider_url" {
  value = aws_iam_openid_connect_provider.eks.url
}

output "cluster_autoscaler_role_arn" {
  value = local.enable_cluster_autoscaler ? aws_iam_role.cluster_autoscaler[0].arn : null
}

output "lb_controller_role_arn" {
  value = local.enable_aws_lb_controller ? aws_iam_role.lb_controller[0].arn : null
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${data.aws_region.current.name} --name ${aws_eks_cluster.main.name}"
}

output "next_steps" {
  value = <<-EOT
    
    EKS Cluster Created: ${aws_eks_cluster.main.name}
    =============================================
    
    1. Configure kubectl:
       ${local.enable_cluster_autoscaler ? "aws eks update-kubeconfig --region ${data.aws_region.current.name} --name ${aws_eks_cluster.main.name}" : ""}
    
    2. Install Cluster Autoscaler (if enabled):
       helm repo add autoscaler https://kubernetes.github.io/autoscaler
       helm install cluster-autoscaler autoscaler/cluster-autoscaler \
         --namespace kube-system \
         --set autoDiscovery.clusterName=${aws_eks_cluster.main.name} \
         --set awsRegion=${data.aws_region.current.name} \
         --set rbac.serviceAccount.create=true \
         --set rbac.serviceAccount.name=cluster-autoscaler \
         --set rbac.serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=${local.enable_cluster_autoscaler ? aws_iam_role.cluster_autoscaler[0].arn : "N/A"}
    
    3. Install AWS Load Balancer Controller (if enabled):
       helm repo add eks https://aws.github.io/eks-charts
       helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
         --namespace kube-system \
         --set clusterName=${aws_eks_cluster.main.name} \
         --set serviceAccount.create=true \
         --set serviceAccount.name=aws-load-balancer-controller \
         --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=${local.enable_aws_lb_controller ? aws_iam_role.lb_controller[0].arn : "N/A"}
    
  EOT
}
