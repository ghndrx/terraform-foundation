# ram-share

Terraform module for AWS landing zone pattern.

Share resources across accounts via AWS Resource Access Manager.

## Planned Features

- [ ] VPC subnet sharing
- [ ] Transit Gateway sharing
- [ ] Route53 Resolver rule sharing
- [ ] Organization-wide sharing option
- [ ] OU-level sharing

## Planned Usage

```hcl
module "vpc_share" {
  source = "../modules/ram-share"
  
  name = "shared-vpc-subnets"
  
  resources = [
    aws_subnet.private_a.arn,
    aws_subnet.private_b.arn,
  ]
  
  # Share with specific accounts
  principals = ["111111111111", "222222222222"]
  
  # Or share with entire org
  # allow_organization = true
}
```
