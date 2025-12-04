# EC2 instance in forbidden region (violates DenyAllExceptApprovedRegions SCP)
# Approved regions: us-east-1, us-west-2
# This instance is created in: ap-southeast-1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-1"  # VIOLATION: Not in approved regions
}

resource "aws_instance" "forbidden_region" {
  instance_type = "t2.micro"
  
  tags = {
    Name = "instance-in-forbidden-region"
  }
}
