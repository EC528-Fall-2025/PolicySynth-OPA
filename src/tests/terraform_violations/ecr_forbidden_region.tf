# ECR repository in forbidden region (violates DenyAllExceptApprovedRegions SCP)
# Approved regions: us-east-1, us-west-2
# This repo is created in: eu-west-3

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-3"  # VIOLATION: Not in approved regions
}

resource "aws_ecr_repository" "forbidden_region" {
  name = "repo-in-forbidden-region"
}
