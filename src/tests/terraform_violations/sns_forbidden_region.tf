# SNS topic in forbidden region (violates DenyAllExceptApprovedRegions SCP)
# Approved regions: us-east-1, us-west-2
# This topic is created in: cn-north-1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "cn-north-1"  # VIOLATION: Not in approved regions
}

resource "aws_sns_topic" "forbidden_region" {
  name = "topic-in-forbidden-region"
}
