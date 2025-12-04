# Lambda function in forbidden region (violates DenyAllExceptApprovedRegions SCP)
# Approved regions: us-east-1, us-west-2
# This function is created in: ap-northeast-1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-1"  # VIOLATION: Not in approved regions
}

resource "aws_lambda_function" "forbidden_region" {
  handler = "index.handler"
  runtime = "python3.11"
}
