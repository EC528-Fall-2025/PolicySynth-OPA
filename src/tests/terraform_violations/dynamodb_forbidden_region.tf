# DynamoDB table in forbidden region (violates DenyAllExceptApprovedRegions SCP)
# Approved regions: us-east-1, us-west-2
# This table is created in: sa-east-1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "sa-east-1"  # VIOLATION: Not in approved regions
}

resource "aws_dynamodb_table" "forbidden_region" {
  name           = "my-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name = "table-in-forbidden-region"
  }
}
