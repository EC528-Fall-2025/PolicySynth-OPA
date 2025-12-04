# S3 bucket in forbidden region (violates DenyAllExceptApprovedRegions SCP)
# Approved regions: us-east-1, us-west-2
# This bucket is created in: eu-central-1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1" 
}

resource "aws_s3_bucket" "forbidden_region" {
  bucket = "my-app-bucket-eu-central"
}
