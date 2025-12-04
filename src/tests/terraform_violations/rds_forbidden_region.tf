# RDS instance in forbidden region (violates DenyAllExceptApprovedRegions SCP)
# Approved regions: us-east-1, us-west-2
# This DB is created in: eu-north-1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-north-1"  # VIOLATION: Not in approved regions
}

resource "aws_db_instance" "forbidden_region" {
  allocated_storage   = 10
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  name                = "violationsdb"
  username            = "admin"
  password            = "Password123!"
  skip_final_snapshot = true
}
