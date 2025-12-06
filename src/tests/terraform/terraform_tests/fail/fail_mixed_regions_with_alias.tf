# fail_mixed_regions_with_alias.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"  
}

provider "aws" {
  alias  = "ap"
  region = "ap-southeast-1"  
}

resource "aws_s3_bucket" "ok_bucket" {
  bucket = "psynth-ok-bucket-us-east-1"
}

resource "aws_s3_bucket" "bad_bucket" {
  provider = aws.ap
  bucket   = "psynth-bad-bucket-ap-southeast-1"
}
