# pass_multi_approved_regions.tf
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
  alias  = "west2"
  region = "us-west-2" 
}

resource "aws_s3_bucket" "east_bucket" {
  bucket = "psynth-east-bucket"
}

resource "aws_s3_bucket" "west_bucket" {
  provider = aws.west2
  bucket   = "psynth-west2-bucket"
}
