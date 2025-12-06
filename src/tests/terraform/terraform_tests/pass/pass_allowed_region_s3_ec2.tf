# pass_allowed_region_s3_ec2.tf
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

resource "aws_s3_bucket" "allowed_bucket" {
  bucket = "psynth-allowed-bucket-us-east-1"
}

resource "aws_instance" "allowed_instance" {
  ami           = "ami-0c55b159cbfafe1f0" # example AMI, adjust to valid one
  instance_type = "t3.micro"
}
