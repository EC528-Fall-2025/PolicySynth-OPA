# fail_disallowed_region_ap_south_1.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"  
}

resource "aws_s3_bucket" "bad_bucket" {
  bucket = "psynth-bad-bucket-ap-south-1"
}

resource "aws_instance" "bad_instance" {
  ami           = "ami-0c55b159cbfafe1f0" # example AMI
  instance_type = "t3.micro"
}
