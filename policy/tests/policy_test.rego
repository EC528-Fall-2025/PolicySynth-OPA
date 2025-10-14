package policy.tests
import data.terraform.policy as p

test_sg_open() {
  input := {"resource_changes": [{
    "type": "aws_security_group",
    "name": "web-sg",
    "change": {"after": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}}
  }]}
  count(p.deny with input as input) == 1
}

test_s3_public_acl() {
  input := {"resource_changes": [{
    "type": "aws_s3_bucket",
    "name": "my-bucket",
    "change": {"after": {"acl": "public-read"}}
  }]}
  count(p.deny with input as input) == 1
}

test_ebs_unencrypted() {
  input := {"resource_changes": [{
    "type": "aws_ebs_volume",
    "name": "vol-1",
    "change": {"after": {"encrypted": false}}
  }]}
  count(p.deny with input as input) == 1
}
