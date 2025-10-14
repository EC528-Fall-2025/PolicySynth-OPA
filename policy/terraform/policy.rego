package terraform.policy

# OPA v1 style
# default violations := set()

#
# Helpers
#

# Only flag create/update (skip delete)
applicable_change(rc) if rc.change.actions[_] == "create"
applicable_change(rc) if rc.change.actions[_] == "update"

# Lightweight null guard
has_array(x) if x != null

#
# 1) Deny SG ingress from 0.0.0.0/0
#

# a) Inline ingress in aws_security_group
violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_security_group"
  applicable_change(rc)
  after := rc.change.after
  after != null
  has_array(after.ingress)
  ing := after.ingress[_]
  has_array(ing.cidr_blocks)
  ing.cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf("Security Group %s allows 0.0.0.0/0 ingress", [rc.address])
}

# b) Standalone ingress rule (classic)
violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_security_group_rule"
  applicable_change(rc)
  after := rc.change.after
  after != null
  after.type == "ingress"
  has_array(after.cidr_blocks)
  after.cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf("Security Group rule %s allows 0.0.0.0/0 ingress", [rc.address])
}

# c) Standalone ingress rule (provider v5 style)
violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_vpc_security_group_ingress_rule"
  applicable_change(rc)
  after := rc.change.after
  after != null
  after.cidr_ipv4 == "0.0.0.0/0"
  msg := sprintf("VPC SG ingress rule %s allows 0.0.0.0/0", [rc.address])
}

#
# 2) Deny public S3 bucket
#

# a) Public ACL
violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_s3_bucket"
  applicable_change(rc)
  after := rc.change.after
  after != null
  after.acl == "public-read"
  msg := sprintf("S3 bucket %s has public ACL: public-read", [rc.address])
}

violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_s3_bucket"
  applicable_change(rc)
  after := rc.change.after
  after != null
  after.acl == "public-read-write"
  msg := sprintf("S3 bucket %s has public ACL: public-read-write", [rc.address])
}

# b) Public access block not fully enabled
violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_s3_bucket_public_access_block"
  applicable_change(rc)
  after := rc.change.after
  after != null
  not after.block_public_acls
  msg := sprintf("S3 public access not fully blocked (block_public_acls=false) for %s", [rc.address])
}

violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_s3_bucket_public_access_block"
  applicable_change(rc)
  after := rc.change.after
  after != null
  not after.block_public_policy
  msg := sprintf("S3 public access not fully blocked (block_public_policy=false) for %s", [rc.address])
}

#
# 3) Require EBS encryption
#

# a) Plain volumes
violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_ebs_volume"
  applicable_change(rc)
  after := rc.change.after
  after != null
  not after.encrypted
  msg := sprintf("EBS volume %s is not encrypted", [rc.address])
}

# b) Launch template block device mappings
violations contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_launch_template"
  applicable_change(rc)
  after := rc.change.after
  after != null
  has_array(after.block_device_mappings)
  bdm := after.block_device_mappings[_]
  ebs := bdm.ebs
  ebs != null
  ebs.encrypted == false
  msg := sprintf("Launch template %s has unencrypted EBS", [rc.address])
}


