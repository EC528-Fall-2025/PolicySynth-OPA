package aws.scp

import future.keywords.if

# allow test
test_allow_s3_getobject if {
	req := {"action": "s3:GetObject"}
	allow with input as req
}

# deny test (IAM)
test_deny_iam_create if {
	req := {"action": "iam:CreateUser"}
	deny with input as req
}

# deny test (S3)
test_deny_s3_deletebucket if {
	req := {"action": "s3:DeleteBucket"}
	deny with input as req
}

# default deny test
test_default_deny if {
	req := {"action": "ec2:RunInstances"}
	not allow with input as req
}
