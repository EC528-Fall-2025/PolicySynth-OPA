package aws.scp

import future.keywords.if

# allow read-only S3
allow if {
	startswith(input.action, "s3:Get")
}

# deny IAM user creation
deny if {
	input.action == "iam:CreateUser"
}

# deny S3 bucket deletion
deny if {
	input.action == "s3:DeleteBucket"
}
