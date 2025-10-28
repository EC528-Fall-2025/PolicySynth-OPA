
    package aws.scp.Deny_Public_S3_And_Require_BlockPublicAccess
    default allow = false
    default deny = false
    deny[msg] {
        input.action == "s3:PutBucketAcl"
        (not input.s3:x-amz-acl or input.s3:x-amz-acl == "['public-read', 'public-read-write', 'authenticated-read']")
        msg := "Deny-Public-S3-And-Require-BlockPublicAccess triggered for s3:PutBucketAcl"
    }

deny[msg] {
        input.action == "s3:PutObjectAcl"
        (not input.s3:x-amz-acl or input.s3:x-amz-acl == "['public-read', 'public-read-write', 'authenticated-read']")
        msg := "Deny-Public-S3-And-Require-BlockPublicAccess triggered for s3:PutObjectAcl"
    }

deny[msg] {
        input.action == "s3:PutAccountPublicAccessBlock"
        (not input.s3:PublicAccessBlockConfiguration/BlockPublicAcls or input.s3:PublicAccessBlockConfiguration/BlockPublicAcls == false) and (not input.s3:PublicAccessBlockConfiguration/IgnorePublicAcls or input.s3:PublicAccessBlockConfiguration/IgnorePublicAcls == false) and (not input.s3:PublicAccessBlockConfiguration/BlockPublicPolicy or input.s3:PublicAccessBlockConfiguration/BlockPublicPolicy == false) and (not input.s3:PublicAccessBlockConfiguration/RestrictPublicBuckets or input.s3:PublicAccessBlockConfiguration/RestrictPublicBuckets == false)
        msg := "Deny-Public-S3-And-Require-BlockPublicAccess triggered for s3:PutAccountPublicAccessBlock"
    }

deny[msg] {
        input.action == "s3:PutBucketPublicAccessBlock"
        (not input.s3:PublicAccessBlockConfiguration/BlockPublicAcls or input.s3:PublicAccessBlockConfiguration/BlockPublicAcls == false) and (not input.s3:PublicAccessBlockConfiguration/IgnorePublicAcls or input.s3:PublicAccessBlockConfiguration/IgnorePublicAcls == false) and (not input.s3:PublicAccessBlockConfiguration/BlockPublicPolicy or input.s3:PublicAccessBlockConfiguration/BlockPublicPolicy == false) and (not input.s3:PublicAccessBlockConfiguration/RestrictPublicBuckets or input.s3:PublicAccessBlockConfiguration/RestrictPublicBuckets == false)
        msg := "Deny-Public-S3-And-Require-BlockPublicAccess triggered for s3:PutBucketPublicAccessBlock"
    }
