package aws.scp

# Test Case 6: Multiple deny statements
# Mode: deny_bool
# Query: data.aws.scp.deny

default deny := false

# Statement 1: Deny root account usage
deny := true if {
    principal_arn := input.context["aws:PrincipalArn"]
    contains(principal_arn, ":root")
}

# Statement 2: Deny dangerous S3 actions
deny := true if {
    dangerous_s3_actions := {
        "s3:DeleteBucket",
        "s3:PutBucketPolicy"
    }
    dangerous_s3_actions[input.action]
}

# Implicit Deny: all other operations (no Allow statements)
deny := true if {
    # Check if not explicitly denied by above rules
    not is_root_user
    not is_dangerous_s3_action
}

is_root_user if {
    principal_arn := input.context["aws:PrincipalArn"]
    contains(principal_arn, ":root")
}

is_dangerous_s3_action if {
    dangerous_s3_actions := {
        "s3:DeleteBucket",
        "s3:PutBucketPolicy"
    }
    dangerous_s3_actions[input.action]
}
