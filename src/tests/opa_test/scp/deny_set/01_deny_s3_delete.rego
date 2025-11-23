package aws.scp

# Test Case 1: Deny S3 delete operations
# Mode: deny_set
# Query: data.aws.scp.deny

default allow := false

# Explicit Deny: S3 delete operations
deny contains msg if {
    denied_actions := {
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:DeleteObject"
    }
    denied_actions[input.action]
    msg := sprintf("SCP: %s is explicitly denied", [input.action])
}

# Implicit Deny: all other operations
deny contains "SCP: Implicit Deny - no Allow statement" if {
    not is_explicitly_denied
}

is_explicitly_denied if {
    denied_actions := {
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:DeleteObject"
    }
    denied_actions[input.action]
}
