package aws.scp

# Test Case 4: Deny all except S3 read operations (NotAction)
# Mode: deny_set
# Query: data.aws.scp.deny

default allow := false

# Explicit Deny: Actions NOT in the allowed list
deny contains msg if {
    allowed_actions := {
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
    }
    
    # If action is NOT in the allowed list, deny it
    not allowed_actions[input.action]
    
    msg := sprintf("SCP: %s is denied (not in read-only list)", [input.action])
}

# Note: Actions in the allowed list are NOT explicitly denied by this statement
# They fall through to implicit deny (because there's no Allow statement in SCP)
deny contains "SCP: Implicit Deny - no Allow statement" if {
    allowed_actions := {
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
    }
    allowed_actions[input.action]
}
