package aws.scp

# Test Case 2: Deny production S3 changes
# Mode: deny_set
# Query: data.aws.scp.deny

default allow := false

# Explicit Deny: production S3 operations
deny contains msg if {
    denied_actions := {
        "s3:PutBucketPolicy",
        "s3:DeleteBucket",
        "s3:PutBucketAcl"
    }
    denied_actions[input.action]
    
    # Check if resource matches production patterns
    matches_production_resource
    
    msg := sprintf("SCP: %s on %s is denied (production resource)", [input.action, input.resource])
}

# Check if resource matches production patterns
matches_production_resource if {
    startswith(input.resource, "arn:aws:s3:::production-")
}

matches_production_resource if {
    startswith(input.resource, "arn:aws:s3:::prod-")
}

# Implicit Deny: all other operations
deny contains "SCP: Implicit Deny - no Allow statement" if {
    not is_explicitly_denied
}

is_explicitly_denied if {
    denied_actions := {
        "s3:PutBucketPolicy",
        "s3:DeleteBucket",
        "s3:PutBucketAcl"
    }
    denied_actions[input.action]
    matches_production_resource
}
