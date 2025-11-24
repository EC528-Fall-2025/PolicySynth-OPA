package aws.scp

# Test Case 5: Deny IAM changes outside us-east-1
# Mode: deny_set
# Query: data.aws.scp.deny

default allow := false

# Explicit Deny: IAM operations outside us-east-1
deny contains msg if {
    denied_actions := {
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateRole",
        "iam:DeleteRole"
    }
    denied_actions[input.action]
    
    # Condition: region is NOT us-east-1
    requested_region := input.context["aws:RequestedRegion"]
    requested_region != "us-east-1"
    
    msg := sprintf("SCP: %s is denied outside us-east-1 (region: %s)", [input.action, requested_region])
}

# Implicit Deny: all other operations
deny contains "SCP: Implicit Deny - no Allow statement" if {
    not is_explicitly_denied
}

is_explicitly_denied if {
    denied_actions := {
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateRole",
        "iam:DeleteRole"
    }
    denied_actions[input.action]
    requested_region := input.context["aws:RequestedRegion"]
    requested_region != "us-east-1"
}
