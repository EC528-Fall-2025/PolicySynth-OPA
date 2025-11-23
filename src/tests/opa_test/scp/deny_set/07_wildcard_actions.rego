package aws.scp

# Test Case 7: Wildcard actions and resources
# Mode: deny_set
# Query: data.aws.scp.deny

import future.keywords.contains
import future.keywords.if

default allow := false

# Statement 1: Deny all EC2 and RDS operations
deny contains msg if {
    # Check if action starts with ec2: or rds:
    action_prefix := split(input.action, ":")[0]
    action_prefix == "ec2"
    msg := sprintf("SCP: %s is denied (all EC2 operations)", [input.action])
}

deny contains msg if {
    action_prefix := split(input.action, ":")[0]
    action_prefix == "rds"
    msg := sprintf("SCP: %s is denied (all RDS operations)", [input.action])
}

# Statement 2: Deny Lambda in ap-* regions
deny contains msg if {
    action_prefix := split(input.action, ":")[0]
    action_prefix == "lambda"
    
    # Check if resource is in ap-* region
    startswith(input.resource, "arn:aws:lambda:ap-")
    
    msg := sprintf("SCP: %s on %s is denied (Lambda in AP region)", [input.action, input.resource])
}

# Implicit Deny: all other operations
deny contains "SCP: Implicit Deny - no Allow statement" if {
    not is_explicitly_denied
}

is_explicitly_denied if {
    action_prefix := split(input.action, ":")[0]
    action_prefix == "ec2"
}

is_explicitly_denied if {
    action_prefix := split(input.action, ":")[0]
    action_prefix == "rds"
}

is_explicitly_denied if {
    action_prefix := split(input.action, ":")[0]
    action_prefix == "lambda"
    startswith(input.resource, "arn:aws:lambda:ap-")
}
