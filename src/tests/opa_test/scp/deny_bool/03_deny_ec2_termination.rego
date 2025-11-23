package aws.scp

# Test Case 3: Deny EC2 termination
# Mode: deny_bool
# Query: data.aws.scp.deny

default deny := false

# Explicit Deny: EC2 termination operations
deny := true if {
    denied_actions := {
        "ec2:TerminateInstances",
        "ec2:StopInstances"
    }
    denied_actions[input.action]
}

# Implicit Deny: all other operations (no Allow statements)
deny := true if {
    denied_actions := {
        "ec2:TerminateInstances",
        "ec2:StopInstances"
    }
    not denied_actions[input.action]
}
