package aws.scp

default deny := false

deny := true if {
    denied_actions := {
        "ec2:TerminateInstances",
        "ec2:StopInstances"
    }
    denied_actions[input.action]
}

deny := true if {
    denied_actions := {
        "ec2:TerminateInstances",
        "ec2:StopInstances"
    }
    not denied_actions[input.action]
}