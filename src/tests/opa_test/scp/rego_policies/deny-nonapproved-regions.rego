
    package aws.scp.Deny_NonApproved_Regions
    default allow = false
    default deny = false
    deny[msg] {
        input.action == "*"
        input.aws:RequestedRegion != "['us-east-1', 'us-west-2', 'eu-west-1']"
        msg := "Deny-NonApproved-Regions triggered for *"
    }
