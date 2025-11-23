
    package aws.scp.Require_IMDSv2_For_EC2
    default allow = false
    default deny = false
    deny[msg] {
        input.action == "ec2:RunInstances"
        input.ec2:MetadataHttpTokens != "required"
        msg := "Require-IMDSv2-For-EC2 triggered for ec2:RunInstances"
    }
