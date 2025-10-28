
    package aws.scp.Require_Tags_And_VPC_For_EC2
    default allow = false
    default deny = false
    deny[msg] {
        input.action == "ec2:RunInstances"
        
        msg := "Require-Tags-And-VPC-For-EC2 triggered for ec2:RunInstances"
    }

deny[msg] {
        input.action == "ec2:RunInstances"
        input.ec2:Vpc != "['arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc123def4567890', 'arn:aws:ec2:us-west-2:123456789012:vpc/vpc-0abc123def4567891']"
        msg := "Require-Tags-And-VPC-For-EC2 triggered for ec2:RunInstances"
    }
