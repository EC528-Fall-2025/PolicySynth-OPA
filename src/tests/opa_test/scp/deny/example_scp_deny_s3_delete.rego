package aws.scp

default allow := false

deny := { msg |
  input.action == "s3:DeleteBucket"
  msg := "SCP: s3:DeleteBucket is denied by policy"
}
