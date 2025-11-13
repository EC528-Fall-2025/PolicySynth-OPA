package aws.scp

default allow := false

allow if {
  input.action == "s3:DeleteObject"
}
