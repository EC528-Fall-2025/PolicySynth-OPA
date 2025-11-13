package aws.scp

default allow := false

allow := true if {
  true
}

deny contains msg if {
  false
  msg := "unused"
}
