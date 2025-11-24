package aws.scp

default allow := false

explicit_deny contains msg if {
    denied_actions := {
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:DeleteBucketWebsite"
    }
    denied_actions[input.action]
    msg := sprintf("SCP: %s is explicitly denied", [input.action])
}

implicit_deny contains msg if {
    not explicit_allow
    msg := "SCP: No explicit Allow - implicit Deny"
}

explicit_allow := false

deny := explicit_deny | implicit_deny