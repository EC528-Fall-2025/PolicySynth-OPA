package aws.scp

default allow := false

approved_regions := {"us-east-1", "us-west-2"}

approved_region if {
  region := input.context["aws:RequestedRegion"]
  region != null
  region in approved_regions
}

deny contains msg if {
  not approved_region
  msg := sprintf("SCP: region %v is not approved", [input.context["aws:RequestedRegion"]])
}

allow if {
  approved_region
}
