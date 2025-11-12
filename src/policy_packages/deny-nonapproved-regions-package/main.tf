
terraform {
  required_providers {
    opa = {
      source  = "openpolicyagent/opa"
      version = ">=0.5.0"
    }
  }
}

resource "opa_policy" "deny-nonapproved-regions" {
  name   = "deny-nonapproved-regions"
  policy = file("${path.module}/policies/deny-nonapproved-regions.rego")
}
