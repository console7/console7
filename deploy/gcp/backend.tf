# Partial backend: the state bucket (and optional prefix) are supplied at init via
# -backend-config, never hardcoded. State may reveal project identifiers and must live
# in the adopter's own bucket (ADR-0002; repo hygiene: never commit Terraform state).
terraform {
  backend "gcs" {}
}
