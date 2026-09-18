variable "subscription_id" {
  description = "The sandbox subscription (TF_VAR_subscription_id). Explicit targeting: never the ambient az context."
  type        = string
}

variable "remediation_mode" {
  description = "Escalation ladder: audit -> dry-run -> enforce. Each step up should be a reviewed PR — automation acts, humans authorize."
  type        = string
  default     = "dry-run"
  validation {
    condition     = contains(["audit", "dry-run", "enforce"], var.remediation_mode)
    error_message = "remediation_mode must be audit, dry-run, or enforce."
  }
}

variable "location" {
  description = "Assignment location (needed for the identity). Null = the foundation's region."
  type        = string
  default     = null
}

variable "state_resource_group" {
  description = "Resource group holding the Terraform state storage account (from bootstrap.sh)."
  type        = string
  default     = "rg-grc-tfstate"
}

variable "state_storage_account" {
  description = "Terraform state storage account name (from bootstrap.sh / backend.hcl)."
  type        = string
}
