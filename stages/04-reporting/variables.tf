variable "subscription_id" {
  description = "The sandbox subscription (TF_VAR_subscription_id). Explicit targeting: never the ambient az context."
  type        = string
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
}

variable "functions_location" {
  description = "Region for the reporting Function tier. Same free-account quota constraint as stage 03 — probe with labs/00-setup/probe-quota.sh."
  type        = string
  default     = "centralus"
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

variable "exemption_expires_on" {
  description = "Expiry of EXC-01 for the reporter's runtime storage (docs/EXCEPTIONS.md)."
  type        = string
  default     = "2027-03-31T00:00:00Z"
}
