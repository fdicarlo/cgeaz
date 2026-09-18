variable "subscription_id" {
  description = "The sandbox subscription (TF_VAR_subscription_id). Explicit targeting: never the ambient az context."
  type        = string
}

variable "location" {
  description = "Azure region for the evidence store. Default eastus2: East US frequently lacks Cosmos capacity and consumption-plan quota for new subscriptions."
  type        = string
  default     = "eastus2"
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
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

variable "reports_retention_days" {
  description = "WORM retention on the reports container. 90 for the course; whatever your obligations demand in production."
  type        = number
  default     = 90
}

variable "functions_location" {
  description = "Region for the Function tier. Free-account consumption (Y1) quota is REGIONAL and zero in most US regions; centralus and westus3 had quota in validation. Probe with labs/00-setup/probe-quota.sh."
  type        = string
  default     = "centralus"
}

variable "deployer_object_id" {
  description = "Entra object ID of the human operator who seeds the catalog and proves WORM. Explicit so a CI plan (running as the CI identity) doesn't propose re-pointing these grants at itself — a nightly false-positive drift otherwise. Null = whoever runs apply."
  type        = string
  default     = null
}

variable "exemption_expires_on" {
  description = "Expiry of the risk acceptance for Functions runtime storage using shared keys (docs/EXCEPTIONS.md EXC-01). Time-boxed on purpose: an exemption that never expires is a silent policy change."
  type        = string
  default     = "2027-03-31T00:00:00Z"
}
