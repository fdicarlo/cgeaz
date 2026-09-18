variable "subscription_id" {
  description = "The sandbox subscription this pipeline governs. Set via TF_VAR_subscription_id (scripts/deploy.sh and CI do this)."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.subscription_id))
    error_message = "subscription_id must be a subscription GUID."
  }
}

variable "location" {
  description = "Azure region for foundation resources."
  type        = string
  default     = "eastus"
}

variable "owner_email" {
  description = "Owner tag applied to governed resource groups (the collector stores it, the POA&M resolves finding owners from it). Also the budget and tripwire alert recipient."
  type        = string
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
}

variable "tag_policy_effect" {
  description = "Effect for the require-env-tag policy (Audit while onboarding, Deny once clean)."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.tag_policy_effect)
    error_message = "tag_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "public_blob_policy_effect" {
  description = "Effect for the deny-public-blob-access policy. This one has earned Deny."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.public_blob_policy_effect)
    error_message = "public_blob_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "cosmos_local_auth_policy_effect" {
  description = "Effect for cge-audit-cosmos-local-auth (own control). New control, so Audit first; Deny once the compliance data says nothing legitimate still uses account keys."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.cosmos_local_auth_policy_effect)
    error_message = "cosmos_local_auth_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "storage_shared_key_policy_effect" {
  description = "Effect for cge-audit-storage-shared-key (own control). Audit only: Functions runtime storage still needs a key on the Consumption plan, handled as time-boxed exemptions (docs/EXCEPTIONS.md)."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.storage_shared_key_policy_effect)
    error_message = "storage_shared_key_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "budget_amount" {
  description = "Monthly cost budget (USD) for the sandbox subscription. Alerts at 80% actual and 100% forecast."
  type        = number
  default     = 10
}

variable "budget_start_date" {
  description = "Budget period start (first day of a month, RFC3339). Static on purpose: a timestamp()-derived value would drift every run."
  type        = string
  default     = "2026-09-01T00:00:00Z"
}

variable "trusted_automation_callers" {
  description = "Object/app IDs whose control-plane writes are expected (e.g. the CI identity). Everything else writing to the subscription trips the out-of-band change alert. The remediation identity is always trusted."
  type        = list(string)
  default     = []
}
