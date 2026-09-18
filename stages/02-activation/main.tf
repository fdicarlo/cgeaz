data "azurerm_subscription" "current" {}

# ---------------------------------------------------------------------------
# STAGE 1 — DISCOVERY: detect what's already running.
# Pure reads. Run this stage a hundred times and it changes nothing on its own.
# ---------------------------------------------------------------------------

# Current tier of every Defender plan in the baseline. Free or Standard.
data "azapi_resource" "pricing" {
  for_each = var.baseline_plans

  type                   = "Microsoft.Security/pricings@2024-01-01"
  parent_id              = data.azurerm_subscription.current.id
  name                   = each.key
  response_export_values = ["properties.pricingTier"]
}

# What is actually running: a typed inventory from Azure Resource Graph (resource count
# per type). Discovery's second output, next to the gap map: activation only earns
# its keep if you know what it is protecting. Storage and Key Vault counts are what
# the two baseline Defender plans bill against.
data "azapi_resource_action" "inventory" {
  type        = "Microsoft.ResourceGraph@2022-10-01"
  resource_id = "/providers/Microsoft.ResourceGraph"
  action      = "resources"
  method      = "POST"
  body = {
    subscriptions = [data.azurerm_subscription.current.subscription_id]
    query         = "Resources | summarize count() by type | order by type asc"
    options       = { resultFormat = "objectArray" }
  }
  response_export_values = ["data"]
}

locals {
  inventory = {
    for row in try(data.azapi_resource_action.inventory.output.data, []) :
    row.type => row.count_
  }

  current_tier = {
    for plan, d in data.azapi_resource.pricing :
    plan => d.output.properties.pricingTier
  }

  # The gap map: what the baseline required that wasn't already on when this
  # plan ran. An INVENTORY OUTPUT, deliberately not the resource key — keying
  # resources on live tiers you're about to change makes Terraform destroy the
  # plan it just enabled on the next run (read-your-own-writes). We validated
  # that failure mode so you don't have to.
  activation_needed = {
    for plan, tier in local.current_tier : plan => tier
    if tier != "Standard"
  }
}

# ---------------------------------------------------------------------------
# STAGE 2 — ACTIVATION: converge the baseline to Standard.
# Idempotent: a plan you already enabled (Lab 2's Defender for Storage) stays
# exactly as it is — same tier, now change-managed. Plans OUTSIDE the baseline
# are never touched. Teardown (`terraform destroy`) flips baseline plans back
# to Free, which is precisely what course cleanup wants.
# ---------------------------------------------------------------------------

# Activation acts only inside the baseline and is driven by discovery: a plan already at
# Standard converges with no change; a Free plan in the gap map is the only thing an
# apply moves.
# Keyed on the baseline (not the gap) on purpose: see VALIDATION-LOG F13.
resource "azurerm_security_center_subscription_pricing" "baseline" {
  for_each = var.baseline_plans

  tier          = "Standard"
  resource_type = each.key
  subplan       = each.value != "" ? each.value : null
}

# The NIST CSF 2.0 compliance standard, as code. You assigned this by hand in
# Lab 2 — ADOPT it here with `terraform import` (Lab 4 guide, step 1); don't
# delete and recreate a live assignment. Codified, a whole assessment posture
# stands up from an empty subscription with one apply.
resource "azurerm_subscription_policy_assignment" "nist_csf_20" {
  name                 = "nist-csf-20"
  display_name         = "NIST CSF v2.0"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/184a0e05-7b06-4a68-bbbe-13b8353bc613"
  subscription_id      = data.azurerm_subscription.current.id
}

