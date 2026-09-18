# The stage contract: what discovery found and what activation is closing.
# `terraform output` here doubles as a live plan-coverage inventory — the first
# artifact every assessment asks for, free.

output "current_plan_tiers" {
  description = "Every baseline Defender plan and its tier as discovered this run."
  value       = local.current_tier
}

output "activation_needed" {
  description = "The gap map this apply closes. Empty means the baseline is fully met."
  value       = local.activation_needed
}

output "inventory" {
  description = "Resource Graph inventory: resource count per type in the governed subscription, as discovered this run."
  value       = local.inventory
}

output "plan_coverage" {
  description = "For each baseline plan: current tier and how many resources of the type it protects exist right now."
  value = {
    for plan, tier in local.current_tier : plan => {
      tier = tier
      protected_resources = lookup({
        StorageAccounts = lookup(local.inventory, "microsoft.storage/storageaccounts", 0)
        KeyVaults       = lookup(local.inventory, "microsoft.keyvault/vaults", 0)
      }, plan, null)
    }
  }
}
