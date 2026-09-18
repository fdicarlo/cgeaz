output "remediation_mode" {
  value = var.remediation_mode
}

output "remediation_assignment_id" {
  description = "Full resource ID — `az policy remediation create --policy-assignment` needs it (VALIDATION-LOG, Lab 6 caveat)."
  value       = azurerm_management_group_policy_assignment.fix_public_blob.id
}
