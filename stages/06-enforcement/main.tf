locals {
  mg_id           = data.terraform_remote_state.foundation.outputs.management_group_id
  remediation_id  = data.terraform_remote_state.foundation.outputs.remediation_identity_id
  remediation_pid = data.terraform_remote_state.foundation.outputs.remediation_identity_principal_id

  # The escalation ladder, wired to one variable. Each step up is a reviewed PR:
  #   audit   -> observe only; count what would change
  #   dry-run -> modify effect deployed, but enforcement_mode DoNotEnforce;
  #              you create the remediation task manually = the human approval
  #   enforce -> modify effect, enforced automatically
  effect           = var.remediation_mode == "audit" ? "Audit" : "Modify"
  enforcement_mode = var.remediation_mode == "enforce" ? "Default" : "DoNotEnforce"
}

# blast radius: flips allowBlobPublicAccess to false on existing storage accounts
# under mg-grc-sandbox (every subscription in it, current and future). Cannot delete
# anything, cannot read data, cannot touch any other property.
# who notices: anything serving anonymous blob reads from those accounts (static
#   assets, public downloads) starts returning 403/409 once remediated.
# conflictEffect=audit: if another policy also modifies the property, this one steps
#   back to reporting rather than fighting it.
# rollback: set remediation_mode back to "audit" and merge; the storage role grant is
#   removed in the same apply, so the identity loses the ability, not just the task.
resource "azurerm_policy_definition" "fix_public_blob" {
  name                = "cge-fix-public-blob"
  display_name        = "Remediate: disable public blob access on storage accounts"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = local.mg_id

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", notEquals = "false" }
      ]
    }
    then = {
      effect = local.effect == "Audit" ? "Audit" : "Modify"
      details = local.effect == "Audit" ? null : {
        roleDefinitionIds = [
          # Storage Account Contributor — the narrowest built-in that can write this property
          "/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab"
        ]
        conflictEffect = "audit"
        operations = [
          { operation = "addOrReplace", field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", value = false }
        ]
      }
    }
  })
}

resource "azurerm_management_group_policy_assignment" "fix_public_blob" {
  name                 = "cge-fix-public-blob"
  display_name         = "Remediate public blob access (${var.remediation_mode})"
  policy_definition_id = azurerm_policy_definition.fix_public_blob.id
  management_group_id  = local.mg_id
  location             = coalesce(var.location, data.terraform_remote_state.foundation.outputs.location)
  description          = "Escalation ladder rung: ${var.remediation_mode}. Change only via a reviewed PR to stages/06-enforcement/variables.tf."
  enforce              = local.enforcement_mode == "Default"

  identity {
    type         = "UserAssigned"
    identity_ids = [local.remediation_id]
  }
}

# The remediation identity earns the storage role only when remediation can actually run.
# blast radius: Storage Account Contributor at mg-grc-sandbox = manage (not read data
# of) every storage account in the sandbox. Narrowest built-in that can write
# allowBlobPublicAccess; the policy's `operations` limit what it is used for.
resource "azurerm_role_assignment" "remediation_storage" {
  count                = var.remediation_mode == "audit" ? 0 : 1
  scope                = local.mg_id
  role_definition_name = "Storage Account Contributor"
  principal_id         = local.remediation_pid
}
