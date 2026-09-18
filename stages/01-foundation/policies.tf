# Five policies, one initiative, assigned once at mg-grc-sandbox.
# Every subscription that ever joins the sandbox group inherits all of it. (CSF: GV.PO, PR.DS, PR.PS, PR.AA)
# 1-3 are the course starter; 4-5 are this capstone's own controls: the pipeline's
# "zero keys" design rule, applied to everything else in the sandbox.

# --- 1. Require the `env` tag on resource groups (inventory hygiene; POA&M owner resolution) ---

resource "azurerm_policy_definition" "require_env_tag" {
  name                = "cge-require-env-tag-rg"
  display_name        = "Resource groups must carry an env tag"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Resources/subscriptions/resourceGroups" },
        { field = "tags['env']", exists = "false" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 2. Deny public blob access on storage accounts (clear-cut, framework-mandated: earned Deny) ---
# blast radius: every create/update of a storage account in mg-grc-sandbox that sets
#   allowBlobPublicAccess=true is refused (RequestDisallowedByPolicy), including the
#   Lab 6 sabotage. Existing accounts are not changed; they show NonCompliant.
# who notices: anyone deploying a public static-asset account; the error names this policy.
# rollback: public_blob_policy_effect = "Audit" via a reviewed PR (the Lab 6 de-escalation).

resource "azurerm_policy_definition" "deny_public_blob" {
  name                = "cge-deny-public-blob"
  display_name        = "Storage accounts must not allow public blob access"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", equals = "true" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 3. deployIfNotExists: storage accounts missing diagnostic settings get them, routed to the GRC workspace ---
# Logging that enforces its own coverage. Remediation runs AS the identity in identity.tf.
# blast radius: adds one diagnostic setting (Transaction metrics -> law-grc-sandbox) to
#   storage accounts in mg-grc-sandbox, only via a remediation task. Never deletes or
#   rewrites existing settings. Cost: workspace ingestion for metrics, pennies at lab scale.
# rollback: remove the definition reference from the initiative; settings already
#   deployed stay until deleted deliberately.

resource "azurerm_policy_definition" "storage_diagnostics" {
  name                = "cge-dine-storage-diagnostics"
  display_name        = "Storage accounts must route diagnostics to the GRC workspace"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    workspaceId = {
      type     = "String"
      metadata = { displayName = "Log Analytics workspace resource ID" }
    }
  })

  policy_rule = jsonencode({
    "if" = {
      field  = "type"
      equals = "Microsoft.Storage/storageAccounts"
    }
    then = {
      effect = "DeployIfNotExists"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        roleDefinitionIds = [
          # Monitoring Contributor
          "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
        ]
        existenceCondition = {
          allOf = [
            { field = "Microsoft.Insights/diagnosticSettings/workspaceId", equals = "[parameters('workspaceId')]" }
          ]
        }
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              resourceName = { value = "[field('name')]" }
              workspaceId  = { value = "[parameters('workspaceId')]" }
              location     = { value = "[field('location')]" }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                resourceName = { type = "string" }
                workspaceId  = { type = "string" }
                location     = { type = "string" }
              }
              resources = [
                {
                  type       = "Microsoft.Storage/storageAccounts/providers/diagnosticSettings"
                  apiVersion = "2021-05-01-preview"
                  name       = "[concat(parameters('resourceName'), '/Microsoft.Insights/ds-to-grc-workspace')]"
                  properties = {
                    workspaceId = "[parameters('workspaceId')]"
                    metrics = [
                      { category = "Transaction", enabled = true }
                    ]
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}

# --- 4. OWN CONTROL: Cosmos DB accounts must disable local (key) authentication ---
# The evidence store runs identity-only; any other Cosmos account in the sandbox should
# too. A new control, so it enters at Audit: the compliance data tells us what would
# break before we escalate. Escalation is a one-line reviewed change to
# var.cosmos_local_auth_policy_effect. (CSF: PR.AA · 800-53: IA-2, AC-3)
# blast radius (at Audit): none, reporting only. At Deny: any Cosmos account create/update
#   leaving key auth on is refused; apps still using keys must move to Entra first.

resource "azurerm_policy_definition" "cosmos_local_auth" {
  name                = "cge-audit-cosmos-local-auth"
  display_name        = "Cosmos DB accounts must disable local (key-based) authentication"
  description         = "Own control (capstone). Account keys are long-lived shared secrets; Entra ID data-plane RBAC gives every read and write a named identity."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Cosmos DB", csf = ["PR.AA"], owner = "grc-engineering" })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.DocumentDB/databaseAccounts" },
        {
          anyOf = [
            { field = "Microsoft.DocumentDB/databaseAccounts/disableLocalAuth", exists = "false" },
            { field = "Microsoft.DocumentDB/databaseAccounts/disableLocalAuth", equals = "false" }
          ]
        }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 5. OWN CONTROL: storage accounts should not permit shared-key authorization ---
# Audit, deliberately not Deny: the Functions runtime storage accounts (stages 03/04)
# still need a key on the Consumption plan. Those two are carried as time-boxed policy
# exemptions (risk acceptances with an expiry date) declared next to the resources
# they cover, and listed in docs/EXCEPTIONS.md. (CSF: PR.AA · 800-53: IA-5, AC-3)
# blast radius (at Audit): none, reporting only. Deny would break Consumption Functions
#   runtime storage on its next update, which is why Deny is not on the ladder yet.

resource "azurerm_policy_definition" "storage_shared_key" {
  name                = "cge-audit-storage-shared-key"
  display_name        = "Storage accounts should disable shared-key authorization"
  description         = "Own control (capstone). Shared keys grant full data-plane access with no identity attached; Entra ID auth makes every access attributable."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({ category = "Storage", csf = ["PR.AA"], owner = "grc-engineering" })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        {
          anyOf = [
            { field = "Microsoft.Storage/storageAccounts/allowSharedKeyAccess", exists = "false" },
            { field = "Microsoft.Storage/storageAccounts/allowSharedKeyAccess", equals = "true" }
          ]
        }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- The initiative: one assignment, whole-sandbox inheritance ---

resource "azurerm_management_group_policy_set_definition" "grc_baseline" {
  name                = "cge-grc-baseline"
  display_name        = "CGE-AZ GRC Baseline"
  policy_type         = "Custom"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    tagEffect              = { type = "String", defaultValue = "Audit" }
    publicBlobEffect       = { type = "String", defaultValue = "Deny" }
    workspaceId            = { type = "String" }
    cosmosLocalAuthEffect  = { type = "String", defaultValue = "Audit" }
    storageSharedKeyEffect = { type = "String", defaultValue = "Audit" }
  })

  # reference_id values are the stable handles that policy exemptions target
  # (stages 03/04 exempt their runtime storage from storage-shared-key only).

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_env_tag.id
    reference_id         = "require-env-tag"
    parameter_values = jsonencode({
      effect = { value = "[parameters('tagEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.deny_public_blob.id
    reference_id         = "deny-public-blob"
    parameter_values = jsonencode({
      effect = { value = "[parameters('publicBlobEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.storage_diagnostics.id
    reference_id         = "storage-diagnostics"
    parameter_values = jsonencode({
      workspaceId = { value = "[parameters('workspaceId')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.cosmos_local_auth.id
    reference_id         = "cosmos-local-auth"
    parameter_values = jsonencode({
      effect = { value = "[parameters('cosmosLocalAuthEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.storage_shared_key.id
    reference_id         = "storage-shared-key"
    parameter_values = jsonencode({
      effect = { value = "[parameters('storageSharedKeyEffect')]" }
    })
  }
}

resource "azurerm_management_group_policy_assignment" "grc_baseline" {
  name                 = "cge-grc-baseline"
  display_name         = "CGE-AZ GRC Baseline"
  policy_definition_id = azurerm_management_group_policy_set_definition.grc_baseline.id
  management_group_id  = azurerm_management_group.sandbox.id
  location             = var.location

  parameters = jsonencode({
    tagEffect              = { value = var.tag_policy_effect }
    publicBlobEffect       = { value = var.public_blob_policy_effect }
    workspaceId            = { value = azurerm_log_analytics_workspace.grc.id }
    cosmosLocalAuthEffect  = { value = var.cosmos_local_auth_policy_effect }
    storageSharedKeyEffect = { value = var.storage_shared_key_policy_effect }
  })

  non_compliance_message {
    content = "Blocked or flagged by the CGE-AZ GRC Baseline (mg-grc-sandbox). Controls and exceptions: docs/CONTROLS.md, docs/EXCEPTIONS.md in the pipeline repo."
  }

  # Remediation effects (deployIfNotExists) execute AS this identity.
  # Without this block, Terraform applies cleanly and remediation silently never runs.
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }
}
