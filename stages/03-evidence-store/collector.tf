# --- The collector Function App: timer-triggered Python, managed identity, zero keys. ---
# One app for collectors, a separate app (stage 04) for reporting: the Function App is
# the identity boundary, and no identity both writes evidence and generates reports.

# Internal plumbing storage for the Functions runtime (NOT the evidence store —
# that account has shared keys disabled; this one is the app's own scratch space).
resource "azurerm_storage_account" "func_internal" {
  name                            = "stgrcfunc${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  # The runtime mints SAS URLs (run-from-package). Over-long ones get logged.
  sas_policy {
    expiration_period = "7.00:00:00"
    expiration_action = "Log"
  }

  tags = local.common_tags
}

resource "azurerm_service_plan" "collectors" {
  name                = "asp-grc-collectors-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption: pay per execution. Pennies.
  tags                = local.common_tags
}

# Run history lives here: every invocation (timer or HTTP) lands in AppRequests in the
# GRC workspace — queryable next to the Activity Log (saved search: grc-pipeline-run-history).
resource "azurerm_application_insights" "pipeline" {
  name                = "appi-grc-pipeline-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.location
  workspace_id        = data.terraform_remote_state.foundation.outputs.log_analytics_workspace_id
  application_type    = "other"
  retention_in_days   = 90
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "collectors" {
  https_only = true

  name                       = "func-grc-collectors-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.collectors.id
  storage_account_name       = azurerm_storage_account.func_internal.name
  storage_account_access_key = azurerm_storage_account.func_internal.primary_access_key

  identity {
    type = "SystemAssigned"
  }

  site_config {
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"
    application_stack {
      python_version = "3.11"
    }
    application_insights_connection_string = azurerm_application_insights.pipeline.connection_string
  }

  app_settings = {
    "COSMOS_ENDPOINT"                = azurerm_cosmosdb_account.evidence.endpoint
    "COSMOS_DATABASE"                = azurerm_cosmosdb_sql_database.grc.name
    "SUBSCRIPTION_ID"                = local.subscription
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
  }

  tags = local.common_tags
}

# --- The collector identity's whitelist: read posture, write evidence. Nothing else. ---

# Security Reader at the subscription: read Defender assessments, change nothing.
resource "azurerm_role_assignment" "collector_security_reader" {
  scope                = "/subscriptions/${local.subscription}"
  role_definition_name = "Security Reader"
  principal_id         = azurerm_linux_function_app.collectors.identity[0].principal_id
}

# Cosmos data-plane write. "Cosmos DB Built-in Data Contributor" (00000000-0000-0000-0000-000000000002)
# is a Cosmos-native data-plane role, not an ARM role — control plane vs data plane, again.
resource "azurerm_cosmosdb_sql_role_assignment" "collector_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_linux_function_app.collectors.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.evidence.id
}

# Policy compliance is the second evidence source: the collector records the state of
# this repo's own cge-* policies next to Defender's assessments (collect once, one
# schema). Security Reader doesn't reliably cover the Policy Insights query API, and
# Reader would be broader than the job, so the grant is a one-action custom role.
resource "azurerm_role_definition" "policy_state_reader" {
  name        = "GRC Policy State Reader (${var.environment})"
  scope       = "/subscriptions/${local.subscription}"
  description = "Read Azure Policy compliance states. Nothing else. Held by the GRC collector."

  permissions {
    actions = [
      "Microsoft.PolicyInsights/policyStates/queryResults/read",
      "Microsoft.PolicyInsights/policyStates/summarize/read",
    ]
    not_actions = []
  }

  assignable_scopes = ["/subscriptions/${local.subscription}"]
}

resource "azurerm_role_assignment" "collector_policy_states" {
  scope              = "/subscriptions/${local.subscription}"
  role_definition_id = azurerm_role_definition.policy_state_reader.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.collectors.identity[0].principal_id
}

# --- EXC-01: the one documented exception to "zero keys" (docs/EXCEPTIONS.md) ---
# Consumption-plan Functions keep their runtime state (AzureWebJobsStorage) in a
# storage account reached by key. That account holds no evidence. The exemption covers
# ONLY the storage-shared-key control, ONLY for this account, and it expires.
resource "azurerm_resource_policy_exemption" "func_internal_shared_key" {
  name                            = "exc-01-collector-runtime-shared-key"
  display_name                    = "EXC-01: collector Functions runtime storage uses a shared key"
  description                     = "Consumption-plan Functions runtime (AzureWebJobsStorage). No evidence stored here. Revisit on move to Flex Consumption with identity-based host storage."
  resource_id                     = azurerm_storage_account.func_internal.id
  policy_assignment_id            = data.terraform_remote_state.foundation.outputs.baseline_assignment_id
  policy_definition_reference_ids = ["storage-shared-key"]
  exemption_category              = "Waiver"
  expires_on                      = var.exemption_expires_on
  metadata                        = jsonencode({ exceptionId = "EXC-01", register = "docs/EXCEPTIONS.md" })
}
