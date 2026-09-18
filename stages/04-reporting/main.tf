locals {
  evidence_rg      = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  cosmos_endpoint  = data.terraform_remote_state.evidence.outputs.cosmos_endpoint
  cosmos_id        = data.terraform_remote_state.evidence.outputs.cosmos_account_id
  cosmos_name      = data.terraform_remote_state.evidence.outputs.cosmos_account_name
  evidence_storage = data.terraform_remote_state.evidence.outputs.evidence_storage_account
  common_tags = {
    env     = var.environment
    purpose = "grc-reporting"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

data "azurerm_storage_account" "evidence" {
  name                = local.evidence_storage
  resource_group_name = local.evidence_rg
}

resource "azurerm_storage_account" "func_internal" {
  name                            = "stgrcrpt${random_string.suffix.result}"
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

resource "azurerm_service_plan" "reporting" {
  name                = "asp-grc-reporting-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "reporting" {
  https_only = true

  name                       = "func-grc-reporting-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.reporting.id
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
    # Same telemetry sink as the collector: one run-history query covers both identities.
    application_insights_connection_string = data.terraform_remote_state.evidence.outputs.app_insights_connection_string
  }

  app_settings = {
    "COSMOS_ENDPOINT"                = local.cosmos_endpoint
    "COSMOS_DATABASE"                = "grc"
    "REPORTS_ACCOUNT_URL"            = data.azurerm_storage_account.evidence.primary_blob_endpoint
    "REPORTS_CONTAINER"              = "reports"
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "ENABLE_ORYX_BUILD"              = "true"
  }

  tags = local.common_tags
}

# --- The reporting identity's whitelist — the mirror image of the collector's. ---
# Cosmos READ (built-in Data Reader), Blob WRITE into the WORM container. No path to
# live platform data: no Security Reader, no Cosmos write. SoD, enforced by scopes.
# The Cosmos-only rule is therefore not a coding convention the generators follow —
# the reporter's identity physically cannot read a live platform API.

resource "azurerm_cosmosdb_sql_role_assignment" "reporter_cosmos_read" {
  resource_group_name = local.evidence_rg
  account_name        = local.cosmos_name
  role_definition_id  = "${local.cosmos_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
  principal_id        = azurerm_linux_function_app.reporting.identity[0].principal_id
  scope               = local.cosmos_id
}

# Scoped to the reports CONTAINER, not the account. Contributor includes delete, but
# the container's WORM policy refuses deletes and overwrites for the retention period
# (scripts/prove-worm.sh shows the failure), so the effective right is append-only.
resource "azurerm_role_assignment" "reporter_blob_write" {
  scope                = "${data.azurerm_storage_account.evidence.id}/blobServices/default/containers/reports"
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_function_app.reporting.identity[0].principal_id
}

# EXC-01 for the reporter's runtime storage (see stage 03 and docs/EXCEPTIONS.md).
resource "azurerm_resource_policy_exemption" "func_internal_shared_key" {
  name                            = "exc-01-reporter-runtime-shared-key"
  display_name                    = "EXC-01: reporter Functions runtime storage uses a shared key"
  description                     = "Consumption-plan Functions runtime (AzureWebJobsStorage). No evidence stored here. Revisit on move to Flex Consumption with identity-based host storage."
  resource_id                     = azurerm_storage_account.func_internal.id
  policy_assignment_id            = data.terraform_remote_state.foundation.outputs.baseline_assignment_id
  policy_definition_reference_ids = ["storage-shared-key"]
  exemption_category              = "Waiver"
  expires_on                      = var.exemption_expires_on
  metadata                        = jsonencode({ exceptionId = "EXC-01", register = "docs/EXCEPTIONS.md" })
}
