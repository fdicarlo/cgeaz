locals {
  evidence_rg  = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  subscription = data.terraform_remote_state.foundation.outputs.subscription_id
  deployer     = coalesce(var.deployer_object_id, data.azurerm_client_config.current.object_id)
  common_tags = {
    env     = var.environment
    purpose = "grc-evidence-plane"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# --- Cosmos DB: the evidence database we OWN. Serverless; pennies at lab scale. ---

resource "azurerm_cosmosdb_account" "evidence" {
  name                = "cosmos-grc-evidence-${random_string.suffix.result}"
  location            = var.location
  resource_group_name = local.evidence_rg
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  # Identity-only access: no key-based auth against the evidence database.
  # local_authentication_disabled was deprecated in favour of local_authentication_enabled
  # (removed in azurerm v5.0); the boolean inverts, so disabled=true becomes enabled=false.
  local_authentication_enabled = false
  # Keys can't be used anyway; this also stops anything but ARM (i.e. Terraform, reviewed)
  # from changing account metadata such as containers and throughput.
  access_key_metadata_writes_enabled = false

  capabilities {
    name = "EnableServerless"
  }

  # Point-in-time restore: an evidence store that can't be recovered to a known moment
  # is a single bad write away from losing its receipts. Continuous7Days is free tier.
  backup {
    type = "Continuous"
    tier = "Continuous7Days"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  tags = local.common_tags
}

resource "azurerm_cosmosdb_sql_database" "grc" {
  name                = "grc"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
}

# assessments: APPEND-ONLY, one document per finding per run (id = hash(findingKey + runId)),
# so any past report is reproducible by its runId query. Partitioned by subscription.
resource "azurerm_cosmosdb_sql_container" "assessments" {
  name                = "assessments"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/subscriptionId"]
}

# runs: the run ledger. One document per collection sweep (runId, collectedAt, trigger,
# counts, errors), written last, so a run exists only once its documents do. Reports
# pin to the newest entry; the ledger is the run history that accumulates.
resource "azurerm_cosmosdb_sql_container" "runs" {
  name                = "runs"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/subscriptionId"]
}

# frameworks: CSF 2.0 / 800-53 catalogs as records we own.
resource "azurerm_cosmosdb_sql_container" "frameworks" {
  name                = "frameworks"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# mappings: the crosswalk — which assessment satisfies which control in which framework.
resource "azurerm_cosmosdb_sql_container" "mappings" {
  name                = "mappings"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# --- Evidence artifact storage: WORM reports container, zero shared keys. ---

resource "azurerm_storage_account" "evidence" {
  name                     = "stgrcevid${random_string.suffix.result}"
  resource_group_name      = local.evidence_rg
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # The store's front door has one kind of lock: identity.
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true

    # Belt and braces under WORM: soft delete catches what immutability doesn't
    # cover (e.g. a whole container, or blobs outside `reports`).
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  tags = local.common_tags
}

resource "azurerm_storage_container" "reports" {
  name               = "reports"
  storage_account_id = azurerm_storage_account.evidence.id
}

# WORM: write once, read many. Not access control — a platform guarantee.
resource "azurerm_storage_container_immutability_policy" "reports_worm" {
  # resource_manager_id was deprecated on azurerm_storage_container; id now returns the
  # resource-manager ID this argument expects.
  storage_container_resource_manager_id = azurerm_storage_container.reports.id
  immutability_period_in_days           = var.reports_retention_days
  # Unlocked for the course so teardown works. Production locks it — after which
  # nobody, including Microsoft, can shorten or remove it.
}

# The deployer needs blob DATA-plane access to verify WORM behavior and upload seeds —
# Owner is control-plane only (the 01_02 lesson, in production form).
data "azurerm_client_config" "current" {}

resource "azurerm_role_assignment" "deployer_blob_data" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = local.deployer
}

# The deployer also seeds the frameworks/mappings containers (labs/04's seed script),
# so it gets the Cosmos data-plane contributor role. Same reasoning as the blob role above.
resource "azurerm_cosmosdb_sql_role_assignment" "deployer_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = local.deployer
  scope               = azurerm_cosmosdb_account.evidence.id
}

# --- Who touched the evidence? Data-plane access logs for the store itself. ---
# Every blob read/write/delete on the evidence account and every Cosmos data-plane
# request land in the GRC workspace, next to the Activity Log. WORM stops tampering;
# these logs show who looked.
resource "azurerm_monitor_diagnostic_setting" "evidence_blob" {
  name                       = "ds-evidence-blob-to-law"
  target_resource_id         = "${azurerm_storage_account.evidence.id}/blobServices/default"
  log_analytics_workspace_id = data.terraform_remote_state.foundation.outputs.log_analytics_workspace_id

  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
}

resource "azurerm_monitor_diagnostic_setting" "evidence_cosmos" {
  name                           = "ds-evidence-cosmos-to-law"
  target_resource_id             = azurerm_cosmosdb_account.evidence.id
  log_analytics_workspace_id     = data.terraform_remote_state.foundation.outputs.log_analytics_workspace_id
  log_analytics_destination_type = "Dedicated"

  enabled_log { category = "DataPlaneRequests" }
  enabled_log { category = "ControlPlaneRequests" }
}
