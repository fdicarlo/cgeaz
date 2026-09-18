# GATE TEST — this PR must be blocked and closed unmerged (docs/EVIDENCE.md#gate).
# A "quick" public storage account for sharing reports: exactly the change the gate exists to stop.
resource "azurerm_storage_account" "public_share" {
  name                            = "stgrcpublic${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_0"
  allow_nested_items_to_be_public = true
  shared_access_key_enabled       = true
}
