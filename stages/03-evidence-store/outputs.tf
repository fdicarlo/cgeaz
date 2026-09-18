output "cosmos_endpoint" {
  description = "Evidence database endpoint (identity auth only — local auth is disabled)."
  value       = azurerm_cosmosdb_account.evidence.endpoint
}

output "cosmos_account_name" {
  value = azurerm_cosmosdb_account.evidence.name
}

output "cosmos_account_id" {
  value = azurerm_cosmosdb_account.evidence.id
}

output "evidence_storage_account" {
  description = "WORM artifact storage (shared keys disabled)."
  value       = azurerm_storage_account.evidence.name
}

output "reports_container" {
  value = azurerm_storage_container.reports.name
}

output "collector_function_app" {
  value = azurerm_linux_function_app.collectors.name
}

output "collector_principal_id" {
  description = "The collector identity — filter logs by this to see every evidence write."
  value       = azurerm_linux_function_app.collectors.identity[0].principal_id
}

output "app_insights_connection_string" {
  description = "Shared pipeline telemetry sink; stage 04's reporter writes its run history here too."
  value       = azurerm_application_insights.pipeline.connection_string
  sensitive   = true
}

output "evidence_storage_account_id" {
  value = azurerm_storage_account.evidence.id
}
