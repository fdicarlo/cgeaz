output "reporting_function_app" {
  value = azurerm_linux_function_app.reporting.name
}

output "reporter_principal_id" {
  value = azurerm_linux_function_app.reporting.identity[0].principal_id
}
