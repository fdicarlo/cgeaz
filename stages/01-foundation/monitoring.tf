# Monitoring plumbing the course builds by hand in Labs 1-2 (az rest scripts), codified
# here so the whole foundation stands up from an empty subscription with one apply.
# If you did the labs by hand, adopt instead of recreating:
#   terraform import azurerm_monitor_diagnostic_setting.activity_log \
#     "/subscriptions/<sub>|ds-activity-to-law"
#   terraform import azurerm_consumption_budget_subscription.sandbox \
#     /subscriptions/<sub>/providers/Microsoft.Consumption/budgets/budget-cge-az-labs

locals {
  # Trusted writers: the remediation identity plus whatever automation the operator
  # declares (the CI identity). Humans are never on this list, which is the point.
  # Activity Log `Caller` for a workload identity can surface either GUID, so both
  # the object (principal) ID and the client ID are listed.
  trusted_callers = distinct(concat(
    [
      azurerm_user_assigned_identity.remediation.principal_id,
      azurerm_user_assigned_identity.remediation.client_id,
    ],
    var.trusted_automation_callers,
  ))

  # Detector 2 of 2 ("who is touching reality?"). Detector 1 is the nightly
  # `terraform plan -detailed-exitcode` in .github/workflows/drift.yml.
  # Any successful control-plane write or delete by a caller outside the trusted
  # list is an out-of-band change, including a human's own `terraform apply` from a
  # laptop. That is intended: every apply leaves a named, alerted record.
  out_of_band_kql = <<-KQL
    AzureActivity
    | where CategoryValue == "Administrative"
    | where ActivityStatusValue in ("Success", "Succeeded")
    | where OperationNameValue endswith "/WRITE" or OperationNameValue endswith "/DELETE"
    | where OperationNameValue !startswith "MICROSOFT.RESOURCES/DEPLOYMENTS"
    | where Caller !in (dynamic(${jsonencode(local.trusted_callers)}))
    | summarize changes = count(), operations = make_set(OperationNameValue, 20),
                firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated)
      by Caller, ResourceGroup
    | order by changes desc
  KQL
}

# --- Activity Log -> GRC workspace (Lab 2's route-activity-log.sh, as code) ---
# Without this, the platform keeps 90 days and nobody can query it with KQL.

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "ds-activity-to-law"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.grc.id

  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Policy" }
  enabled_log { category = "Alert" }
}

# --- Cost guardrail (Lab 1's create-budget.sh, as code) ---

resource "azurerm_consumption_budget_subscription" "sandbox" {
  name            = "budget-cge-az-labs"
  subscription_id = data.azurerm_subscription.current.id
  amount          = var.budget_amount
  time_grain      = "Monthly"

  time_period {
    start_date = var.budget_start_date
  }

  notification {
    enabled        = true
    operator       = "GreaterThan"
    threshold      = 80
    threshold_type = "Actual"
    contact_emails = [var.owner_email]
  }

  notification {
    enabled        = true
    operator       = "GreaterThan"
    threshold      = 100
    threshold_type = "Forecasted"
    contact_emails = [var.owner_email]
  }

  lifecycle {
    # Azure normalises end_date server-side when none is given.
    ignore_changes = [time_period[0].end_date]
  }
}

# --- The out-of-band change tripwire ---

resource "azurerm_monitor_action_group" "grc" {
  name                = "ag-grc-${var.environment}"
  resource_group_name = azurerm_resource_group.sandbox.name
  short_name          = "grc-alerts"

  email_receiver {
    name                    = "grc-owner"
    email_address           = var.owner_email
    use_common_alert_schema = true
  }

  tags = {
    env     = var.environment
    purpose = "grc-alerting"
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "out_of_band_change" {
  name                = "alert-grc-out-of-band-change"
  display_name        = "GRC: control-plane change by an untrusted caller"
  description         = "Drift detector 2 of 2. A write/delete in the governed subscription by a caller that is neither the remediation identity nor declared automation. Changes go through the repo, never the portal."
  resource_group_name = azurerm_resource_group.sandbox.name
  location            = var.location
  scopes              = [azurerm_log_analytics_workspace.grc.id]
  severity            = 2

  evaluation_frequency = "PT1H"
  window_duration      = "PT1H"

  criteria {
    query                   = local.out_of_band_kql
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    dimension {
      name     = "Caller"
      operator = "Include"
      values   = ["*"]
    }

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.grc.id]
  }

  tags = {
    env     = var.environment
    purpose = "grc-drift-detection"
  }
}

# --- Saved searches: the auditor's questions, answerable by name in the workspace ---

resource "azurerm_log_analytics_saved_search" "out_of_band" {
  name                       = "grc-out-of-band-changes"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.grc.id
  category                   = "GRC"
  display_name               = "Out-of-band control-plane changes (drift detector 2)"
  query                      = local.out_of_band_kql
}

resource "azurerm_log_analytics_saved_search" "remediation_history" {
  name                       = "grc-remediation-history"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.grc.id
  category                   = "GRC"
  display_name               = "Every change made by the remediation identity"
  query                      = <<-KQL
    AzureActivity
    | where Caller in ("${azurerm_user_assigned_identity.remediation.principal_id}", "${azurerm_user_assigned_identity.remediation.client_id}")
    | project TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceGroup, _ResourceId
    | order by TimeGenerated desc
  KQL
}

resource "azurerm_log_analytics_saved_search" "pipeline_run_history" {
  name                       = "grc-pipeline-run-history"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.grc.id
  category                   = "GRC"
  display_name               = "Collector and report generator run history (Functions)"
  query                      = <<-KQL
    AppRequests
    | where Name in ("collect_scheduled", "poam_scheduled", "framework_scheduled", "sar_scheduled",
                     "collect_now", "poam_now", "framework_now", "sar_now")
    | summarize runs = count(), failures = countif(Success == false),
                firstRun = min(TimeGenerated), lastRun = max(TimeGenerated) by Name
    | order by Name asc
  KQL
}
