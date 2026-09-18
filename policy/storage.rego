# Gate rule: the pipeline's own storage must pass the pipeline's own standard.
# Any storage account in a plan must disable public blob access, enforce TLS 1.2+,
# and disable shared keys — Functions runtime storage is the one documented exception
# (EXC-01), and it must carry a matching policy exemption in the same stage.
package main

import rego.v1

storage_accounts contains rc if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	not "delete" in rc.change.actions
}

deny contains msg if {
	some rc in storage_accounts
	rc.change.after.allow_nested_items_to_be_public == true
	msg := sprintf("%s: storage accounts must not allow public blob access", [rc.address])
}

deny contains msg if {
	some rc in storage_accounts
	not rc.change.after.min_tls_version in {"TLS1_2", "TLS1_3"}
	msg := sprintf("%s: min_tls_version must be TLS1_2 or higher", [rc.address])
}

deny contains msg if {
	some rc in storage_accounts
	rc.change.after.shared_access_key_enabled == true
	not startswith(rc.name, "func_internal")
	msg := sprintf("%s: shared key access must be disabled (identity or nothing) — func runtime storage is the documented exception", [rc.address])
}

# The exception is only valid while it is recorded where Azure Policy can see it.
deny contains msg if {
	some rc in storage_accounts
	rc.change.after.shared_access_key_enabled == true
	startswith(rc.name, "func_internal")
	not has_exemption_in_plan
	msg := sprintf("%s: runtime storage uses shared keys but no azurerm_resource_policy_exemption (EXC-01) is declared in this stage", [rc.address])
}

has_exemption_in_plan if {
	some rc in input.resource_changes
	rc.type == "azurerm_resource_policy_exemption"
	not "delete" in rc.change.actions
}
