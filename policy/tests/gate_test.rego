# Unit tests for the gate: `conftest verify -p policy` (CI job: static).
# Each rule gets a failing fixture it must catch and a passing one it must leave alone.
package main

import rego.v1

rc(type, name, after) := {
	"address": sprintf("%s.%s", [type, name]),
	"type": type,
	"name": name,
	"change": {"actions": ["create"], "after": after},
}

plan(changes) := {"resource_changes": changes}

good_storage := {
	"allow_nested_items_to_be_public": false,
	"shared_access_key_enabled": false,
	"min_tls_version": "TLS1_2",
}

# --- policy_identity.rego ---

test_assignment_without_identity_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_management_group_policy_assignment", "x", {"identity": []})])
}

test_assignment_missing_identity_key_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_management_group_policy_assignment", "x", {})])
}

test_assignment_with_identity_allowed if {
	count(deny) == 0 with input as plan([rc("azurerm_management_group_policy_assignment", "x", {"identity": [{"type": "UserAssigned"}]})])
}

test_exempt_audit_only_assignment_allowed if {
	count(deny) == 0 with input as plan([rc("azurerm_subscription_policy_assignment", "nist_csf_20", {"identity": []})])
}

# --- broad_roles.rego ---

test_contributor_by_name_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_role_assignment", "x", {"role_definition_name": "Contributor"})])
}

test_owner_by_guid_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_role_assignment", "x", {
		"role_definition_name": null,
		"role_definition_id": "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
	})])
}

test_granular_role_allowed if {
	count(deny) == 0 with input as plan([rc("azurerm_role_assignment", "x", {"role_definition_name": "Security Reader"})])
}

test_wildcard_custom_role_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_role_definition", "x", {"permissions": [{"actions": ["*"]}]})])
}

test_narrow_custom_role_allowed if {
	count(deny) == 0 with input as plan([rc("azurerm_role_definition", "x", {"permissions": [{"actions": ["Microsoft.PolicyInsights/policyStates/queryResults/read"]}]})])
}

# --- storage.rego ---

test_public_blob_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_storage_account", "evidence", object.union(good_storage, {"allow_nested_items_to_be_public": true}))])
}

test_shared_key_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_storage_account", "evidence", object.union(good_storage, {"shared_access_key_enabled": true}))])
}

test_weak_tls_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_storage_account", "evidence", object.union(good_storage, {"min_tls_version": "TLS1_0"}))])
}

test_compliant_storage_allowed if {
	count(deny) == 0 with input as plan([rc("azurerm_storage_account", "evidence", good_storage)])
}

test_runtime_storage_needs_exemption if {
	count(deny) > 0 with input as plan([rc("azurerm_storage_account", "func_internal", object.union(good_storage, {"shared_access_key_enabled": true}))])
}

test_runtime_storage_with_exemption_allowed if {
	count(deny) == 0 with input as plan([
		rc("azurerm_storage_account", "func_internal", object.union(good_storage, {"shared_access_key_enabled": true})),
		rc("azurerm_resource_policy_exemption", "func_internal_shared_key", {"expires_on": "2027-03-31T00:00:00Z", "description": "EXC-01"}),
	])
}

# --- cosmos.rego ---

test_cosmos_local_auth_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_cosmosdb_account", "e", {"local_authentication_enabled": true, "backup": [{"type": "Continuous"}]})])
}

test_cosmos_periodic_backup_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_cosmosdb_account", "e", {"local_authentication_enabled": false, "backup": [{"type": "Periodic"}]})])
}

test_cosmos_compliant_allowed if {
	count(deny) == 0 with input as plan([rc("azurerm_cosmosdb_account", "e", {"local_authentication_enabled": false, "backup": [{"type": "Continuous"}]})])
}

# --- exemptions.rego ---

test_exemption_without_expiry_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_resource_policy_exemption", "x", {"expires_on": null, "description": "why"})])
}

test_exemption_without_reason_denied if {
	count(deny) > 0 with input as plan([rc("azurerm_resource_policy_exemption", "x", {"expires_on": "2027-01-01T00:00:00Z", "description": " "})])
}

# --- deletes never trip the gate ---

test_delete_ignored if {
	count(deny) == 0 with input as plan([{
		"address": "azurerm_role_assignment.old",
		"type": "azurerm_role_assignment",
		"name": "old",
		"change": {"actions": ["delete"], "after": null},
	}])
}
