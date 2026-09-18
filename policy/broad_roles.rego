# Gate rule: no broad role grants sneak into governance code — not even yours,
# not even at 2 AM with a deadline. Catches the role by name AND by its well-known
# GUID, so role_definition_id can't be used to walk around the name check.
package main

import rego.v1

broad_roles := {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}

broad_role_guids := {
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
	"b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", # User Access Administrator
	"f58310d9-a9f6-439a-9e8d-f62e7b41a168", # Role Based Access Control Administrator
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	not "delete" in rc.change.actions
	rc.change.after.role_definition_name in broad_roles
	msg := sprintf("%s: %s at any scope is not a whitelist — use a granular role", [rc.address, rc.change.after.role_definition_name])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	not "delete" in rc.change.actions
	some guid in broad_role_guids
	role_id := object.get(rc.change.after, "role_definition_id", null)
	is_string(role_id)
	endswith(lower(role_id), guid)
	msg := sprintf("%s: role_definition_id resolves to a broad built-in role (%s) — use a granular role", [rc.address, guid])
}

# Custom roles must not smuggle in wildcards either.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_definition"
	not "delete" in rc.change.actions
	some p in rc.change.after.permissions
	some action in p.actions
	action in {"*", "*/write", "*/delete"}
	msg := sprintf("%s: custom role grants wildcard action '%s'", [rc.address, action])
}
