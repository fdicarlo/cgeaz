# Gate rule: the evidence database is identity-only and recoverable.
# Same control as the cge-audit-cosmos-local-auth Azure Policy (stage 01), applied one
# step earlier: at the pull request, before the resource exists.
package main

import rego.v1

cosmos_accounts contains rc if {
	some rc in input.resource_changes
	rc.type == "azurerm_cosmosdb_account"
	not "delete" in rc.change.actions
}

deny contains msg if {
	some rc in cosmos_accounts
	object.get(rc.change.after, "local_authentication_enabled", true) != false
	msg := sprintf("%s: Cosmos DB local (key) authentication must be disabled", [rc.address])
}

deny contains msg if {
	some rc in cosmos_accounts
	not continuous_backup(rc)
	msg := sprintf("%s: evidence stores need continuous backup (point-in-time restore)", [rc.address])
}

continuous_backup(rc) if {
	some b in rc.change.after.backup
	b.type == "Continuous"
}
