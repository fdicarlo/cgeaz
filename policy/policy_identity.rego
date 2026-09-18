# Gate rule: a policy assignment carrying remediation effects without an identity
# applies cleanly and then silently never remediates. Make that mistake unmergeable.
#
# Note the emptiness test: in a plan JSON a missing identity block is `[]`, which is
# a DEFINED value in Rego — `not rc.change.after.identity` never fires on it. The
# starter repo's version of this rule had exactly that hole; tests/ pins the fix.
package main

import rego.v1

assignment_types := {
	"azurerm_management_group_policy_assignment",
	"azurerm_subscription_policy_assignment",
	"azurerm_resource_group_policy_assignment",
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type in assignment_types
	not "delete" in rc.change.actions
	count(object.get(rc.change.after, "identity", [])) == 0
	not identity_exempt[rc.address]
	msg := sprintf("%s: policy assignments must carry an identity block (remediation effects silently no-op without one); audit-only assignments go in policy/exceptions.rego with a reason", [rc.address])
}
