# Gate rule: a policy exemption is a risk acceptance, so it needs what a risk
# acceptance needs — a reason, and a date it stops being true.
package main

import rego.v1

exemption_types := {
	"azurerm_resource_policy_exemption",
	"azurerm_resource_group_policy_exemption",
	"azurerm_subscription_policy_exemption",
	"azurerm_management_group_policy_exemption",
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type in exemption_types
	not "delete" in rc.change.actions
	not has_text(object.get(rc.change.after, "expires_on", null))
	msg := sprintf("%s: policy exemptions must expire (set expires_on) — a permanent exemption is a silent policy change", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type in exemption_types
	not "delete" in rc.change.actions
	not has_text(object.get(rc.change.after, "description", null))
	msg := sprintf("%s: policy exemptions must state why (description)", [rc.address])
}

has_text(s) if {
	is_string(s)
	count(trim_space(s)) > 0
}
