# Gate exceptions, as reviewed data. Adding a line here is a PR a human approves,
# with the reason on the record — the gate's equivalent of a policy exemption.
# Mirrors docs/EXCEPTIONS.md.
package main

import rego.v1

identity_exempt := {
	# The built-in NIST CSF v2.0 initiative is assigned for Defender's regulatory
	# compliance dashboard: assessment only, nothing remediates through it. An
	# identity would be a standing principal with nothing to do. (EXC-02)
	"azurerm_subscription_policy_assignment.nist_csf_20": "audit-only built-in initiative (EXC-02)",
}
