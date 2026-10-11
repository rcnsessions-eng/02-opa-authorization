package learning.authz

import rego.v1

policy_version := "1.0.0"

default allow := false

default reason_code := "ACCESS_DENIED"

nonempty_string(value) if {
	is_string(value)
	value != ""
}

valid_context if {
	input.schema_version == "1.0"
	input.principal.type == "human"
	nonempty_string(input.principal.id)
	nonempty_string(input.principal.tenant_id)
	input.workload.id == "learning-api"
	nonempty_string(input.resource.id)
	nonempty_string(input.resource.tenant_id)
	nonempty_string(input.tenant.id)
	nonempty_string(input.request.id)
	input.principal.tenant_id == input.tenant.id
	input.resource.tenant_id == input.tenant.id
}

allow if {
	valid_context
	input.action == "progress.read"
	input.resource.type == "learner-progress"
	nonempty_string(input.resource.owner_id)
	input.principal.id == input.resource.owner_id
}

allow if {
	valid_context
	input.action == "content.search"
	input.resource.type == "approved-content-collection"
}

reason_code := "OWNER_AND_TENANT_MATCH" if {
	allow
	input.action == "progress.read"
}

reason_code := "TENANT_APPROVED_CONTENT" if {
	allow
	input.action == "content.search"
}

decision := {
	"allow": allow,
	"reason_code": reason_code,
	"policy_version": policy_version,
}
