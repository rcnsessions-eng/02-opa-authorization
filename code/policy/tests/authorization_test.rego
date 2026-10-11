package learning.authz_test

import data.learning.authz
import rego.v1

progress_input := {
	"schema_version": "1.0",
	"principal": {"id": "learner-red-1", "type": "human", "tenant_id": "tenant-red"},
	"workload": {"id": "learning-api"},
	"action": "progress.read",
	"resource": {"id": "progress-red-1", "type": "learner-progress", "tenant_id": "tenant-red", "owner_id": "learner-red-1"},
	"tenant": {"id": "tenant-red"},
	"request": {"id": "policy-test"},
}

test_own_progress_allowed if {
	authz.allow with input as progress_input
}

test_owner_mismatch_denied if {
	resource := object.union(progress_input.resource, {"owner_id": "learner-red-2"})
	modified := object.union(progress_input, {"resource": resource})
	not authz.allow with input as modified
}

test_tenant_checked_independently_of_owner if {
	resource := object.union(progress_input.resource, {"tenant_id": "tenant-blue"})
	modified := object.union(progress_input, {"resource": resource})
	not authz.allow with input as modified
}

test_unknown_action_denied if {
	modified := object.union(progress_input, {"action": "arbitrary.execute"})
	not authz.allow with input as modified
}

test_missing_principal_denied if {
	modified := object.remove(progress_input, ["principal"])
	not authz.allow with input as modified
}

test_missing_owner_denied if {
	resource := object.remove(progress_input.resource, ["owner_id"])
	modified := object.union(object.remove(progress_input, ["resource"]), {"resource": resource})
	not authz.allow with input as modified
}

test_wrong_resource_type_denied if {
	resource := object.union(progress_input.resource, {"type": "assessment"})
	modified := object.union(progress_input, {"resource": resource})
	not authz.allow with input as modified
}

test_missing_request_denied if {
	modified := object.remove(progress_input, ["request"])
	not authz.allow with input as modified
}

test_wrong_schema_version_denied if {
	modified := object.union(progress_input, {"schema_version": "unknown"})
	not authz.allow with input as modified
}

test_wrong_attribute_types_denied if {
	principal := object.union(progress_input.principal, {"id": 7})
	resource := object.union(progress_input.resource, {"owner_id": 7})
	modified := object.union(progress_input, {"principal": principal, "resource": resource})
	not authz.allow with input as modified
}

test_reserved_writes_denied if {
	every action in ["assessment.create", "evidence.record"] {
		modified := object.union(progress_input, {"action": action})
		not authz.allow with input as modified
	}
}

test_approved_content_collection_allowed if {
	modified := object.union(progress_input, {
		"action": "content.search",
		"resource": {"id": "approved-red", "type": "approved-content-collection", "tenant_id": "tenant-red"},
	})
	authz.allow with input as modified
}
