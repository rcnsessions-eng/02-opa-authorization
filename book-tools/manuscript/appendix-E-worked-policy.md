```rego
package learning.authz

import rego.v1

default decision := {
  "allow": false,
  "reason_code": "DENY_BY_DEFAULT",
  "policy_version": "teaching-1.0.0",
  "obligations": []
}

decision := {
  "allow": true,
  "reason_code": "OWNER_AND_TENANT_MATCH",
  "policy_version": "teaching-1.0.0",
  "obligations": []
} if {
  is_string(input.principal.id)
  input.principal.id != ""
  is_string(input.resource.owner_id)
  input.resource.owner_id != ""
  is_string(input.principal.tenant_id)
  input.principal.tenant_id != ""
  is_string(input.resource.tenant_id)
  input.resource.tenant_id != ""
  input.principal.type == "human"
  input.action == "progress.read"
  input.resource.type == "learner-progress"
  input.principal.id == input.resource.owner_id
  input.principal.tenant_id == input.resource.tenant_id
}
```

```rego
package learning.authz

import rego.v1

owner_input := {
  "principal": {"id": "learner-a", "type": "human", "tenant_id": "tenant-a"},
  "action": "progress.read",
  "resource": {
    "type": "learner-progress", "owner_id": "learner-a", "tenant_id": "tenant-a"
  }
}

expected_allow := {
  "allow": true, "reason_code": "OWNER_AND_TENANT_MATCH",
  "policy_version": "teaching-1.0.0", "obligations": []
}

expected_deny := {
  "allow": false, "reason_code": "DENY_BY_DEFAULT",
  "policy_version": "teaching-1.0.0", "obligations": []
}

negative_inputs := [
  object.union(owner_input, {"action": "progress.delete"}),
  object.union(owner_input, {"resource": {"owner_id": "learner-b"}}),
  object.union(owner_input, {"resource": {"tenant_id": "tenant-b"}}),
  object.union(owner_input, {"resource": {"type": "unknown"}}),
  object.remove(owner_input, ["principal"]),
  object.union(object.remove(owner_input, ["principal"]), {
    "principal": object.remove(owner_input.principal, ["id"])
  }),
  object.union(owner_input, {"principal": {"id": 101}, "resource": {"owner_id": 101}}),
  object.union(owner_input, {"principal": {"type": "workload"}})
]

test_owner_contract if {
  actual := decision with input as owner_input
  actual == expected_allow
}

test_negative_matrix if {
  every candidate in negative_inputs {
    actual := decision with input as candidate
    actual == expected_deny
  }
}

test_admin_claim_cannot_elevate if {
  candidate := object.union(owner_input, {
    "principal": {"roles": ["admin"]},
    "resource": {"tenant_id": "tenant-b"}
  })
  actual := decision with input as candidate
  actual == expected_deny
}
```

```rego
package learning.authz

import rego.v1

test_missing_id_denied if {
  without_principal := object.remove(owner_input, ["principal"])
  candidate := object.union(without_principal, {
    "principal": object.remove(owner_input.principal, ["id"])
  })
  actual := decision with input as candidate
  actual == expected_deny
}
```
