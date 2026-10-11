```rego
package learning.authz

import rego.v1

default allow := false

allow if {
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
  input.principal.type == "human"
  input.resource.type == "learner-progress"
  is_string(input.principal.id)
  input.principal.id != ""
  is_string(input.resource.owner_id)
  input.resource.owner_id != ""
  is_string(input.principal.tenant_id)
  input.principal.tenant_id != ""
  is_string(input.resource.tenant_id)
  input.resource.tenant_id != ""
  input.action == "progress.read"
  input.principal.id == input.resource.owner_id
  input.principal.tenant_id == input.resource.tenant_id
}
```
