```python
class AuthorizationDenied(Exception):
    pass

class PolicyUnavailable(Exception):
    pass

def validate_decision(decision):
    required = {"allow", "reason_code", "policy_version", "obligations"}
    if not isinstance(decision, dict) or set(decision) != required:
        raise PolicyUnavailable("invalid_policy_contract")
    if type(decision["allow"]) is not bool:
        raise PolicyUnavailable("invalid_policy_contract")
    if decision["policy_version"] != "teaching-1.0.0":
        raise PolicyUnavailable("unsupported_policy_version")
    if decision["obligations"] != []:
        raise PolicyUnavailable("unsupported_policy_obligations")
    expected_reason = (
        "OWNER_AND_TENANT_MATCH" if decision["allow"]
        else "DENY_BY_DEFAULT"
    )
    if decision["reason_code"] != expected_reason:
        raise PolicyUnavailable("invalid_policy_reason")
    return decision

def read_progress(principal, learner_id, repository, policy_client, audit):
    # 1. `principal` must come from validated authentication middleware.
    if principal is None or not principal.subject:
        raise AuthorizationDenied("authentication_required")

    # 2. Load authoritative metadata; do not trust model-supplied owner/tenant.
    resource = repository.get_progress_metadata(
        tenant_id=principal.tenant_id,
        learner_id=learner_id,
    )
    if resource is None:
        # Use a consistent not-found/denied strategy to avoid resource enumeration.
        raise AuthorizationDenied("resource_not_available")

    # 3. Construct the decision input from trusted values.
    policy_input = {
        "principal": {
            "id": principal.subject,
            "type": "human",
            "tenant_id": principal.tenant_id,
        },
        "action": "progress.read",
        "resource": {
            "type": "learner-progress",
            "id": resource.id,
            "owner_id": resource.owner_id,
            "tenant_id": resource.tenant_id,
        },
    }

    # 4. A timeout or malformed result must not become an allow.
    try:
        decision = policy_client.evaluate(policy_input)
    except TimeoutError as exc:
        audit.authorization_error(
            request_id=principal.request_id,
            action="progress.read",
            reason_code="POLICY_TIMEOUT",
        )
        raise PolicyUnavailable("authorization temporarily unavailable") from exc

    decision = validate_decision(decision)
    if decision["allow"] is not True:
        audit.authorization_decision(
            request_id=principal.request_id,
            action="progress.read",
            resource_ref=resource.audit_ref,
            decision="deny",
            reason_code=decision["reason_code"],
        )
        raise AuthorizationDenied("operation_not_permitted")

    # 5. Recheck scope in the actual query. Do not query by learner ID alone.
    result = repository.read_progress(
        tenant_id=principal.tenant_id,
        learner_id=learner_id,
    )

    audit.authorization_decision(
        request_id=principal.request_id,
        action="progress.read",
        resource_ref=resource.audit_ref,
        decision="allow",
        reason_code=decision.get("reason_code", "POLICY_ALLOW"),
    )
    return result
```
