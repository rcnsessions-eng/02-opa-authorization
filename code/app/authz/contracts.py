import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from app.domain import Identifier

CanonicalAction = Literal[
    "content.search", "progress.read", "assessment.create", "evidence.record"
]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PrincipalContext(Contract):
    id: Identifier
    tenant_id: Identifier
    type: Literal["human"] = "human"


class WorkloadContext(Contract):
    id: Literal["learning-api"] = "learning-api"


class ResourceContext(Contract):
    id: Identifier
    type: Literal["learner-progress", "approved-content-collection"]
    tenant_id: Identifier
    owner_id: Identifier | None = None


class TenantContext(Contract):
    id: Identifier


class RequestContext(Contract):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


class AuthorizationInput(Contract):
    schema_version: Literal["1.0"] = "1.0"
    principal: PrincipalContext
    workload: WorkloadContext
    action: CanonicalAction
    resource: ResourceContext
    tenant: TenantContext
    request: RequestContext


class Decision(Contract):
    allow: StrictBool
    reason_code: Literal["ACCESS_DENIED", "OWNER_AND_TENANT_MATCH", "TENANT_APPROVED_CONTENT"]
    policy_version: Literal["1.0.0"]


class Envelope(Contract):
    result: Decision


if __name__ == "__main__":
    destination = Path("policy/schema/input-v1.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(AuthorizationInput.model_json_schema(), indent=2) + "\n")
