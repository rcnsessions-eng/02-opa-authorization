import json
import logging

from app.authz.client import OPAClient, PolicyUnavailable
from app.authz.contracts import (
    AuthorizationInput,
    CanonicalAction,
    PrincipalContext,
    RequestContext,
    ResourceContext,
    TenantContext,
    WorkloadContext,
)
from app.domain import ContentCollection, Principal, PublicProgress
from app.errors import ServiceError
from app.repositories.memory import InMemoryLearningRepository
from app.services.learning import LearningService

LOGGER = logging.getLogger("learning.authorization")


class AuthorizedLearningService(LearningService):
    def __init__(
        self,
        repository: InMemoryLearningRepository,
        policy: OPAClient,
        request_id: str,
    ) -> None:
        super().__init__(repository)
        self.metadata = repository.learners
        self.policy = policy
        self.request_id = request_id

    def enforce(
        self, principal: Principal, action: CanonicalAction, resource: ResourceContext
    ) -> None:
        context = AuthorizationInput(
            principal=PrincipalContext(id=principal.subject, tenant_id=principal.tenant_id),
            workload=WorkloadContext(),
            action=action,
            resource=resource,
            tenant=TenantContext(id=principal.tenant_id),
            request=RequestContext(id=self.request_id),
        )
        try:
            decision = self.policy.decide(context)
        except PolicyUnavailable:
            LOGGER.info(
                json.dumps(
                    {
                        "event": "authorization_decision",
                        "request_id": self.request_id,
                        "action": action,
                        "decision": "deny",
                        "reason_code": "POLICY_UNAVAILABLE",
                        "policy_version": "unavailable",
                    }
                )
            )
            raise
        LOGGER.info(
            json.dumps(
                {
                    "event": "authorization_decision",
                    "request_id": self.request_id,
                    "action": action,
                    "decision": "allow" if decision.allow else "deny",
                    "reason_code": decision.reason_code,
                    "policy_version": decision.policy_version,
                }
            )
        )
        if not decision.allow:
            raise ServiceError(404, "not_found", "Resource not found")

    def read_progress(self, principal: Principal, learner_id: str) -> PublicProgress:
        if principal.subject != learner_id:
            raise ServiceError(404, "not_found", "Resource not found")
        learner = next((learner for learner in self.metadata if learner.id == learner_id), None)
        if learner is None:
            raise ServiceError(404, "not_found", "Resource not found")
        resource = ResourceContext(
            id="progress-" + learner.id,
            type="learner-progress",
            tenant_id=learner.tenant_id,
            owner_id=learner.id,
        )
        self.enforce(principal, "progress.read", resource)
        return super().read_progress(principal, learner_id)

    def list_content(self, principal: Principal, limit: int) -> ContentCollection:
        self.enforce(
            principal,
            "content.search",
            ResourceContext(
                id="approved-" + principal.tenant_id,
                type="approved-content-collection",
                tenant_id=principal.tenant_id,
            ),
        )
        return super().list_content(principal, limit)
