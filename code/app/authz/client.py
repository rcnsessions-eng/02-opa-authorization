import time

import httpx
from pydantic import ValidationError

from app.authz.contracts import AuthorizationInput, Decision, Envelope
from app.errors import ServiceError


class PolicyUnavailable(ServiceError):
    def __init__(self) -> None:
        super().__init__(
            503, "policy_unavailable", "A required authorization decision is unavailable"
        )


class OPAClient:
    def __init__(
        self,
        url: str,
        timeout: float = 0.5,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not 0.01 <= timeout <= 2.0:
            raise ValueError("Policy timeout must be between 0.01 and 2 seconds")
        self.timeout = timeout
        self.client = httpx.Client(
            base_url=url, timeout=timeout, transport=transport, trust_env=False
        )

    def decide(self, context: AuthorizationInput) -> Decision:
        started = time.monotonic()
        try:
            with self.client.stream(
                "POST",
                "/v1/data/learning/authz/decision",
                json={"input": context.model_dump(exclude_none=True)},
            ) as response:
                response.raise_for_status()
                payload = bytearray()
                for chunk in response.iter_bytes():
                    payload.extend(chunk)
                    if len(payload) > 4096 or time.monotonic() - started > self.timeout * 4:
                        raise PolicyUnavailable()
                decision = Envelope.model_validate_json(bytes(payload)).result
                expected = {
                    "progress.read": "OWNER_AND_TENANT_MATCH",
                    "content.search": "TENANT_APPROVED_CONTENT",
                }.get(context.action)
                if (decision.allow and decision.reason_code != expected) or (
                    not decision.allow and decision.reason_code != "ACCESS_DENIED"
                ):
                    raise PolicyUnavailable()
                return decision
        except (httpx.HTTPError, ValidationError, ValueError):
            raise PolicyUnavailable() from None

    def close(self) -> None:
        self.client.close()
