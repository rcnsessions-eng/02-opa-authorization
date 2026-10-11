import json
import logging
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.authz.main import create_app
from app.repositories.memory import InMemoryLearningRepository


class CountingRepository(InMemoryLearningRepository):
    def __init__(self) -> None:
        super().__init__()
        self.protected_reads = 0

    def get_progress(self, tenant_id: str, learner_id: str) -> Any:
        self.protected_reads += 1
        return super().get_progress(tenant_id, learner_id)


def test_allowed_decision_and_trusted_context(caplog: pytest.LogCaptureFixture) -> None:
    captured = []

    def reply(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content)["input"])
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": True,
                    "reason_code": "OWNER_AND_TENANT_MATCH",
                    "policy_version": "1.0.0",
                }
            },
        )

    repository = CountingRepository()
    caplog.set_level(logging.INFO, logger="learning.authorization")
    with TestClient(create_app(repository, httpx.MockTransport(reply))) as client:
        response = client.get(
            "/v1/learners/learner-red-1/progress",
            headers={
                "Authorization": "Bearer demo-learner-red",
                "X-Tenant-ID": "tenant-blue",
                "X-User-ID": "learner-blue-1",
                "X-Role": "admin",
                "X-Request-ID": "trusted-context",
            },
        )
    assert response.status_code == 200 and repository.protected_reads == 1
    assert captured[0]["principal"] == {
        "id": "learner-red-1",
        "tenant_id": "tenant-red",
        "type": "human",
    }
    assert captured[0]["resource"]["owner_id"] == "learner-red-1"
    assert captured[0]["workload"] == {"id": "learning-api"}
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "learning.authorization"
    ]
    assert events[-1]["reason_code"] == "OWNER_AND_TENANT_MATCH"
    assert events[-1]["policy_version"] == "1.0.0"
    assert "demo-learner-red" not in json.dumps(events)


@pytest.mark.parametrize(
    "result",
    [
        None,
        [],
        "allow",
        True,
        {},
        {"allow": "true", "reason_code": "OWNER_AND_TENANT_MATCH", "policy_version": "1.0.0"},
        {"allow": True, "reason_code": "unknown", "policy_version": "1.0.0"},
        {"allow": True, "reason_code": "OWNER_AND_TENANT_MATCH", "policy_version": "unknown"},
        {"allow": True, "reason_code": "ACCESS_DENIED", "policy_version": "1.0.0"},
        {
            "allow": True,
            "reason_code": "OWNER_AND_TENANT_MATCH",
            "policy_version": "1.0.0",
            "unexpected": "value",
        },
    ],
)
def test_malformed_decision_prevents_protected_read(result: object) -> None:
    repository = CountingRepository()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"result": result})
    )
    with TestClient(create_app(repository, transport)) as client:
        response = client.get(
            "/v1/learners/learner-red-1/progress",
            headers={"Authorization": "Bearer demo-learner-red"},
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "policy_unavailable"
    assert repository.protected_reads == 0
    assert "completion_percent" not in response.text


@pytest.mark.parametrize("failure", ["timeout", "connection", "status", "oversize", "missing"])
def test_policy_failure_prevents_protected_read(failure: str) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.ReadTimeout("private-timeout-detail")
        if failure == "connection":
            raise httpx.ConnectError("private-connection-detail")
        if failure == "status":
            return httpx.Response(500, text="private-error")
        if failure == "oversize":
            return httpx.Response(200, content=b"x" * 5000)
        return httpx.Response(200, json={})

    repository = CountingRepository()
    with TestClient(create_app(repository, httpx.MockTransport(reply))) as client:
        response = client.get(
            "/v1/learners/learner-red-1/progress",
            headers={"Authorization": "Bearer demo-learner-red"},
        )
    assert response.status_code == 503
    assert repository.protected_reads == 0
    assert "private" not in response.text


def test_denied_decision_prevents_protected_read() -> None:
    repository = CountingRepository()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "result": {
                    "allow": False,
                    "reason_code": "ACCESS_DENIED",
                    "policy_version": "1.0.0",
                }
            },
        )
    )
    with TestClient(create_app(repository, transport)) as client:
        response = client.get(
            "/v1/learners/learner-red-1/progress",
            headers={"Authorization": "Bearer demo-learner-red"},
        )
    assert response.status_code == 404 and repository.protected_reads == 0


def test_application_owner_guard_survives_erroneous_allow() -> None:
    repository = CountingRepository()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "result": {
                    "allow": True,
                    "reason_code": "OWNER_AND_TENANT_MATCH",
                    "policy_version": "1.0.0",
                }
            },
        )
    )
    with TestClient(create_app(repository, transport)) as client:
        response = client.get(
            "/v1/learners/learner-blue-1/progress",
            headers={"Authorization": "Bearer demo-learner-red"},
        )
    assert response.status_code == 404 and repository.protected_reads == 0


@pytest.mark.parametrize("value", ["0", "3", "not-a-number"])
def test_invalid_timeout_configuration(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("OPA_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError, match="Invalid policy configuration"):
        create_app()
