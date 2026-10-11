import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from pydantic import AnyHttpUrl, BaseModel, Field, ValidationError

from app.api.routes import learning_service
from app.authz.client import OPAClient
from app.authz.service import AuthorizedLearningService
from app.main import create_app as foundation_app
from app.repositories.memory import InMemoryLearningRepository


class PolicySettings(BaseModel):
    url: AnyHttpUrl
    timeout: float = Field(default=0.5, ge=0.01, le=2.0)


def create_app(
    repository: InMemoryLearningRepository | None = None,
    transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    try:
        settings = PolicySettings.model_validate(
            {
                "url": os.getenv("OPA_URL", "http://opa:8181"),
                "timeout": os.getenv("OPA_TIMEOUT_SECONDS", "0.5"),
            }
        )
    except ValidationError:
        raise ValueError("Invalid policy configuration") from None
    records = repository if repository is not None else InMemoryLearningRepository()
    client = OPAClient(str(settings.url), settings.timeout, transport=transport)
    application = foundation_app(repository=records)
    logger = logging.getLogger("learning.authorization")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    def service_for_request(request: Request) -> AuthorizedLearningService:
        return AuthorizedLearningService(records, client, request.state.request_id)

    application.dependency_overrides[learning_service] = service_for_request
    original_lifespan = application.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        try:
            async with original_lifespan(application):
                yield
        finally:
            client.close()

    application.router.lifespan_context = lifespan
    application.title = "PRD 02 OPA-Authorized Learning API"
    return application
