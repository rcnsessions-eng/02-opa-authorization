FROM openpolicyagent/opa:1.21.1-static@sha256:4675ab04ad1627f74741d2d9c5142698c79e18b7b09f192587d31d6dba20838e AS policy
FROM zero-trust-learning-api-api:0.1.0 AS runtime
ENV PYTHONPATH=/app
USER root
COPY 01-foundation-learning-api/code/requirements.lock /deps/foundation.lock
RUN pip install --no-cache-dir -c /deps/foundation.lock httpx==0.28.1
COPY 02-opa-authorization/code/app/authz /app/app/authz
USER 10001:10001
CMD ["uvicorn", "app.authz.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM zero-trust-learning-api-checks:0.1.0 AS checks
ENV PYTHONPATH=/app
COPY --from=policy /opa /usr/local/bin/opa
COPY 02-opa-authorization/code/app/authz /app/app/authz
COPY 02-opa-authorization/code/tests /checks
COPY 02-opa-authorization/code/scripts /scripts
COPY 02-opa-authorization/code/policy /policy
CMD ["sh", "-c", "ruff check app/authz /checks /scripts && ruff format --check app/authz /checks /scripts && mypy app/authz /scripts && python -m pytest -p no:cacheprovider /checks && opa test /policy -v && python /scripts/mutation_check.py"]