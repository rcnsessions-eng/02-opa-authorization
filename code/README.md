# PRD 02: OPA Authorization and Default Deny

This folder implements **only PRD 02**. `app/authz/` extends the foundation package supplied by PRD 01's explicitly built images. It does not contain a duplicate learning API. OPA decides; the resource-owning application service enforces the decision before the protected progress lookup. MCP, caching, real identity and Istio remain out of scope.

## Run and Test

Keep the numbered projects together; Docker build context is the parent workshop root. From this `code/` directory:

```bash
bash scripts/run.sh
bash scripts/check.sh
LEARNING_BASE_URL=http://127.0.0.1:8221 python3 ../../01-foundation-learning-api/code/scripts/smoke.py
python3 scripts/outage_check.py
LEARNING_BASE_URL=http://127.0.0.1:8221 python3 ../../01-foundation-learning-api/code/scripts/smoke.py
```

OpenAPI UI: <http://127.0.0.1:8221/docs>. `run.sh` builds the upstream foundation API image first, then this project's API and private OPA service. `check.sh` builds the upstream check image too, then runs Python lint/format/mypy/tests, real Rego tests and a tenant-condition mutation check. The mutation uses temporary files, never the live policy. `outage_check.py` stops only this Compose project's OPA, verifies a safe 503, and restores its API/OPA in a `finally` block.

Loopback port and dedicated subnet can be overridden with `LEARNING_PORT` and `LEARNING_SUBNET`; set `LEARNING_BASE_URL` consistently for HTTP scripts. `.env.example` contains a placeholder credential; public synthetic demo defaults work without copying it. Replacement smoke credentials must resolve to `learner-red-1` and be supplied as `LEARNING_SMOKE_CREDENTIAL`.

## Versioned Contract

Input schema version: `1.0`, generated at `policy/schema/input-v1.json`. Policy revision: `1.0.0`, recorded in `policy/rego/.manifest` and every decision. The policy input has principal, workload, canonical action, resource, tenant and request context. Subject/tenant come from server demo identity, owner/tenant from authoritative learner metadata, action from the service method and workload from trusted server configuration. Raw user/tenant/role headers do not override these fields.

Canonical actions are `content.search`, `progress.read`, `assessment.create` and `evidence.record`. Only approved-content search and own progress reads have allow rules. Reserved writes default deny because PRD 01 has no write operations. This is not an implementation of later write-tool PRDs.

The only accepted response is a strict `result` object with boolean `allow`, a recognized reason code and exact policy version. Unexpected fields, unknown versions/reasons, string booleans, missing decisions, errors, timeouts and oversized results fail closed with 503. Valid denials return a non-enumerating 404. HTTPX has bounded phase timeouts (default 0.5 seconds); streamed response processing has a 4 KiB ceiling and checks a four-phase time budget between chunks. This is not a separate preemptive hard-deadline executor.

Application ownership checks remain active even if a policy erroneously allows a foreign request. Metadata resolution and protected progress lookup are different operations. Audit events identify action, request ID, allow/deny, reason and policy version without principal records, credentials or resource payloads. An allow audit event records a policy decision, not proof that an effect committed.

The fixed `learning-api` workload attribute is a **local application fixture**, not cryptographically verified workload identity or mTLS. Human identity remains the PRD 01 demo mechanism. OPA is not host-published; Docker network membership is not a production trust boundary.

## Artifacts

After building the check image:

```bash
docker compose --profile tools run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace checks python /scripts/build_artifacts.py
```

Generated, ignored outputs: `artifacts/learning-policy-v1.0.0.tar.gz` and `artifacts/input-v1.json`. They are versioned policy/schema outputs, **not SBOMs, vulnerability reports, signed releases or provenance verification**. Those controls belong to PRD 09.

The workshop-root `.github/workflows/prd02-policy.yml` invokes the same local gate. GitHub discovers it only when this workshop root is the published repository root (or the workflow is deliberately relocated). No repository URL is invented and no hosted CI execution is claimed.

## Cleanup

```bash
docker compose down
```

Only this project's containers/network are removed. Earlier projects can stay running independently. No Kubernetes context is changed. Actual results and residual risks are recorded in the parent documentation.