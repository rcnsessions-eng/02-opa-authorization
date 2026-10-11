#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
docker compose -f ../../01-foundation-learning-api/code/docker-compose.yml --profile tools build api checks
docker compose --profile tools build checks
docker compose --profile tools run --rm checks