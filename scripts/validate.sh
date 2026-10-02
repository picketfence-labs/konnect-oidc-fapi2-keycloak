#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
terraform -chdir="$ROOT/infra" fmt -check -recursive
terraform -chdir="$ROOT/infra" validate
"$ROOT/scripts/deck.sh" validate
KONNECT_API_CP_HOST="validation-api.cp.konghq.com" \
KONNECT_API_TP_HOST="validation-api.tp.konghq.com" \
KONNECT_THIRD_PARTY_CP_HOST="validation-third-party.cp.konghq.com" \
KONNECT_THIRD_PARTY_TP_HOST="validation-third-party.tp.konghq.com" \
docker compose --env-file "$ROOT/.env.example" -f "$ROOT/docker-compose.yml" config --quiet
python3 "$ROOT/tests/test_static.py"
python3 "$ROOT/tests/test_jwk_export.py"
python3 "$ROOT/tests/test_runtime_secrets.py"
