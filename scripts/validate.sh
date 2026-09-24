#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
terraform -chdir="$ROOT/infra" fmt -check -recursive
terraform -chdir="$ROOT/infra" validate
"$ROOT/scripts/deck.sh" validate
KONNECT_CP_HOST="validation.cp.konghq.com" \
KONNECT_TP_HOST="validation.tp.konghq.com" \
docker compose --env-file "$ROOT/.env.example" -f "$ROOT/docker-compose.yml" config --quiet
python3 "$ROOT/tests/test_static.py"
python3 "$ROOT/tests/test_jwk_export.py"
python3 "$ROOT/tests/test_runtime_secrets.py"
