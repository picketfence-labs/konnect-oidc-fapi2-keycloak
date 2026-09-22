#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
terraform -chdir="$ROOT/infra" fmt -check -recursive
terraform -chdir="$ROOT/infra" validate
export DECK_AUTH0_ISSUER="https://validation.invalid/"
export DECK_AUTH0_CLIENT_ID="validation-client"
export DECK_AUTH0_CLIENT_SECRET="validation-secret"
export DECK_AUTH0_AUDIENCE="https://validation.invalid/api"
export DECK_AUTH0_PAR_ENDPOINT="https://validation.invalid/oauth/par"
export DECK_DEPARTMENT_CLAIM="https://oidc-demo.example.com/department"
export DECK_ROUTE_CLAIM="https://oidc-demo.example.com/route"
export DECK_SESSION_SECRET="01234567890123456789012345678901"
export DECK_CACHE_TOKENS_SALT="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
deck file validate "$ROOT/kong/kong.yaml"
deck file validate "$ROOT/kong/kong-par.yaml"
KONNECT_CP_HOST="validation.cp.konghq.com" \
KONNECT_TP_HOST="validation.tp.konghq.com" \
docker compose --env-file "$ROOT/.env.example" -f "$ROOT/docker-compose.yml" config --quiet
python3 "$ROOT/tests/test_static.py"
