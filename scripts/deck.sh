#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"

if [[ "$MODE" == "validate" ]]; then
  export DECK_FAPI_CA_CERT_YAML="validation-ca-certificate"
  export DECK_ROUTE_A_TLS_CERT_YAML="validation-route-a-certificate"
  export DECK_ROUTE_B_TLS_CERT_YAML="validation-route-b-certificate"
  export DECK_API_INTROSPECTION_CERT_YAML="validation-introspection-certificate"
  export DECK_API_UPSTREAM_CERT_YAML="validation-upstream-certificate"
  export DECK_ROUTE_A_SESSION_SECRET="validation-route-a-session"
  export DECK_ROUTE_B_SESSION_SECRET="validation-route-b-session"
  export DECK_ROUTE_A_CACHE_SALT="validation-route-a-cache"
  export DECK_ROUTE_B_CACHE_SALT="validation-route-b-cache"
  export DECK_ROUTE_B_JWK_KID="validation-jwk-kid"
  export DECK_ROUTE_B_JWK_N="validation-jwk-modulus"
  export DECK_ROUTE_B_JWK_E="AQAB"
  python3 "$ROOT/scripts/wp1_target.py" validate --root "$ROOT" --gateway api
  python3 "$ROOT/scripts/wp1_target.py" validate --root "$ROOT" --gateway third-party
  python3 "$ROOT/scripts/wp1_target.py" validate --root "$ROOT" --gateway third-party --stage runtime
  deck file validate "$ROOT/kong/kong.yaml"
  deck file validate "$ROOT/kong/api-gateway.yaml"
  deck file validate "$ROOT/kong/third-party-gateway.yaml"
  deck file validate "$ROOT/kong/foundation/api.yaml"
  deck file validate "$ROOT/kong/foundation/third-party.yaml"
  exit 0
fi

if [[ "$MODE" != "diff" && "$MODE" != "sync" ]]; then
  echo "Usage: $0 {validate|diff|sync}" >&2
  exit 2
fi

GATEWAY="${GATEWAY:-}"
STAGE="${STAGE:-}"
exec python3 "$ROOT/scripts/run-deck.py" "$MODE" \
  --root "$ROOT" --gateway "$GATEWAY" --stage "$STAGE"
