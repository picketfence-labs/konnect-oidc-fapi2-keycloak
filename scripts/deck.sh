#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
STATE="$ROOT/kong/kong.yaml"

if [[ "$MODE" == "validate" ]]; then
  export DECK_FAPI_CA_CERT_YAML="validation-ca-certificate"
  export DECK_ROUTE_A_SESSION_SECRET="validation-session-secret-route-a-0001"
  export DECK_ROUTE_B_SESSION_SECRET="validation-session-secret-route-b-0001"
  export DECK_ROUTE_A_CACHE_SALT="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  export DECK_ROUTE_B_CACHE_SALT="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
  export DECK_ROUTE_B_JWK_KID="validation-key-id"
  export DECK_ROUTE_B_JWK_N="validation-modulus"
  export DECK_ROUTE_B_JWK_E="AQAB"
  exec deck file validate "$STATE"
fi

if [[ ! -f "$ROOT/.generated/deck.env" || ! -f "$ROOT/.env" ]]; then
  echo "Run make generate-dev-assets and copy .env.example to .env first." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$ROOT/.env"
# shellcheck disable=SC1091
source "$ROOT/.generated/deck.env"
set +a

export DECK_FAPI_CA_CERT_YAML="$(python3 - "$ROOT/.generated/pki/ca.crt" <<'PY'
import json
import sys
from pathlib import Path

encoded = json.dumps(Path(sys.argv[1]).read_text())
print(encoded[1:-1])
PY
)"

common=(--konnect-addr "${KONNECT_SERVER_URL:-https://us.api.konghq.com}" --konnect-token "$KONNECT_TOKEN" --konnect-control-plane-name "$KONNECT_CONTROL_PLANE_NAME" --select-tag fapi2-demo)

"$ROOT/scripts/plugin-schema.sh" check

case "$MODE" in
  diff)
    deck gateway diff "$STATE" "${common[@]}"
    ;;
  sync)
    echo "This will mutate Gateway entities in Konnect control plane: $KONNECT_CONTROL_PLANE_NAME" >&2
    deck gateway sync "$STATE" "${common[@]}"
    ;;
  *)
    echo "Usage: $0 {validate|diff|sync}" >&2
    exit 2
    ;;
esac
