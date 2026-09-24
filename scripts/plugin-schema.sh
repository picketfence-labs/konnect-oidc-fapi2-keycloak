#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
PLUGIN_NAME="fapi-client-auth-bridge"
SCHEMA="$ROOT/kong/plugins/$PLUGIN_NAME/schema.lua"

if [[ "$MODE" != "check" && "$MODE" != "sync" ]]; then
  echo "Usage: $0 {check|sync}" >&2
  exit 2
fi

if [[ ! -f "$ROOT/.env" ]]; then
  echo "Missing $ROOT/.env; copy .env.example and fill credentials." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$ROOT/.env"
set +a

: "${KONNECT_TOKEN:?KONNECT_TOKEN is required}"
KONNECT_SERVER_URL="${KONNECT_SERVER_URL:-https://us.api.konghq.com}"
KONNECT_SERVER_URL="${KONNECT_SERVER_URL%/}"
CONTROL_PLANE_ID="${KONNECT_CONTROL_PLANE_ID:-$(terraform -chdir="$ROOT/infra" output -raw control_plane_id)}"
COLLECTION_URL="$KONNECT_SERVER_URL/v2/control-planes/$CONTROL_PLANE_ID/core-entities/plugin-schemas"
PLUGIN_URL="$COLLECTION_URL/$PLUGIN_NAME"

response="$(mktemp)"
payload="$(mktemp)"
trap 'rm -f "$response" "$payload"' EXIT

status="$(curl --silent --show-error --output "$response" --write-out '%{http_code}' \
  --header "Authorization: Bearer $KONNECT_TOKEN" \
  "$PLUGIN_URL")"

if [[ "$MODE" == "check" ]]; then
  if [[ "$status" == "200" ]]; then
    echo "Konnect custom plugin schema is registered: $PLUGIN_NAME"
    exit 0
  fi
  if [[ "$status" == "404" ]]; then
    echo "Konnect custom plugin schema is not registered: $PLUGIN_NAME" >&2
    echo "Review the schema, then run 'make plugin-schema-sync' before deck diff/sync." >&2
    exit 1
  fi
  echo "Failed to inspect custom plugin schema (HTTP $status)." >&2
  exit 1
fi

python3 - "$SCHEMA" "$payload" <<'PY'
import json
import sys
from pathlib import Path

schema_path = Path(sys.argv[1])
payload_path = Path(sys.argv[2])
payload_path.write_text(json.dumps({"lua_schema": schema_path.read_text()}))
PY

if [[ "$status" == "200" ]]; then
  method="PUT"
  target="$PLUGIN_URL"
elif [[ "$status" == "404" ]]; then
  method="POST"
  target="$COLLECTION_URL"
else
  echo "Failed to inspect custom plugin schema before sync (HTTP $status)." >&2
  exit 1
fi

curl --silent --show-error --fail-with-body \
  --request "$method" \
  --header "Authorization: Bearer $KONNECT_TOKEN" \
  --header "Content-Type: application/json" \
  --data-binary "@$payload" \
  --output "$response" \
  "$target"

echo "Synchronized Konnect custom plugin schema: $PLUGIN_NAME"
