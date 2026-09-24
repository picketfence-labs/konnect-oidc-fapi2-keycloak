#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -f "$ROOT/.env" ]]; then
  echo "Missing $ROOT/.env; copy .env.example and fill credentials." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$ROOT/.env"
set +a

: "${KONNECT_TOKEN:?KONNECT_TOKEN is required}"
export KONNECT_SERVER_URL="${KONNECT_SERVER_URL:-https://us.api.konghq.com}"

exec "$@"
