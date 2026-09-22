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

: "${AUTH0_DOMAIN:?AUTH0_DOMAIN is required}"
: "${AUTH0_CLIENT_ID:?AUTH0_CLIENT_ID is required}"
: "${KONNECT_TOKEN:?KONNECT_TOKEN is required}"
export TF_VAR_auth0_domain="$AUTH0_DOMAIN"
export TF_VAR_auth0_management_client_id="$AUTH0_CLIENT_ID"
export KONNECT_SERVER_URL="${KONNECT_SERVER_URL:-https://us.api.konghq.com}"

exec "$@"
