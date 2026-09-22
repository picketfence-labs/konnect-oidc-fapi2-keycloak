#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF=("$ROOT/scripts/with-env.sh" terraform -chdir="$ROOT/infra" output -raw)
mkdir -p "$ROOT/.generated"
mode="${1:-all}"
if [[ "$mode" != all && "$mode" != runtime ]]; then
  echo "Usage: $0 [all|runtime]" >&2
  exit 2
fi

strip_endpoint() {
  sed -E 's#^https?://##; s#:[0-9]+$##; s#/$##'
}

cp_host="$(${TF[@]} control_plane_endpoint | strip_endpoint)"
tp_host="$(${TF[@]} telemetry_endpoint | strip_endpoint)"
cat > "$ROOT/.generated/runtime.env" <<EOF
KONNECT_CP_HOST=$cp_host
KONNECT_TP_HOST=$tp_host
EOF
chmod 600 "$ROOT/.generated/runtime.env"
if [[ "$mode" == runtime ]]; then
  echo "Rendered gitignored runtime file under .generated/."
  exit 0
fi

issuer="$(${TF[@]} auth0_issuer)"
client_id="$(${TF[@]} auth0_client_id)"
client_secret="$(${TF[@]} auth0_client_secret)"
if [[ -z "$client_secret" ]]; then
  echo "Auth0 gateway client secret is empty. Grant read:client_credentials (or read:client_keys) to the Terraform Management API client, refresh Terraform state, then rerun make render." >&2
  exit 1
fi
audience="$(${TF[@]} auth0_audience)"
department_claim="$(${TF[@]} department_claim)"
route_claim="$(${TF[@]} route_claim)"
cp_name="$(${TF[@]} control_plane_name)"
par_enabled="$(${TF[@]} par_enabled)"
session_secret="$(${TF[@]} session_secret)"
cache_tokens_salt="$(printf '%s' "$session_secret" | openssl dgst -sha256 -r | awk '{print $1}')"

cat > "$ROOT/.generated/deck.env" <<EOF
DECK_AUTH0_ISSUER=$issuer
DECK_AUTH0_CLIENT_ID=$client_id
DECK_AUTH0_CLIENT_SECRET=$client_secret
DECK_AUTH0_AUDIENCE=$audience
DECK_AUTH0_PAR_ENDPOINT=${issuer%/}/oauth/par
DECK_DEPARTMENT_CLAIM=$department_claim
DECK_ROUTE_CLAIM=$route_claim
DECK_SESSION_SECRET=$session_secret
DECK_CACHE_TOKENS_SALT=$cache_tokens_salt
KONNECT_CONTROL_PLANE_NAME=$cp_name
PAR_ENABLED=$par_enabled
EOF

chmod 600 "$ROOT/.generated/deck.env"
echo "Rendered gitignored runtime files under .generated/."
