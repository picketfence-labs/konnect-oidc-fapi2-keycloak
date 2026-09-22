#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
if [[ ! -f "$ROOT/.generated/deck.env" || ! -f "$ROOT/.env" ]]; then
  echo "Run make render after Terraform apply." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$ROOT/.env"
# shellcheck disable=SC1091
source "$ROOT/.generated/deck.env"
set +a

STATE="$ROOT/kong/kong.yaml"
if [[ "$PAR_ENABLED" == "true" ]]; then STATE="$ROOT/kong/kong-par.yaml"; fi

common=(--konnect-addr "${KONNECT_SERVER_URL:-https://us.api.konghq.com}" --konnect-token "$KONNECT_TOKEN" --konnect-control-plane-name "$KONNECT_CONTROL_PLANE_NAME" --select-tag oidc-routing-demo)

case "$MODE" in
  validate)
    deck file validate "$STATE"
    ;;
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
