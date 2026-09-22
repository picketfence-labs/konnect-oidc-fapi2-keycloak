#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT/.generated/runtime.env" && -f "$ROOT/.env" ]]; then
  docker compose --env-file "$ROOT/.env" --env-file "$ROOT/.generated/runtime.env" down --volumes
fi

echo "Terraform will destroy the Konnect control plane, DP certificate, and Auth0 demo resources." >&2
"$ROOT/scripts/with-env.sh" terraform -chdir="$ROOT/infra" destroy
rm -rf "$ROOT/.generated"
