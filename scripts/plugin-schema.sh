#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
GATEWAY="${GATEWAY:-}"

if [[ $# -ne 1 || ${STAGE+x} == x ]]; then
  echo "Schema operations accept only check|sync and GATEWAY; STAGE is not supported" >&2
  exit 2
fi

case "$MODE" in
  check) OPERATION="schema-check" ;;
  sync) OPERATION="schema-sync" ;;
  *) echo "Usage: $0 {check|sync}" >&2; exit 2 ;;
esac

exec python3 "$ROOT/scripts/wp1_target.py" "$OPERATION" \
  --root "$ROOT" --gateway "$GATEWAY"
