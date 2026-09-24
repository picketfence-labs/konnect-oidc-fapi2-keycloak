#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF=("$ROOT/scripts/with-env.sh" terraform -chdir="$ROOT/infra" output -raw)
mkdir -p "$ROOT/.generated"
mode="${1:-runtime}"
if [[ "$mode" != runtime ]]; then
  echo "Usage: $0 runtime" >&2
  exit 2
fi

strip_endpoint() {
  sed -E 's#^https?://##; s#:[0-9]+$##; s#/$##'
}

cp_host="$(${TF[@]} control_plane_endpoint | strip_endpoint)"
tp_host="$(${TF[@]} telemetry_endpoint | strip_endpoint)"
runtime_file="$ROOT/.generated/runtime.env"
touch "$runtime_file"
python3 - "$runtime_file" "$cp_host" "$tp_host" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
kept = [
    line for line in path.read_text().splitlines()
    if line and not line.startswith(("KONNECT_CP_HOST=", "KONNECT_TP_HOST="))
]
kept.extend((f"KONNECT_CP_HOST={sys.argv[2]}", f"KONNECT_TP_HOST={sys.argv[3]}"))
path.write_text("\n".join(kept) + "\n")
PY
chmod 600 "$ROOT/.generated/runtime.env"
echo "Rendered gitignored runtime files under .generated/."
