#!/usr/bin/env python3
"""Render non-secret dual-Gateway runtime targets from Terraform outputs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from wp1 import validate_targets


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key in {"TF_VAR_control_plane_name", "TF_VAR_third_party_control_plane_name", "KONNECT_SERVER_URL"}:
            values[key] = value.strip().strip("\"'")
    return values


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    config = read_env_file(root / ".env")
    region_url = os.environ.get(
        "KONNECT_SERVER_URL", config.get("KONNECT_SERVER_URL", "https://us.api.konghq.com")
    ).rstrip("/")
    expected_names = {
        "api": os.environ.get(
            "TF_VAR_control_plane_name",
            config.get("TF_VAR_control_plane_name", "keycloak-fapi2-demo"),
        ),
        "third-party": os.environ.get(
            "TF_VAR_third_party_control_plane_name",
            config.get("TF_VAR_third_party_control_plane_name", "keycloak-fapi2-third-party-demo"),
        ),
    }
    output = subprocess.run(
        ["terraform", f"-chdir={root / 'infra'}", "output", "-json", "gateway_targets"],
        check=True,
        capture_output=True,
        text=True,
    )
    targets = validate_targets(json.loads(output.stdout), expected_names)

    source_targets = json.loads(output.stdout)
    manifest = {"konnect_server_url": region_url, "targets": source_targets}
    generated = root / ".generated"
    generated.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest_path = generated / "gateway_targets.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    manifest_path.chmod(0o600)

    runtime_path = generated / "runtime.env"
    prior = runtime_path.read_text().splitlines() if runtime_path.exists() else []
    names = {
        "KONNECT_CP_HOST",
        "KONNECT_TP_HOST",
        "KONNECT_API_CP_HOST",
        "KONNECT_API_TP_HOST",
        "KONNECT_THIRD_PARTY_CP_HOST",
        "KONNECT_THIRD_PARTY_TP_HOST",
        "KONNECT_SERVER_URL",
    }
    kept = [line for line in prior if line.partition("=")[0] not in names]
    rendered = [
        f"KONNECT_API_CP_HOST={targets['api']['control_plane_host']}",
        f"KONNECT_API_TP_HOST={targets['api']['telemetry_host']}",
        f"KONNECT_THIRD_PARTY_CP_HOST={targets['third-party']['control_plane_host']}",
        f"KONNECT_THIRD_PARTY_TP_HOST={targets['third-party']['telemetry_host']}",
        f"KONNECT_SERVER_URL={region_url}",
    ]
    runtime_path.write_text("\n".join([*kept, *rendered]) + "\n")
    runtime_path.chmod(0o600)
    print("Rendered dual-Gateway target manifest and runtime endpoints under .generated/.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"Cannot render dual-Gateway runtime targets: {exc}", file=sys.stderr)
        raise SystemExit(1)
