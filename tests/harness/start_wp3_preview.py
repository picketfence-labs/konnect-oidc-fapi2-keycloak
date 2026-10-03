#!/usr/bin/env python3
"""Start only the dedicated WP3 API runtime after explicit fixture approval."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

from prepare_wp3_preview import (
    COMPOSE_FILE,
    HOST_PORTS,
    PREVIEW,
    PROJECT,
    VOLUME,
    PreviewError,
    compose_config_check,
    inspect_images,
    load_runtime_role_values,
    require_isolated_project_absent,
    require_ports_free,
    runtime_role_values,
    verify_preparation_receipt,
)


ROOT = Path(__file__).resolve().parents[2]
REQUIRED = (
    "bootstrap.env",
    "accounts.env",
    "runtime-api.json",
    "api-runtime.yml",
    "realm-import/fapi-demo-realm.json",
    "pki/ca.crt",
    "pki/keycloak.crt",
    "pki/keycloak.key",
    "pki/api-gateway.crt",
    "pki/api-gateway.key",
    "pki/api-introspection.crt",
    "pki/api-introspection.key",
    "pki/api-upstream.crt",
    "pki/api-upstream.key",
    "pki/pop-verifier.crt",
    "pki/pop-verifier.key",
    "pki/outside-ca-client.crt",
    "pki/outside-ca-client.key",
    "evidence/wp3-preparation-receipt.json",
)


def verify_assets() -> None:
    if PREVIEW.is_symlink() or not PREVIEW.is_dir() or stat.S_IMODE(PREVIEW.stat().st_mode) != 0o700:
        raise PreviewError("fresh WP3 preview directory is absent or unsafe")
    for relative in REQUIRED:
        path = PREVIEW / relative
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise PreviewError("fresh WP3 preview asset is absent or has unsafe permissions")
    receipt = PREVIEW / "evidence/wp3-preparation-receipt.json"
    if receipt.stat().st_size > 16_384:
        raise PreviewError("WP3 preparation receipt exceeds its safety limit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-start-isolated-wp3-runtime", action="store_true")
    args = parser.parse_args()
    if not args.allow_start_isolated_wp3_runtime:
        parser.error("starting the isolated Kong/Keycloak/capture Compose project requires a separate preview approval")
    try:
        verify_assets()
        require_ports_free()
        require_isolated_project_absent()
        if not os.environ.get("KONG_LICENSE_DATA"):
            raise PreviewError("Kong license is absent from the current process environment")
        inspect_images()
        role_values = load_runtime_role_values()
        verify_preparation_receipt()
        compose_config_check(role_values)
    except (PreviewError, OSError) as error:
        print(f"WP3 runtime start guard rejected the request: {error}", file=sys.stderr)
        return 1
    command = [
        "docker", "compose", "--env-file", "/dev/null",
        "--project-directory", str(ROOT), "--project-name", PROJECT,
        "-f", str(COMPOSE_FILE), "up", "--no-build", "-d",
        "keycloak", "kong-api", "pop-verifier",
    ]
    environment = os.environ.copy()
    environment["API_INTROSPECTION_KEY"] = role_values["API_INTROSPECTION_KEY"]
    environment["API_UPSTREAM_KEY"] = role_values["API_UPSTREAM_KEY"]
    result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
    if result.returncode != 0:
        print("WP3 isolated Compose start failed; no other project was targeted.", file=sys.stderr)
        return result.returncode
    print("Started only wp3-isolated-api-rs: stock Kong, fresh Keycloak, and internal TLS capture.")
    print("Host listeners are loopback-only on 127.0.0.1:18443 and :18444; OAuth callback uses :8443 during token issuance.")
    print("The TLS capture has no host port. See the exact cleanup command in tests/harness/README.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
