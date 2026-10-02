#!/usr/bin/env python3
"""Validate the WP1 target locally and remotely before calling decK."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wp1_target import (  # noqa: E402
    FOUNDATION_FILES,
    check_schemas,
    local_manifest,
    read_env,
    verify_remote_target,
)


def sanitize_output(text: str, secrets: list[str]) -> str:
    text = re.sub(
        r"-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----",
        "[REDACTED PEM]",
        text,
        flags=re.DOTALL,
    )
    for secret in sorted({value for value in secrets if isinstance(value, str) and len(value) >= 4}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["diff", "sync"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--gateway", choices=["api", "third-party"], required=True)
    parser.add_argument("--stage", required=True)
    args = parser.parse_args()
    root = args.root.resolve()

    # This is the sole decK launch path. Validate selector, YAML ownership, and
    # target mapping before reading a token or making any network request.
    info = local_manifest(root, args.gateway, args.stage, args.mode)
    if args.stage != "foundation":
        raise ValueError("WP1 decK launcher accepts foundation state only")
    state = root / FOUNDATION_FILES[args.gateway]
    if not state.is_file():
        raise ValueError("fixed foundation state is unavailable")
    role_file = root / ".generated" / f"runtime-{args.gateway}.json"
    if not role_file.is_file():
        raise ValueError("role-scoped decK inputs are missing; run make generate-dev-assets")

    config = read_env(root / ".env")
    token = config.get("KONNECT_TOKEN", "")
    if not token:
        raise ValueError("KONNECT_TOKEN is required after local target validation")
    manifest = info["manifest"]
    base = manifest["konnect_server_url"].rstrip("/")
    target = info["target"]
    verify_remote_target(base, target, token)
    check_schemas(root, args.gateway, base, target, token)

    generated = read_env(root / ".generated/deck.env")
    role_values = json.loads(role_file.read_text())
    if not isinstance(role_values, dict):
        raise ValueError("role-scoped decK input is malformed")
    environment = os.environ.copy()
    environment.update(generated)
    environment.update(role_values)
    environment.update(
        {
            "KONNECT_TOKEN": token,
            "KONNECT_SERVER_URL": base,
            "KONNECT_CONTROL_PLANE_NAME": target["control_plane_name"],
        }
    )
    command = [
        "deck",
        "gateway",
        args.mode,
        str(state),
        "--konnect-addr",
        base,
        "--konnect-token",
        token,
        "--konnect-control-plane-name",
        target["control_plane_name"],
    ]
    print(f"decK {args.mode}: gateway={args.gateway}, stage=foundation, target={target['control_plane_name']}")
    result = subprocess.run(command, cwd=root, env=environment, check=False, capture_output=True, text=True)
    sensitive_values = [token, *generated.values(), *role_values.values()]
    sys.stdout.write(sanitize_output(result.stdout, sensitive_values))
    sys.stderr.write(sanitize_output(result.stderr, sensitive_values))
    return result.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"decK target preparation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
