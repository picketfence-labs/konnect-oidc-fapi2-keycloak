#!/usr/bin/env python3
"""Validate the WP1 target locally and remotely before calling decK."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wp1_target import (  # noqa: E402
    FOUNDATION_FILES,
    RUNTIME_FILES,
    check_schemas,
    local_manifest,
    read_env,
    validate_role_values,
    verify_shared_api_ca,
    verify_remote_target,
)
from wp3_runtime import (  # noqa: E402
    canonical_sha256,
    file_sha256,
    parse_deck_diff_report,
    read_migration_approval,
)


def sanitize_output(text: str, secrets: list[str]) -> str:
    text = re.sub(
        r"-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----",
        "[REDACTED PEM]",
        text,
        flags=re.DOTALL,
    )
    safe_secrets = {value for value in secrets if isinstance(value, str) and len(value) >= 4}
    for secret in sorted(safe_secrets, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


DECK_SUBPROCESS_TIMEOUT_SECONDS = 300
MAX_ROLE_FILE_BYTES = 1_048_576


def read_private_role_file(path: Path, *, require_private_mode: bool) -> object:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None or path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError("role-scoped decK input directory is missing or unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise ValueError("role-scoped decK inputs are missing or unsafe") from None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (require_private_mode and stat.S_IMODE(info.st_mode) != 0o600)
            or info.st_size > MAX_ROLE_FILE_BYTES
        ):
            raise ValueError("role-scoped decK input must be a regular file with safe permissions under 1 MiB")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_ROLE_FILE_BYTES + 1)
        if len(raw) > MAX_ROLE_FILE_BYTES:
            raise ValueError("role-scoped decK input must be a regular file with safe permissions under 1 MiB")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError("role-scoped decK inputs are malformed") from None
    finally:
        os.close(descriptor)


def run_deck_subprocess(
    command: list[str],
    *,
    root: Path,
    environment: dict[str, str],
    stage: str,
    mode: str,
    purpose: str,
):
    try:
        return subprocess.run(
            command,
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=DECK_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        if stage == "runtime" and mode == "sync":
            raise ValueError(
                "API runtime migration sync timed out; outcome is unknown; "
                "inspect current state before any retry"
            ) from None
        if purpose == "migration pre-sync diff":
            raise ValueError("API runtime migration diff timed out; sync was not attempted") from None
        raise ValueError(f"decK {mode} timed out; no raw subprocess output was retained") from None
    except OSError:
        if stage == "runtime" and mode == "sync":
            raise ValueError(
                "API runtime migration sync transport failed; outcome is unknown; "
                "inspect current state before any retry"
            ) from None
        raise ValueError(f"decK {mode} could not be started; no raw subprocess output was retained") from None


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
    if args.stage == "foundation":
        state_relative = FOUNDATION_FILES[args.gateway]
    elif args.stage == "runtime" and args.gateway == "api":
        state_relative = RUNTIME_FILES["api"]
    else:
        raise ValueError("runtime decK state is available only for the API gateway")
    state = root / state_relative
    if not state.is_file():
        raise ValueError(f"fixed {args.stage} state is unavailable")

    if (
        args.stage == "runtime"
        and args.mode == "sync"
        and os.environ.get("WP3_API_RUNTIME_MIGRATION_APPROVED") != "YES"
    ):
        raise ValueError(
            "API runtime sync is a separate live migration; it requires "
            "WP3_API_RUNTIME_MIGRATION_APPROVED=YES after root review"
        )

    role_file = root / ".generated" / f"runtime-{args.gateway}.json"
    role_values = validate_role_values(
        args.gateway,
        read_private_role_file(role_file, require_private_mode=args.stage == "runtime"),
    )
    role_inputs_sha256 = canonical_sha256(role_values)

    migration_receipt = None
    if args.stage == "runtime" and args.mode == "sync":
        # Local approval binding is checked before loading the Konnect token or contacting Konnect.
        target = info["target"]
        migration_receipt = read_migration_approval(root, target["control_plane_id"], role_values)

    config = read_env(root / ".env")
    token = config.get("KONNECT_TOKEN", "")
    if not token:
        raise ValueError("KONNECT_TOKEN is required after local target validation")
    manifest = info["manifest"]
    base = manifest["konnect_server_url"].rstrip("/")
    target = info["target"]
    verify_remote_target(base, target, token)
    if args.gateway == "api":
        verify_shared_api_ca(base, target, token, role_values["DECK_FAPI_CA_CERT_YAML"])
    check_schemas(root, args.gateway, base, target, token)

    generated = read_env(root / ".generated/deck.env")
    environment = os.environ.copy()
    environment.update(generated)
    environment.update(role_values)
    environment.update(
        {
            "DECK_KONNECT_TOKEN": token,
            "KONNECT_SERVER_URL": base,
            "KONNECT_CONTROL_PLANE_NAME": target["control_plane_name"],
        }
    )
    environment.pop("KONNECT_TOKEN", None)
    sensitive_values = [token, *generated.values(), *role_values.values()]
    common_command = [
        "deck",
        "gateway",
        None,
        str(state),
        "--konnect-addr",
        base,
        "--konnect-control-plane-name",
        target["control_plane_name"],
    ]
    if args.stage == "runtime" and args.mode == "sync":
        diff_command = [*common_command]
        diff_command[2] = "diff"
        diff_command.append("--json-output")
        diff_command.append("--no-color")
        diff_result = run_deck_subprocess(
            diff_command,
            root=root,
            environment=environment,
            stage=args.stage,
            mode="diff",
            purpose="migration pre-sync diff",
        )
        if diff_result.returncode != 0:
            raise ValueError("API runtime migration diff failed; sync was not attempted")
        if diff_result.stderr.strip():
            raise ValueError("API runtime migration diff returned unexpected diagnostics; sync was not attempted")
        current_operations, current_diff_sha256 = parse_deck_diff_report(diff_result.stdout)
        if (
            migration_receipt is None
            or current_diff_sha256 != migration_receipt["diff_sha256"]
            or current_operations["summary"] != migration_receipt["summary"]
            or current_operations["operations"] != migration_receipt["operations"]
        ):
            raise ValueError("API runtime migration diff changed after approval; sync was not attempted")
        current_role_values = validate_role_values(
            args.gateway,
            read_private_role_file(role_file, require_private_mode=True),
        )
        if (
            state.is_symlink()
            or file_sha256(state) != migration_receipt["state_sha256"]
            or canonical_sha256(current_role_values) != migration_receipt["role_inputs_sha256"]
        ):
            raise ValueError(
                "API runtime state or certificate role inputs changed after approval; "
                "sync was not attempted"
            )

    command = [*common_command]
    command[2] = args.mode
    print(
        f"decK {args.mode}: gateway={args.gateway}, stage={args.stage}, target={target['control_plane_name']}"
    )
    if args.stage == "runtime" and args.mode == "diff":
        command.append("--json-output")
        command.append("--no-color")
    result = run_deck_subprocess(
        command,
        root=root,
        environment=environment,
        stage=args.stage,
        mode=args.mode,
        purpose="requested command",
    )
    safe_stdout = sanitize_output(result.stdout, sensitive_values)
    safe_stderr = sanitize_output(result.stderr, sensitive_values)
    if args.stage == "runtime" and args.mode == "diff":
        if result.returncode != 0:
            raise ValueError("API runtime migration diff failed")
        if safe_stderr.strip():
            raise ValueError("API runtime migration diff returned unexpected diagnostics")
        operations, digest = parse_deck_diff_report(result.stdout)
        print(json.dumps(operations, sort_keys=True, separators=(",", ":")))
        print(f"WP3_MIGRATION_DIFF_SHA256={digest}")
        print(f"WP3_API_RUNTIME_STATE_SHA256={file_sha256(state)}")
        print(f"WP3_API_RUNTIME_ROLE_INPUTS_SHA256={role_inputs_sha256}")
    elif args.stage == "runtime" and args.mode == "sync" and result.returncode != 0:
        raise ValueError(
            "API runtime migration sync exited nonzero; outcome is unknown; "
            "inspect current state before any retry"
        )
    else:
        sys.stdout.write(safe_stdout)
        sys.stderr.write(safe_stderr)
    return result.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"decK target preparation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
