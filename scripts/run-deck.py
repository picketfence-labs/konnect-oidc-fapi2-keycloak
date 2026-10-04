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
from collections import Counter
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


WP5_APPROVAL_RELATIVE = Path(".generated/evidence/wp5-third-party-runtime-approval.json")
WP5_APPROVAL_FIELDS = {
    "schema_version",
    "scope",
    "approved",
    "target_sha256",
    "state_sha256",
    "role_inputs_sha256",
    "diff_sha256",
    "summary",
    "operations",
}
WP5_EXPECTED_SUMMARY = {"creating": 11, "updating": 0, "deleting": 0, "total": 11}
WP5_EXPECTED_CREATE_KINDS = Counter({"service": 2, "route": 2, "plugin": 7})
WP5_EXPECTED_CREATE_IDENTITIES = {
    ("service", "third-party-route-a-api"),
    ("service", "third-party-route-b-api"),
    ("route", "third-party-route-a"),
    ("route", "third-party-route-b"),
    ("plugin", "cors for service third-party-route-a-api"),
    ("plugin", "openid-connect for service third-party-route-a-api"),
    ("plugin", "request-transformer for service third-party-route-a-api"),
    ("plugin", "cors for service third-party-route-b-api"),
    ("plugin", "fapi-client-auth-bridge for service third-party-route-b-api"),
    ("plugin", "openid-connect for service third-party-route-b-api"),
    ("plugin", "request-transformer for service third-party-route-b-api"),
}


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


def parse_sanitized_runtime_diff(raw_output: str, secrets: list[str] | None = None) -> tuple[dict, str]:
    """Return safe operation labels and a digest of the canonical full report."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate decK runtime diff report field")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite JSON number")

    try:
        report = json.loads(
            raw_output,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError):
        raise ValueError("third-party runtime diff did not return valid JSON") from None
    operations = ("creating", "updating", "deleting")
    if not isinstance(report, dict) or set(report) != {"changes", "summary", "warnings", "errors"} \
        or report["warnings"] != [] or report["errors"] != []:
        raise ValueError("third-party runtime diff report contains errors, warnings, or unexpected fields")
    changes, summary = report["changes"], report["summary"]
    if not isinstance(changes, dict) or set(changes) != set(operations) \
        or not isinstance(summary, dict) or set(summary) != {*operations, "total"}:
        raise ValueError("third-party runtime diff report structure is malformed")

    safe_changes = {}
    normalized_changes = {}
    counts = {}
    for operation in operations:
        entries = changes[operation]
        if not isinstance(entries, list):
            raise ValueError("third-party runtime diff operation list is malformed")
        safe_entities = []
        normalized_changes[operation] = []
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"kind", "name", "body"} \
                or not isinstance(entry["kind"], str) \
                or entry["kind"] not in {"service", "route", "plugin", "certificate", "ca_certificate"} \
                or not isinstance(entry["name"], str) or not entry["name"] \
                or len(entry["name"]) > 256 or any(ord(char) < 0x20 or ord(char) == 0x7f for char in entry["name"]) \
                or not isinstance(entry["body"], dict) or set(entry["body"]) != {"old", "new"}:
                raise ValueError("third-party runtime diff entity is malformed")
            old_entity, new_entity = entry["body"]["old"], entry["body"]["new"]
            if operation == "creating" and (old_entity is not None or not isinstance(new_entity, dict)):
                raise ValueError("third-party runtime diff create body is malformed")
            if operation == "updating" and (not isinstance(old_entity, dict) or not isinstance(new_entity, dict)):
                raise ValueError("third-party runtime diff update body is malformed")
            if operation == "deleting" and (old_entity is not None or not isinstance(new_entity, dict)):
                raise ValueError("third-party runtime diff delete body is malformed")
            safe_name = sanitize_output(entry["name"], secrets or [])
            identity = (entry["kind"], safe_name)
            if identity in seen:
                raise ValueError("third-party runtime diff contains duplicate operation identities")
            seen.add(identity)
            safe_entities.append({"kind": identity[0], "name": identity[1]})
            normalized_changes[operation].append(entry)
        safe_entities.sort(key=lambda entity: (entity["kind"], entity["name"]))
        normalized_changes[operation].sort(key=lambda entry: (entry["kind"], entry["name"]))
        safe_changes[operation] = safe_entities
        counts[operation] = len(safe_entities)
        if type(summary[operation]) is not int or summary[operation] != len(safe_entities):
            raise ValueError("third-party runtime diff summary does not match its operation identities")
    total = sum(counts.values())
    if type(summary["total"]) is not int or summary["total"] != total:
        raise ValueError("third-party runtime diff total is malformed")
    safe_report = {
        "changes": normalized_changes,
        "summary": {**counts, "total": total},
        "warnings": [],
        "errors": [],
    }
    digest = canonical_sha256(safe_report)
    return {"summary": {**counts, "total": total}, "operations": safe_changes}, digest


def validate_wp5_additive_scope(operations: dict) -> None:
    summary = operations.get("summary") if isinstance(operations, dict) else None
    changes = operations.get("operations") if isinstance(operations, dict) else None
    if summary != WP5_EXPECTED_SUMMARY or not isinstance(changes, dict) \
        or set(changes) != {"creating", "updating", "deleting"} \
        or changes["updating"] or changes["deleting"]:
        raise ValueError(
            "third-party runtime diff is not the reviewed additive 11/0/0 change; "
            "inspect with read-only diff; sync was not attempted"
        )
    if not isinstance(changes["creating"], list) or Counter(
        entry.get("kind") for entry in changes["creating"] if isinstance(entry, dict)
    ) != WP5_EXPECTED_CREATE_KINDS or len(changes["creating"]) != 11:
        raise ValueError(
            "third-party runtime diff is not the reviewed additive 11/0/0 change; "
            "inspect with read-only diff; sync was not attempted"
        )
    identities = {(entry["kind"], entry["name"]) for entry in changes["creating"]}
    if identities != WP5_EXPECTED_CREATE_IDENTITIES:
        raise ValueError(
            "third-party runtime diff create identities differ from the reviewed fixed 11-entity scope; "
            "sync was not attempted"
        )


def _read_wp5_approval_bytes(path: Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("third-party runtime approval cannot be safely opened on this platform")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise ValueError("third-party runtime approval receipt is missing or unsafe") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16_384:
            raise ValueError("third-party runtime approval receipt must be a regular mode-0600 file under 16 KiB")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(16_385)
        if len(content) > 16_384:
            raise ValueError("third-party runtime approval receipt must be a regular mode-0600 file under 16 KiB")
        return content
    finally:
        os.close(descriptor)


def read_wp5_runtime_approval(root: Path, target: dict, state: Path, role_values: dict) -> dict:
    """Read a private Root review binding for the exact third-party runtime inputs."""
    path = root / WP5_APPROVAL_RELATIVE
    for parent in (root / ".generated", path.parent):
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("third-party runtime approval receipt directory is missing or unsafe")
    try:
        raw_receipt = _read_wp5_approval_bytes(path)
    except FileNotFoundError:
        raise ValueError("third-party runtime sync requires a private Root review receipt") from None
    except OSError:
        raise ValueError("third-party runtime approval receipt is missing or unsafe") from None

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate receipt field")
            result[key] = value
        return result

    try:
        receipt = json.loads(raw_receipt.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("third-party runtime approval receipt is malformed") from None
    if not isinstance(receipt, dict) or set(receipt) != WP5_APPROVAL_FIELDS:
        raise ValueError("third-party runtime approval receipt fields are malformed")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 \
        or receipt["scope"] != "third-party-runtime" or receipt["approved"] is not True:
        raise ValueError("third-party runtime approval receipt scope is invalid")
    digests = {
        "target_sha256": canonical_sha256(target),
        "state_sha256": file_sha256(state),
        "role_inputs_sha256": canonical_sha256(role_values),
    }
    for field, expected in digests.items():
        value = receipt[field]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None or value != expected:
            raise ValueError("third-party runtime approval does not match current target, state, or role inputs")
    if not isinstance(receipt["diff_sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", receipt["diff_sha256"]) is None:
        raise ValueError("third-party runtime approval diff digest is malformed")
    operations = receipt["operations"]
    if not isinstance(receipt["summary"], dict) or set(receipt["summary"]) != set(WP5_EXPECTED_SUMMARY) \
        or any(type(value) is not int for value in receipt["summary"].values()) \
        or receipt["summary"] != WP5_EXPECTED_SUMMARY \
        or not isinstance(operations, dict) or set(operations) != {"creating", "updating", "deleting"}:
        raise ValueError("third-party runtime approval is not bound to the reviewed additive 11/0/0 change")
    if any(not isinstance(operations[name], list) for name in ("creating", "updating", "deleting")) \
        or operations["updating"] or operations["deleting"] or len(operations["creating"]) != 11:
        raise ValueError("third-party runtime approval operation identities are malformed")
    if any(
        not isinstance(entry, dict) or set(entry) != {"kind", "name"}
        or not isinstance(entry["kind"], str)
        or entry["kind"] not in {"service", "route", "plugin"}
        or not isinstance(entry["name"], str) or not entry["name"] or len(entry["name"]) > 256
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in entry["name"])
        for entry in operations["creating"]
    ) or Counter(entry["kind"] for entry in operations["creating"]) != WP5_EXPECTED_CREATE_KINDS:
        raise ValueError("third-party runtime approval operation identities are malformed")
    canonical_operations = {
        operation: sorted(entries, key=lambda entry: (entry["kind"], entry["name"]))
        for operation, entries in operations.items()
    }
    if operations != canonical_operations:
        raise ValueError("third-party runtime approval operation identities are not canonical")
    if len({(entry["kind"], entry["name"]) for entry in operations["creating"]}) != 11:
        raise ValueError("third-party runtime approval contains duplicate operation identities")
    if {(entry["kind"], entry["name"]) for entry in operations["creating"]} != WP5_EXPECTED_CREATE_IDENTITIES:
        raise ValueError("third-party runtime approval identities differ from the fixed additive scope")
    return receipt


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
    gateway: str = "api",
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
            label = "API runtime migration" if gateway == "api" else "third-party runtime"
            raise ValueError(
                f"{label} sync timed out; outcome is unknown; "
                "inspect current state before any retry"
            ) from None
        if purpose == "migration pre-sync diff":
            raise ValueError("API runtime migration diff timed out; sync was not attempted") from None
        raise ValueError(f"decK {mode} timed out; no raw subprocess output was retained") from None
    except OSError:
        if stage == "runtime" and mode == "sync":
            label = "API runtime migration" if gateway == "api" else "third-party runtime"
            raise ValueError(
                f"{label} sync transport failed; outcome is unknown; "
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
    elif args.stage == "runtime":
        state_relative = RUNTIME_FILES[args.gateway]
    else:
        raise ValueError("fixed decK state is unavailable for the selected gateway and stage")
    state = root / state_relative
    if not state.is_file():
        raise ValueError(f"fixed {args.stage} state is unavailable")

    if args.stage == "runtime" and args.gateway == "third-party" and args.mode == "sync":
        if os.environ.get("WP5_THIRD_PARTY_RUNTIME_APPROVED") != "YES":
            raise ValueError(
                "third-party runtime sync requires WP5_THIRD_PARTY_RUNTIME_APPROVED=YES after Root review"
            )

    if (
        args.stage == "runtime"
        and args.mode == "sync"
        and args.gateway == "api"
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
    wp5_receipt = None
    if args.stage == "runtime" and args.mode == "sync" and args.gateway == "api":
        # Local approval binding is checked before loading the Konnect token or contacting Konnect.
        target = info["target"]
        migration_receipt = read_migration_approval(root, target["control_plane_id"], role_values)
    elif args.stage == "runtime" and args.mode == "sync" and args.gateway == "third-party":
        wp5_receipt = read_wp5_runtime_approval(root, info["target"], state, role_values)

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
    third_party_runtime = args.stage == "runtime" and args.gateway == "third-party"
    if third_party_runtime:
        common_command.extend(["--parallelism", "1"])
    wp5_runtime_sync = args.stage == "runtime" and args.mode == "sync" and args.gateway == "third-party"
    if wp5_runtime_sync:
        diff_command = [*common_command]
        diff_command[2] = "diff"
        diff_command.extend(["--json-output", "--no-color", "--no-mask-deck-env-vars-value"])
        diff_result = run_deck_subprocess(
            diff_command,
            root=root,
            environment=environment,
            stage=args.stage,
            mode="diff",
            purpose="third-party pre-sync diff",
            gateway=args.gateway,
        )
        if diff_result.returncode != 0 or diff_result.stderr.strip():
            raise ValueError("third-party runtime pre-sync diff failed; sync was not attempted")
        current_operations, current_diff_sha256 = parse_sanitized_runtime_diff(
            diff_result.stdout, sensitive_values
        )
        validate_wp5_additive_scope(current_operations)
        if (
            wp5_receipt is None
            or current_diff_sha256 != wp5_receipt["diff_sha256"]
            or current_operations["summary"] != wp5_receipt["summary"]
            or current_operations["operations"] != wp5_receipt["operations"]
        ):
            raise ValueError("third-party runtime diff changed after Root review; sync was not attempted")
        fresh_info = local_manifest(root, args.gateway, args.stage, args.mode)
        fresh_role_values = validate_role_values(
            args.gateway,
            read_private_role_file(role_file, require_private_mode=True),
        )
        if (
            state.is_symlink()
            or file_sha256(state) != wp5_receipt["state_sha256"]
            or canonical_sha256(fresh_role_values) != wp5_receipt["role_inputs_sha256"]
            or canonical_sha256(fresh_info["target"]) != wp5_receipt["target_sha256"]
        ):
            raise ValueError("third-party runtime target, state, or role inputs changed after review; sync was not attempted")
    elif args.stage == "runtime" and args.mode == "sync":
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
            gateway=args.gateway,
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
        if third_party_runtime:
            command.append("--no-mask-deck-env-vars-value")
    result = run_deck_subprocess(
        command,
        root=root,
        environment=environment,
        stage=args.stage,
        mode=args.mode,
        purpose="requested command",
        gateway=args.gateway,
    )
    safe_stdout = sanitize_output(result.stdout, sensitive_values)
    safe_stderr = sanitize_output(result.stderr, sensitive_values)
    if args.stage == "runtime" and args.mode == "diff":
        if result.returncode != 0:
            raise ValueError(f"{args.gateway} runtime diff failed")
        if safe_stderr.strip():
            raise ValueError(f"{args.gateway} runtime diff returned unexpected diagnostics")
        if args.gateway == "api":
            operations, digest = parse_deck_diff_report(result.stdout)
            print(json.dumps(operations, sort_keys=True, separators=(",", ":")))
            print(f"WP3_MIGRATION_DIFF_SHA256={digest}")
            print(f"WP3_API_RUNTIME_STATE_SHA256={file_sha256(state)}")
            print(f"WP3_API_RUNTIME_ROLE_INPUTS_SHA256={role_inputs_sha256}")
        else:
            operations, digest = parse_sanitized_runtime_diff(result.stdout, sensitive_values)
            print(json.dumps(operations, sort_keys=True, separators=(",", ":")))
            print(f"WP5_THIRD_PARTY_RUNTIME_STATE_SHA256={file_sha256(state)}")
            print(f"WP5_THIRD_PARTY_RUNTIME_ROLE_INPUTS_SHA256={role_inputs_sha256}")
            print(f"WP5_THIRD_PARTY_RUNTIME_TARGET_SHA256={canonical_sha256(target)}")
            print(f"WP5_THIRD_PARTY_RUNTIME_DIFF_SHA256={digest}")
    elif args.stage == "runtime" and args.mode == "sync" and result.returncode != 0:
        label = "API runtime migration" if args.gateway == "api" else "third-party runtime"
        raise ValueError(
            f"{label} sync exited nonzero; outcome is unknown; inspect current state before any retry"
        )
    elif wp5_runtime_sync:
        print("third-party runtime sync completed for the approved additive 11-entity scope; decK output withheld")
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
