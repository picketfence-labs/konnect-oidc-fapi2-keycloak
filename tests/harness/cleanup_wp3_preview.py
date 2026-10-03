#!/usr/bin/env python3
"""Remove only the dedicated WP3 Compose project and its fresh fixture secrets."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from prepare_wp3_preview import (
    COMPOSE_FILE,
    IMAGES,
    PREVIEW,
    PROJECT,
    VOLUME,
    PreviewError,
    inspect_images,
    load_runtime_role_values,
    require_isolated_project_absent,
    require_ports_free,
    validate_runtime_receipt,
    verify_preparation_receipt,
)


ROOT = Path(__file__).resolve().parents[2]
RECEIPT_NAMES = (
    "wp3-preparation-receipt.json",
    "wp3-runtime-receipt.json",
)


def compose_command(args: list[str], env: dict[str, str]):
    command = [
        "docker", "compose", "--env-file", "/dev/null",
        "--project-directory", str(ROOT), "--project-name", PROJECT,
        "-f", str(COMPOSE_FILE), *args,
    ]
    try:
        return subprocess.run(command, cwd=ROOT, env=env, check=False, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise PreviewError("the dedicated WP3 Compose cleanup command failed") from None


def project_container_ids() -> list[str]:
    result = subprocess.run(
        ["docker", "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"],
        cwd=ROOT, check=False, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise PreviewError("could not inspect the dedicated WP3 Compose project")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def require_cleanup_ports_free(*, timeout_seconds: float = 8.0, poll_interval_seconds: float = 0.25) -> None:
    """Wait only for expected owned-port release races after Compose teardown."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            require_ports_free()
            return
        except PreviewError as error:
            message = str(error)
            if not (message.startswith("required isolated preview port ") and message.endswith(" is already in use")):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PreviewError("dedicated WP3 ports remained occupied after bounded cleanup wait") from None
            time.sleep(min(poll_interval_seconds, remaining))


def persist_sanitized_receipts() -> None:
    evidence = ROOT / ".generated/evidence"
    if (ROOT / ".generated").is_symlink() or evidence.is_symlink():
        raise PreviewError("refusing to preserve WP3 evidence through a symlink")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(evidence, 0o700)
    preview_evidence = PREVIEW / "evidence"
    for source_name in RECEIPT_NAMES:
        source = preview_evidence / source_name
        if not os.path.lexists(source):
            continue
        if source.is_symlink() or not source.is_file() or stat.S_IMODE(source.stat().st_mode) != 0o600:
            raise PreviewError("WP3 sanitized receipt is absent or unsafe")
        payload = json.loads(source.read_text(encoding="utf-8"))
        if source_name == "wp3-runtime-receipt.json":
            validate_runtime_receipt(payload)
        target = evidence / f"{source.stem}-{time.time_ns()}.json"
        with target.open("x", encoding="utf-8") as output:
            json.dump(payload, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
        os.chmod(target, 0o600)


def persist_cleanup_status(status: str) -> None:
    allowed = {"sanitized_receipt_rejected", "private_fixture_removal_failed", "ports_remained_occupied"}
    if status not in allowed:
        raise PreviewError("WP3 cleanup status was outside its fixed enum")
    evidence = ROOT / ".generated/evidence"
    if (ROOT / ".generated").is_symlink() or evidence.is_symlink():
        raise PreviewError("refusing to preserve WP3 cleanup status through a symlink")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(evidence, 0o700)
    target = evidence / f"wp3-cleanup-status-{time.time_ns()}.json"
    payload = {
        "schema_version": 1,
        "scope": "wp3-isolated-fixture-cleanup",
        "status": status,
    }
    with target.open("x", encoding="utf-8") as output:
        json.dump(payload, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    os.chmod(target, 0o600)


def cleanup() -> None:
    if PREVIEW.is_symlink() or not PREVIEW.is_dir() or stat.S_IMODE(PREVIEW.stat().st_mode) != 0o700:
        raise PreviewError("WP3 private fixture is absent or unsafe")
    verify_preparation_receipt()
    role_values = load_runtime_role_values()
    if not os.environ.get("KONG_LICENSE_DATA"):
        raise PreviewError("Kong license is absent from the current process environment")
    observed = inspect_images()
    if observed != verify_preparation_receipt()["images"]:
        raise PreviewError("WP3 fixture image metadata changed")

    env = os.environ.copy()
    env["API_INTROSPECTION_KEY"] = role_values["API_INTROSPECTION_KEY"]
    env["API_UPSTREAM_KEY"] = role_values["API_UPSTREAM_KEY"]
    containers = project_container_ids()
    if containers:
        inspect = subprocess.run(
            ["docker", "inspect", *containers], cwd=ROOT, check=False,
            capture_output=True, text=True, timeout=30,
        )
        if inspect.returncode != 0:
            raise PreviewError("could not validate WP3 container ownership before cleanup")
        try:
            details = json.loads(inspect.stdout)
        except json.JSONDecodeError:
            raise PreviewError("WP3 container ownership metadata is malformed") from None
        expected_services = {"keycloak", "kong-api", "pop-verifier"}
        for container in details:
            labels = container.get("Config", {}).get("Labels", {})
            service = labels.get("com.docker.compose.service")
            project = labels.get("com.docker.compose.project")
            image = container.get("Config", {}).get("Image")
            if project != PROJECT or service not in expected_services or image != IMAGES[service][0]:
                raise PreviewError("refusing to clean an unexpected container in the WP3 project")
    result = compose_command(["down", "--volumes", "--remove-orphans"], env)
    if result.returncode != 0:
        raise PreviewError("dedicated WP3 Compose cleanup failed")

    require_isolated_project_absent()
    volume_result = subprocess.run(
        ["docker", "volume", "ls", "--quiet", "--filter", f"name={VOLUME}"],
        cwd=ROOT, check=False, capture_output=True, text=True, timeout=30,
    )
    if volume_result.returncode != 0 or VOLUME in {line.strip() for line in volume_result.stdout.splitlines()}:
        raise PreviewError("dedicated WP3 Compose volume remains after cleanup")
    receipt_rejected = False
    try:
        persist_sanitized_receipts()
    except (PreviewError, OSError, json.JSONDecodeError, KeyError, TypeError):
        receipt_rejected = True
    try:
        shutil.rmtree(PREVIEW)
    except OSError:
        try:
            persist_cleanup_status("private_fixture_removal_failed")
        except Exception:
            pass
        raise PreviewError("dedicated containers were removed but private fixture removal needs recovery") from None
    if PREVIEW.exists() or PREVIEW.is_symlink():
        raise PreviewError("WP3 private fixture cleanup did not complete")
    try:
        require_cleanup_ports_free()
    except PreviewError:
        try:
            persist_cleanup_status("ports_remained_occupied")
        except Exception:
            pass
        raise
    if receipt_rejected:
        persist_cleanup_status("sanitized_receipt_rejected")
        raise PreviewError("private fixture removed; unsafe sanitized receipt was not preserved")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-cleanup-isolated-wp3-runtime", action="store_true")
    args = parser.parse_args()
    if not args.allow_cleanup_isolated_wp3_runtime:
        parser.error("removing the WP3 Compose project and fixture keys requires cleanup approval")
    try:
        cleanup()
    except (PreviewError, OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"WP3 cleanup stopped safely: {error}", file=sys.stderr)
        return 1
    print("Removed only the dedicated WP3 containers, project network, and private fixture keys.")
    print("Sanitized receipts remain in .generated/evidence; no unrelated project was targeted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
