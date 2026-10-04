#!/usr/bin/env python3
"""Apply the bounded WP5 observer hook to one clean, pinned Keycloak checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PINNED_COMMIT = "aa9fe3fba0c6cd5770f19a49378c55f4378cf544"
HANDLER_RELATIVE = Path(
    "quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/"
    "TransactionalSessionHandler.java"
)
OBSERVER_RELATIVE = HANDLER_RELATIVE.parent / "AsPeerObserver.java"
PINNED_HANDLER_SHA256 = "9c751a303a52984a64a0cac5ba4dd07c2f639006608c2386df68f4ecba6d5e9d"
ANCHOR = b"        KeycloakSessionUtil.setKeycloakSession(currentSession);\n"
CALL = ANCHOR + b"        AsPeerObserver.observe(currentSession);\n"
MARKER = b"AsPeerObserver.observe(currentSession);"


class PatchError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_handler_bytes(source: bytes, expected_sha256: str = PINNED_HANDLER_SHA256) -> bytes:
    """Return only the anchored hook insertion, after exact source identity checks."""
    if sha256(source) != expected_sha256:
        raise PatchError("handler_source_digest_mismatch")
    if MARKER in source:
        raise PatchError("handler_already_patched")
    if source.count(ANCHOR) != 1:
        raise PatchError("handler_anchor_count_mismatch")
    return source.replace(ANCHOR, CALL, 1)


def _git(source_tree: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_tree), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise PatchError("source_git_check_failed")
    return result.stdout.strip()


def apply_source_tree(source_tree: Path, helper_source: Path | None = None) -> dict[str, str]:
    source_tree = source_tree.resolve(strict=True)
    if _git(source_tree, "rev-parse", "HEAD") != PINNED_COMMIT:
        raise PatchError("source_commit_mismatch")
    if _git(source_tree, "status", "--porcelain", "--untracked-files=all"):
        raise PatchError("source_tree_not_clean")

    handler_path = source_tree / HANDLER_RELATIVE
    observer_path = source_tree / OBSERVER_RELATIVE
    if observer_path.exists() or observer_path.is_symlink():
        raise PatchError("observer_path_already_exists")

    original = handler_path.read_bytes()
    patched = patch_handler_bytes(original, PINNED_HANDLER_SHA256)
    source_file = helper_source or (ROOT / "tests/harness/wp5_observer/observer/AsPeerObserver.java")
    helper_bytes = source_file.read_bytes()
    if not helper_bytes or b"class AsPeerObserver" not in helper_bytes:
        raise PatchError("observer_helper_invalid")

    # Create the helper exclusively and replace the one pinned handler only after every preflight passed.
    temporary_handler = handler_path.with_name(handler_path.name + ".wp5-tmp")
    if temporary_handler.exists() or temporary_handler.is_symlink():
        raise PatchError("temporary_handler_path_exists")
    with observer_path.open("xb") as helper_output:
        helper_output.write(helper_bytes)
    try:
        with temporary_handler.open("xb") as handler_output:
            handler_output.write(patched)
        temporary_handler.replace(handler_path)
    except OSError:
        observer_path.unlink(missing_ok=True)
        temporary_handler.unlink(missing_ok=True)
        raise PatchError("handler_write_failed") from None

    return {
        "source_commit": PINNED_COMMIT,
        "handler_before_sha256": sha256(original),
        "handler_after_sha256": sha256(patched),
        "observer_sha256": sha256(helper_bytes),
        "changed_file_count": "2",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_tree", type=Path)
    args = parser.parse_args()
    try:
        result = apply_source_tree(args.source_tree)
    except (OSError, PatchError) as error:
        reason = error.reason if isinstance(error, PatchError) else "source_io_failed"
        print(json.dumps({"result": "rejected", "reason": reason}, sort_keys=True))
        return 1
    print(json.dumps({"result": "patched", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
