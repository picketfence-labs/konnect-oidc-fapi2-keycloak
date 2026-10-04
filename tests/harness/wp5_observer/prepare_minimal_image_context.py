#!/usr/bin/env python3
"""Prepare a fresh, public-only context for the WP5 published-JAR image build."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[3]
PATCHER_PATH = ROOT / "tests/harness/wp5_observer/patch_keycloak_source.py"
HELPER_PATH = ROOT / "tests/harness/wp5_observer/observer/AsPeerObserver.java"
DOCKERFILE_PATH = ROOT / "tests/harness/wp5_observer/minimal_image/Dockerfile"
COMPILE_SCRIPT_PATH = ROOT / "tests/harness/wp5_observer/minimal_image/compile.sh"
PINNED_COMMIT = "aa9fe3fba0c6cd5770f19a49378c55f4378cf544"
RELEASE_ZIP_SHA256 = "a286e98b4296d4e75ee88d8527c7cd463b307caa022f088c9f22cffccc741fa1"
RUNTIME_ENTRY = "keycloak-26.7.4/lib/lib/main/org.keycloak.keycloak-quarkus-server-26.7.4.jar"
RUNTIME_SHA256 = "57bda3c01502dc553029f2e96f3b7b79e6e3aefcc33be13f67b0b29a3e693a2c"
PATCHED_HANDLER_SHA256 = "0bfae99bf4ad1e3c69eb3c687deb9f5e0cddf44324613cac7df35b752a6af6e2"
HELPER_SHA256 = "550291bd8411ca4fa18c03709e7be730532a67bfc244ef4f6ab35cf73d540141"
JAR_COUNT = 471
DEFAULT_SOURCE = Path("/private/tmp/wp5-published-artifact-analysis-20261004/keycloak-source")
DEFAULT_ZIP = Path("/private/tmp/wp5-published-artifact-analysis-20261004/keycloak-26.7.4.zip")
DEFAULT_OUTPUT = Path("/private/tmp/wp5-as-peer-minimal-image-build-20261004-v3")
HANDLER_RELATIVE = Path(
    "quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/"
    "TransactionalSessionHandler.java"
)
OBSERVER_RELATIVE = HANDLER_RELATIVE.parent / "AsPeerObserver.java"
SAFE_ARCHIVE_PATH = re.compile(r"[A-Za-z0-9_.+/-]+\Z")


class ContextError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_patcher():
    spec = importlib.util.spec_from_file_location("wp5_minimal_context_patcher", PATCHER_PATH)
    if spec is None or spec.loader is None:
        raise ContextError("patcher_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_release_zip(zip_path: Path) -> tuple[list[tuple[str, str]], bytes]:
    raw = zip_path.read_bytes()
    if digest(raw) != RELEASE_ZIP_SHA256:
        raise ContextError("release_zip_digest_mismatch")
    try:
        with zipfile.ZipFile(zip_path) as archive:
            rows: list[tuple[str, str]] = []
            seen: set[str] = set()
            runtime_bytes = b""
            for item in archive.infolist():
                if (not item.filename.endswith(".jar")
                        or not item.filename.startswith("keycloak-26.7.4/lib/")):
                    continue
                path = PurePosixPath(item.filename)
                if (not SAFE_ARCHIVE_PATH.fullmatch(item.filename)
                        or path.is_absolute() or ".." in path.parts
                        or not item.filename.startswith("keycloak-26.7.4/lib/")):
                    raise ContextError("release_jar_path_invalid")
                if item.filename in seen or (stat.S_IFMT(item.external_attr >> 16) == stat.S_IFLNK):
                    raise ContextError("release_jar_entry_invalid")
                seen.add(item.filename)
                body = archive.read(item)
                rows.append((item.filename.removeprefix("keycloak-26.7.4/lib/"), digest(body)))
                if item.filename == RUNTIME_ENTRY:
                    runtime_bytes = body
            if len(rows) != JAR_COUNT:
                raise ContextError("release_jar_count_mismatch")
            if not runtime_bytes or digest(runtime_bytes) != RUNTIME_SHA256:
                raise ContextError("runtime_jar_identity_mismatch")
            rows.sort()
            return rows, runtime_bytes
    except (OSError, zipfile.BadZipFile, RuntimeError):
        raise ContextError("release_zip_invalid") from None


def verify_source(source_tree: Path, helper_bytes: bytes) -> tuple[bytes, bytes]:
    try:
        head = subprocess.run(
            ["git", "-C", str(source_tree), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10, check=False,
        )
        dirty = subprocess.run(
            ["git", "-C", str(source_tree), "status", "--porcelain", "--untracked-files=all"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ContextError("source_git_check_failed") from None
    if head.returncode or dirty.returncode:
        raise ContextError("source_git_check_failed")
    if head.stdout.strip() != PINNED_COMMIT:
        raise ContextError("source_commit_mismatch")
    if dirty.stdout.strip():
        raise ContextError("source_tree_not_clean")
    try:
        handler = (source_tree / HANDLER_RELATIVE).read_bytes()
        observer_path = source_tree / OBSERVER_RELATIVE
        if observer_path.exists() or observer_path.is_symlink():
            raise ContextError("source_already_patched")
    except OSError:
        raise ContextError("source_file_unavailable") from None
    patcher = load_patcher()
    try:
        patched = patcher.patch_handler_bytes(handler)
    except patcher.PatchError as error:
        raise ContextError(error.reason) from None
    if digest(patched) != PATCHED_HANDLER_SHA256 or digest(helper_bytes) != HELPER_SHA256:
        raise ContextError("observer_source_digest_mismatch")
    return patched, helper_bytes


def write_context(output_root: Path, files: dict[str, bytes]) -> Path:
    expected_names = {
        "Dockerfile", "AsPeerObserver.java", "TransactionalSessionHandler.java",
        "published-classpath.sha256", "input.sha256", "context-manifest.json", "compile.sh",
    }
    if set(files) != expected_names:
        raise ContextError("context_allowlist_mismatch")
    try:
        output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chmod(output_root, 0o700)
        context = output_root / "context"
        context.mkdir(mode=0o700, exist_ok=False)
        for name, body in files.items():
            path = context / name
            with path.open("xb") as stream:
                os.chmod(path, 0o600)
                stream.write(body)
        return context
    except FileExistsError:
        raise ContextError("output_path_already_exists") from None
    except OSError:
        raise ContextError("context_write_failed") from None


def prepare(source_tree: Path, zip_path: Path, output_root: Path) -> dict[str, object]:
    rows, runtime_bytes = inspect_release_zip(zip_path)
    helper = HELPER_PATH.read_bytes()
    patched, helper = verify_source(source_tree, helper)
    classpath = "".join(f"{sha}  {name}\n" for name, sha in rows).encode("ascii")
    input_hashes = {
        "AsPeerObserver.java": digest(helper),
        "TransactionalSessionHandler.java": digest(patched),
        "compile.sh": digest(COMPILE_SCRIPT_PATH.read_bytes()),
        "published-classpath.sha256": digest(classpath),
        "runtime_jar_sha256": digest(runtime_bytes),
        "release_zip_sha256": RELEASE_ZIP_SHA256,
        "source_commit": PINNED_COMMIT,
    }
    context_manifest = json.dumps(
        {"format": 1, "source_commit": PINNED_COMMIT, "release_zip_sha256": RELEASE_ZIP_SHA256,
         "runtime_jar_sha256": RUNTIME_SHA256, "jar_count": len(rows), "inputs": input_hashes},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    input_hashes["context-manifest.json"] = digest(context_manifest)
    input_manifest = "".join(
        f"{input_hashes[name]}  {name}\n"
        for name in sorted(("AsPeerObserver.java", "TransactionalSessionHandler.java", "compile.sh",
                            "published-classpath.sha256", "context-manifest.json"))
    ).encode("ascii")
    files = {
        "Dockerfile": DOCKERFILE_PATH.read_bytes(),
        "AsPeerObserver.java": helper,
        "TransactionalSessionHandler.java": patched,
        "published-classpath.sha256": classpath,
        "input.sha256": input_manifest,
        "context-manifest.json": context_manifest,
        "compile.sh": COMPILE_SCRIPT_PATH.read_bytes(),
    }
    context = write_context(output_root, files)
    return {
        "result": "prepared", "context": str(context), "source_commit": PINNED_COMMIT,
        "release_zip_sha256": RELEASE_ZIP_SHA256, "runtime_jar_sha256": RUNTIME_SHA256,
        "published_jar_count": len(rows), "context_file_count": len(files),
        "context_manifest_sha256": digest(context_manifest),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-tree", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--release-zip", type=Path, default=DEFAULT_ZIP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        record = prepare(args.source_tree, args.release_zip, args.output)
    except ContextError as error:
        print(json.dumps({"result": "rejected", "reason": error.code}, sort_keys=True))
        return 1
    except OSError:
        print(json.dumps({"result": "rejected", "reason": "input_io_failed"}, sort_keys=True))
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
