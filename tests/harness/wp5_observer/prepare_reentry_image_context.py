#!/usr/bin/env python3
"""Prepare a fresh public-only Keycloak context with the opt-in re-entry probe."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BASE_PREP_PATH = ROOT / "tests/harness/wp5_observer/prepare_minimal_image_context.py"
HELPER_PATH = ROOT / "tests/harness/wp5_observer/observer/AsPeerObserver.java"
DEFAULT_OUTPUT = Path("/private/tmp/wp5-as-peer-minimal-image-build-20261004-v4-reentry")
DEFAULT_SOURCE = Path("/private/tmp/wp5-published-artifact-analysis-20261004/keycloak-source")
DEFAULT_ZIP = Path("/private/tmp/wp5-published-artifact-analysis-20261004/keycloak-26.7.4.zip")
VARIANT = "wp5-reentry-probe-v1"


class ContextError(ValueError):
    """A safe context preparation error code."""

    _CODES = frozenset({"base_preparer_unavailable", "context_write_failed"})

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "context_write_failed"
        self.code = code
        super().__init__(code)


def _load(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ContextError("base_preparer_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare(source_tree: Path, zip_path: Path, output_root: Path) -> dict[str, object]:
    base = _load(BASE_PREP_PATH, "wp5_reentry_base_context")
    patcher = _load(
        ROOT / "tests/harness/wp5_observer/reentry_probe.py",
        "wp5_reentry_source_patcher",
    )
    rows, runtime_bytes = base.inspect_release_zip(zip_path)

    # Reuse v3's exact source, commit, dirty-tree, archive and runtime-JAR checks.
    original_helper = HELPER_PATH.read_bytes()
    patched_handler, checked_helper = base.verify_source(source_tree, original_helper)
    if checked_helper != original_helper:
        raise base.ContextError("observer_source_digest_mismatch")
    reentry_helper = patcher.patch_helper_bytes(original_helper)

    classpath = "".join(f"{sha}  {name}\n" for name, sha in rows).encode("ascii")
    input_hashes = {
        "AsPeerObserver.java": digest(reentry_helper),
        "TransactionalSessionHandler.java": digest(patched_handler),
        "compile.sh": digest(base.COMPILE_SCRIPT_PATH.read_bytes()),
        "published-classpath.sha256": digest(classpath),
        "runtime_jar_sha256": digest(runtime_bytes),
        "release_zip_sha256": base.RELEASE_ZIP_SHA256,
        "source_commit": base.PINNED_COMMIT,
        "v3_observer_sha256": digest(original_helper),
    }
    context_manifest = json.dumps(
        {
            "format": 1,
            "variant": VARIANT,
            "source_commit": base.PINNED_COMMIT,
            "release_zip_sha256": base.RELEASE_ZIP_SHA256,
            "runtime_jar_sha256": digest(runtime_bytes),
            "jar_count": len(rows),
            "class_count_expected": 2,
            "variant": VARIANT,
            "inputs": input_hashes,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"

    manifest_inputs = {
        "AsPeerObserver.java": digest(reentry_helper),
        "TransactionalSessionHandler.java": digest(patched_handler),
        "compile.sh": digest(base.COMPILE_SCRIPT_PATH.read_bytes()),
        "published-classpath.sha256": digest(classpath),
        "context-manifest.json": digest(context_manifest),
    }
    input_manifest = "".join(
        f"{manifest_inputs[name]}  {name}\n" for name in sorted(manifest_inputs)
    ).encode("ascii")

    files = {
        "Dockerfile": base.DOCKERFILE_PATH.read_bytes(),
        "AsPeerObserver.java": reentry_helper,
        "TransactionalSessionHandler.java": patched_handler,
        "published-classpath.sha256": classpath,
        "input.sha256": input_manifest,
        "context-manifest.json": context_manifest,
        "compile.sh": base.COMPILE_SCRIPT_PATH.read_bytes(),
    }
    context = base.write_context(output_root, files)
    return {
        "result": "prepared",
        "variant": VARIANT,
        "context": str(context),
        "source_commit": base.PINNED_COMMIT,
        "release_zip_sha256": base.RELEASE_ZIP_SHA256,
        "runtime_jar_sha256": digest(runtime_bytes),
        "published_jar_count": len(rows),
        "context_file_count": len(files),
        "expected_class_count": 2,
        "v3_observer_sha256": digest(original_helper),
        "reentry_observer_sha256": digest(reentry_helper),
        "patched_handler_sha256": digest(patched_handler),
        "context_manifest_sha256": digest(context_manifest),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-tree", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--release-zip", type=Path, default=DEFAULT_ZIP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        record = prepare(args.source_tree, args.release_zip, args.output)
    except ContextError as error:
        record = {"result": "rejected", "reason": error.code}
        print(json.dumps(record, sort_keys=True))
        return 1
    except OSError:
        print(json.dumps({"result": "rejected", "reason": "input_io_failed"}, sort_keys=True))
        return 1
    except Exception as error:
        code = getattr(error, "code", None)
        reason = getattr(error, "reason", None)
        safe_reasons = {
            "input_io_failed", "source_commit_mismatch", "source_tree_not_clean",
            "observer_source_digest_mismatch", "source_git_check_failed",
            "release_zip_digest_mismatch", "runtime_jar_identity_mismatch",
            "release_jar_path_invalid", "release_jar_entry_invalid",
            "release_jar_count_mismatch", "release_zip_invalid",
            "output_path_already_exists", "context_allowlist_mismatch",
            "context_write_failed", "source_digest_mismatch", "anchor_mismatch",
            "handler_source_digest_mismatch", "handler_already_patched",
            "handler_anchor_count_mismatch", "source_git_check_failed",
            "source_commit_mismatch", "source_tree_not_clean", "source_already_patched",
            "source_file_unavailable", "patcher_unavailable",
        }
        candidate = code if code in safe_reasons else reason
        reason = candidate if candidate in safe_reasons else "context_preparation_failed"
        print(json.dumps({"result": "rejected", "reason": reason}, sort_keys=True))
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
