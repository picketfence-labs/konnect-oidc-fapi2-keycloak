#!/usr/bin/env python3
"""Prepare and run one isolated proof of the Keycloak handler re-entry probe."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import sys
import time
from pathlib import Path
from typing import Any

HARNESS = Path(__file__).resolve().parent
if str(HARNESS) not in sys.path:
    sys.path.insert(0, str(HARNESS))

import observation_parser  # noqa: E402
import reentry_parser  # noqa: E402
import runtime_fixture as base_runtime  # noqa: E402


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = Path("/private/tmp/wp5-as-reentry-probe-20261004-v4-r4")
PREP_RECEIPT = Path("/private/tmp/wp5-as-reentry-probe-prep-receipt-20261004-v4-r4.json")
RUN_INTENT = Path("/private/tmp/wp5-as-reentry-probe-run-intent-20261004-v4-r4.json")
RUN_ATTEMPT = Path("/private/tmp/wp5-as-reentry-probe-run-attempt-20261004-v4-r4.json")
RUN_RECEIPT = Path("/private/tmp/wp5-as-reentry-probe-run-receipt-20261004-v4-r4.json")
COMPOSE_FILE = ROOT / "tests/harness/docker-compose.wp5-observer-reentry.yml"
IMAGE_TAG = "wp5-as-peer-observer:20261004-minimal-v4-reentry"
IMAGE_ID = "sha256:82080852b6ce7b81b4b6acf3af2890bc605b6d1350ac2aa7a21612733ff6ee36"
RUNTIME_JAR_SHA256 = "5fee36722d2e1c6d3bfa8a3e07e92bf033959c0f444faef9874e0146c065d814"
IMAGE_REVIEW = ROOT / ".generated/evidence/wp5-root-reentry-built-image-review-1791088656415961000.json"
IMAGE_REVIEW_SHA256 = "9949c9c5a984b8c2245280bd657985b859265ae838cffb99bfd6e2371602cf13"
OWNER = "wp5-luna"
IMAGE_PHASE = "observer-image-build-only"
RUNTIME_PHASE = "observer-reentry-runtime"
PROJECT = "wp5-as-reentry-probe"
VOLUME = "wp5-as-reentry-probe-data"
NETWORK = "wp5-as-reentry-probe_default"
PORT = 19443

MAX_LOG = 32 * 1024 * 1024
MAX_COMMAND = 60
MAX_REQUEST = 10
MAX_STARTUP = 180
MAX_RUNTIME = 12 * 60
CLEANUP_RESERVE = 120
COMMAND_OUTPUT_CAP = 1024 * 1024

PAR_PATH = "realms/fapi-demo/protocol/openid-connect/ext/par/request"
READY_PATH = "realms/fapi-demo/wp5-reentry-readiness-probe"
PAR_BODY = (
    b"client_id=wp5-reentry-probe-no-client"
    b"&response_type=code"
    b"&redirect_uri=https%3A%2F%2Fexample.invalid%2Fcallback"
    b"&scope=openid"
    b"&code_challenge=ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    b"&code_challenge_method=S256"
)
ID_RE = re.compile(r"[0-9a-f]{32}\Z")
THUMB_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
MODES: tuple[dict[str, Any], ...] = (
    {"name": "observer_on_probe_off", "env": "mode-observer-on-probe-off.env",
     "observer": True, "probe": False},
    {"name": "observer_on_probe_on", "env": "mode-observer-on-probe-on.env",
     "observer": True, "probe": True},
    {"name": "observer_off_probe_on", "env": "mode-observer-off-probe-on.env",
     "observer": False, "probe": True},
)
EXPECTED_DIRS = {"ca", "tls", "clients", "realm", "env"}
EXPECTED_FILES = {
    "ca/ca.crt",
    "tls/server.crt",
    "tls/server.key",
    "clients/route-b.crt",
    "clients/route-b.key",
    "realm/fapi-demo-realm.json",
    "env/mode-observer-on-probe-off.env",
    "env/mode-observer-on-probe-on.env",
    "env/mode-observer-off-probe-on.env",
}


class ReentryFixtureError(Exception):
    """A safe fixed-category failure; raw command, TLS, and HTTP text is never echoed."""

    CODES = frozenset({
        "cryptography_unavailable", "fixture_path_exists", "receipt_path_exists",
        "fixture_root_invalid", "fixture_inventory_invalid", "fixture_file_invalid",
        "fixture_directory_invalid", "fixture_manifest_mismatch", "prep_receipt_invalid",
        "certificate_invalid", "certificate_identity_invalid", "certificate_profile_invalid",
        "compose_input_invalid", "image_review_missing", "image_review_mismatch",
        "docker_unavailable", "docker_command_timeout", "docker_command_output_limit",
        "docker_command_failed", "docker_output_leak", "runtime_image_identity_mismatch",
        "runtime_project_resources_present", "runtime_resource_identity_mismatch",
        "runtime_port_unavailable", "run_intent_missing", "run_intent_mismatch",
        "runtime_approval_flag_required",
        "runtime_attempt_already_exists", "runtime_deadline_exceeded", "runtime_startup_timeout",
        "runtime_resource_missing", "runtime_cleanup_ownership_failed", "runtime_cleanup_failed",
        "runtime_fixture_cleanup_failed", "runtime_port_release_timeout", "tls_request_failed",
        "tls_server_verification_failed", "tls_peer_handshake_failed", "tls_socket_timeout",
        "tls_socket_failure", "http_request_failed", "http_response_leak", "http_status_invalid",
        "readiness_status_invalid", "request_identity_invalid", "observer_parse_failed",
        "reentry_parse_failed", "observer_mode_rows_invalid", "observer_mode_join_invalid",
        "observer_mode_unexpected_reentry", "observer_off_emitted_row", "probe_mode_rows_invalid",
        "probe_mode_evidence_invalid", "probe_off_emitted_row", "reentry_off_emitted_row",
        "http_status_not_par_negative", "mode_http_status_mismatch", "run_interrupted",
    })

    def __init__(self, code: str) -> None:
        self.code = code if code in self.CODES else "run_interrupted"
        super().__init__(self.code)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_text() -> str:
    return utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    try:
        base_runtime.write_exclusive(
            path, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"), 0o600
        )
    except FileExistsError:
        raise ReentryFixtureError("receipt_path_exists") from None
    except OSError:
        raise ReentryFixtureError("fixture_file_invalid") from None


def input_manifest() -> dict[str, Any]:
    sources = {
        "tests/harness/wp5_observer/reentry_runtime_fixture.py": Path(__file__).resolve(),
        "tests/harness/wp5_observer/runtime_fixture.py": HARNESS / "runtime_fixture.py",
        "tests/harness/wp5_observer/observation_parser.py": HARNESS / "observation_parser.py",
        "tests/harness/wp5_observer/reentry_parser.py": HARNESS / "reentry_parser.py",
        "tests/harness/docker-compose.wp5-observer-reentry.yml": COMPOSE_FILE,
    }
    if not all(path.is_file() and not path.is_symlink() for path in sources.values()):
        raise ReentryFixtureError("compose_input_invalid")
    hashes = {name: sha256(path.read_bytes()) for name, path in sorted(sources.items())}
    packed = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"files": hashes, "sha256": sha256(packed)}


def _private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ReentryFixtureError("fixture_directory_invalid")


def _file_manifest(root: Path) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for relative in sorted(EXPECTED_FILES):
        path = root / relative
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ReentryFixtureError("fixture_file_invalid")
        raw = path.read_bytes()
        files[relative] = {"mode": "0600", "size": len(raw), "sha256": sha256(raw)}
    actual: set[str] = set()
    for directory, subdirs, names in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in subdirs:
            entry = base / name
            if entry.is_symlink() or not entry.is_dir() or stat.S_IMODE(entry.stat().st_mode) != 0o700:
                raise ReentryFixtureError("fixture_directory_invalid")
        for name in names:
            entry = base / name
            if entry.is_symlink() or not entry.is_file():
                raise ReentryFixtureError("fixture_file_invalid")
            actual.add(entry.relative_to(root).as_posix())
    if actual != EXPECTED_FILES:
        raise ReentryFixtureError("fixture_inventory_invalid")
    return files


def verify_fixture_tree(root: Path = FIXTURE_ROOT) -> dict[str, dict[str, Any]]:
    if root != FIXTURE_ROOT and not root.is_absolute():
        raise ReentryFixtureError("fixture_root_invalid")
    if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ReentryFixtureError("fixture_root_invalid")
    actual_dirs: set[str] = set()
    for directory, subdirs, _names in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in subdirs:
            item = base / name
            _private_directory(item)
            actual_dirs.add(item.relative_to(root).as_posix())
    if actual_dirs != EXPECTED_DIRS:
        raise ReentryFixtureError("fixture_inventory_invalid")
    return _file_manifest(root)


def _fingerprint(cert: Any, hashes: Any) -> str:
    return base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).rstrip(b"=").decode("ascii")


def _check_certificate_material(root: Path, expected: dict[str, Any] | None = None) -> dict[str, str]:
    try:
        x509, hashes, serialization, ec, eku, name_oid = base_runtime._crypto()
        ca_cert = x509.load_pem_x509_certificate((root / "ca/ca.crt").read_bytes())
        server_cert = x509.load_pem_x509_certificate((root / "tls/server.crt").read_bytes())
        client_cert = x509.load_pem_x509_certificate((root / "clients/route-b.crt").read_bytes())
        server_key = serialization.load_pem_private_key((root / "tls/server.key").read_bytes(), password=None)
        client_key = serialization.load_pem_private_key((root / "clients/route-b.key").read_bytes(), password=None)
        ca_public = ca_cert.public_key()
        for cert in (server_cert, client_cert):
            if cert.issuer != ca_cert.subject:
                raise ReentryFixtureError("certificate_invalid")
            ca_public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != \
                    (server_key if cert is server_cert else client_key).public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                raise ReentryFixtureError("certificate_identity_invalid")
        now = utc_now()
        for cert in (ca_cert, server_cert, client_cert):
            before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=dt.timezone.utc))
            after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=dt.timezone.utc))
            if now < before or now > after:
                raise ReentryFixtureError("certificate_invalid")
        server_eku = server_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        client_eku = client_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if list(server_eku) != [eku.SERVER_AUTH] or list(client_eku) != [eku.CLIENT_AUTH]:
            raise ReentryFixtureError("certificate_profile_invalid")
        constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise ReentryFixtureError("certificate_profile_invalid")
        san = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if san.get_values_for_type(x509.DNSName) != ["localhost"] or \
                san.get_values_for_type(x509.IPAddress) != [ipaddress.ip_address("127.0.0.1")]:
            raise ReentryFixtureError("certificate_profile_invalid")
        result = {
            "ca_sha256": _fingerprint(ca_cert, hashes),
            "server_leaf_sha256": _fingerprint(server_cert, hashes),
            "route_b_leaf_sha256": _fingerprint(client_cert, hashes),
        }
        if expected is not None and result != expected:
            raise ReentryFixtureError("fixture_manifest_mismatch")
        return result
    except ReentryFixtureError:
        raise
    except Exception:
        raise ReentryFixtureError("certificate_invalid") from None


def _mode_env(root: Path, mode: dict[str, Any]) -> bytes:
    return (
        f"WP5_FIXTURE_ROOT={root}\n"
        f"WP5_OBSERVER_ENABLED={'true' if mode['observer'] else 'false'}\n"
        f"WP5_REENTRY_PROBE_ENABLED={'true' if mode['probe'] else 'false'}\n"
    ).encode("ascii")


def prepare_fixture(root: Path = FIXTURE_ROOT, receipt: Path | None = PREP_RECEIPT) -> dict[str, Any]:
    """Create only server TLS material, the host-side Route B client, realm, and mode env files."""
    if root != FIXTURE_ROOT and not root.is_absolute():
        raise ReentryFixtureError("fixture_root_invalid")
    if root.exists() or root.is_symlink():
        raise ReentryFixtureError("fixture_path_exists")
    for path in (receipt, RUN_INTENT, RUN_ATTEMPT, RUN_RECEIPT):
        if path is not None and (path.exists() or path.is_symlink()):
            raise ReentryFixtureError("receipt_path_exists")
    try:
        x509, hashes, serialization, ec, eku, name_oid = base_runtime._crypto()
        now = utc_now().replace(tzinfo=None)
        root.mkdir(mode=0o700, parents=False)
        for directory in sorted(EXPECTED_DIRS):
            (root / directory).mkdir(mode=0o700)
        ca_key, ca_cert = base_runtime._make_ca("WP5 reentry isolated CA", x509, hashes, ec, name_oid, now)
        server_key, server_cert = base_runtime._make_leaf(
            "localhost", ca_key, ca_cert, x509, hashes, ec, name_oid, eku, now,
            server=True, dns_san=True, ip_san=True,
        )
        client_key, client_cert = base_runtime._make_leaf(
            "kong-fapi-pkj-mtls", ca_key, ca_cert, x509, hashes, ec, name_oid, eku, now,
        )
        materials = {
            "ca/ca.crt": base_runtime._pem_cert(ca_cert, serialization),
            "tls/server.crt": base_runtime._pem_cert(server_cert, serialization),
            "tls/server.key": base_runtime._pem_key(server_key, serialization),
            "clients/route-b.crt": base_runtime._pem_cert(client_cert, serialization),
            "clients/route-b.key": base_runtime._pem_key(client_key, serialization),
            "realm/fapi-demo-realm.json": b'{"realm":"fapi-demo","enabled":true}\n',
        }
        for mode in MODES:
            materials[f"env/{mode['env']}"] = _mode_env(root, mode)
        for relative, raw in materials.items():
            base_runtime.write_exclusive(root / relative, raw, 0o600)
        files = verify_fixture_tree(root)
        pki = _check_certificate_material(root)
        receipt_data: dict[str, Any] = {
            "schema": "wp5-as-reentry-probe-prep-v1",
            "result": "prepared",
            "created_at": utc_text(),
            "fixture_root": str(root),
            "directory_mode": "0700",
            "file_mode": "0600",
            "file_count": len(files),
            "files": files,
            "pki_leaf_sha256": pki,
            "server_name": "localhost",
            "server_san": ["localhost", "127.0.0.1"],
            "route_b_client_eku": True,
            "server_eku": True,
            "trust_anchor_mounted_read_only": True,
            "route_b_certificate_and_key_host_only": True,
            "realm": "fapi-demo",
            "realm_accounts": 0,
            "realm_clients": 0,
            "oauth_credentials_created": 0,
            "mode_files": [mode["env"] for mode in MODES],
            "compose_sha256": sha256(COMPOSE_FILE.read_bytes()),
            "input_manifest": input_manifest(),
        }
        if receipt is not None:
            _write_exclusive(receipt, receipt_data)
        return receipt_data
    except ReentryFixtureError:
        raise
    except Exception:
        raise ReentryFixtureError("fixture_file_invalid") from None


def fixture_candidate_secrets(root: Path = FIXTURE_ROOT) -> tuple[bytes, ...]:
    candidates: list[bytes] = []
    for relative in sorted(EXPECTED_FILES):
        if relative.endswith((".crt", ".key")):
            candidates.append((root / relative).read_bytes())
    return tuple(candidates)


def verify_prep_receipt(root: Path = FIXTURE_ROOT) -> tuple[dict[str, Any], dict[str, Any]]:
    if PREP_RECEIPT.is_symlink() or not PREP_RECEIPT.is_file() or stat.S_IMODE(PREP_RECEIPT.stat().st_mode) != 0o600:
        raise ReentryFixtureError("prep_receipt_invalid")
    try:
        prep = json.loads(PREP_RECEIPT.read_text(encoding="utf-8"))
    except Exception:
        raise ReentryFixtureError("prep_receipt_invalid") from None
    files = verify_fixture_tree(root)
    if prep.get("schema") != "wp5-as-reentry-probe-prep-v1" or prep.get("fixture_root") != str(root):
        raise ReentryFixtureError("prep_receipt_invalid")
    if prep.get("files") != files or prep.get("input_manifest") != input_manifest():
        raise ReentryFixtureError("fixture_manifest_mismatch")
    pki = _check_certificate_material(root, prep.get("pki_leaf_sha256"))
    if prep.get("compose_sha256") != sha256(COMPOSE_FILE.read_bytes()):
        raise ReentryFixtureError("fixture_manifest_mismatch")
    return prep, pki


def _review_receipt() -> dict[str, Any]:
    if IMAGE_REVIEW.is_symlink() or not IMAGE_REVIEW.is_file() or IMAGE_REVIEW.stat().st_size > 64 * 1024:
        raise ReentryFixtureError("image_review_missing")
    raw = IMAGE_REVIEW.read_bytes()
    if sha256(raw) != IMAGE_REVIEW_SHA256:
        raise ReentryFixtureError("image_review_mismatch")
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ReentryFixtureError("image_review_mismatch") from None
    required = {
        "image_id": IMAGE_ID,
        "image_tag": IMAGE_TAG,
        "platform": "linux/arm64",
        "owner": OWNER,
        "phase": IMAGE_PHASE,
        "scope": "independent-minimal-built-image-review",
        "supported_jdk21_image_build": "pass: frozen compile script JDK21 guard and build exit zero",
        "changed_runtime_jar_sha256": RUNTIME_JAR_SHA256,
        "classpath_jar_count": 471,
        "unchanged_jars": 470,
        "runtime_existing_entries_changed": 1,
        "runtime_existing_entries_unchanged": 256,
        "runtime_new_entries": 1,
        "hook_count": 1,
        "hook_order_correct": True,
        "abi_identical": True,
        "runtime_acceptance": "not_run",
        "runtime_started": False,
    }
    if any(value.get(key) != expected for key, expected in required.items()):
        raise ReentryFixtureError("image_review_mismatch")
    if value.get("class_majors") != {
            "org/keycloak/quarkus/runtime/integration/resteasy/AsPeerObserver.class": 61,
            "org/keycloak/quarkus/runtime/integration/resteasy/TransactionalSessionHandler.class": 61,
    } or value.get("image_helper_raw_path_bytecode_and_50_controls") != "pass":
        raise ReentryFixtureError("image_review_mismatch")
    return {
        "path": str(IMAGE_REVIEW), "sha256": sha256(raw),
        "runtime_jar_sha256": RUNTIME_JAR_SHA256, "classpath_jar_count": 471,
        "unchanged_jars": 470, "changed_runtime_jar_entries": 1,
        "new_runtime_jar_entries": 1, "hook_count": 1, "hook_order_correct": True,
        "abi_identical": True, "offline_controls": "50_pass", "runtime_acceptance": "not_run",
    }


def _docker() -> str:
    path = shutil.which("docker", path=base_runtime._minimal_env()["PATH"])
    if not path:
        raise ReentryFixtureError("docker_unavailable")
    return path


def _bounded_output(argv: list[str], *, timeout: int, cap: int = COMMAND_OUTPUT_CAP,
                    candidates: tuple[bytes, ...] = (), deadline: float | None = None) -> tuple[bytes, dict[str, Any]]:
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReentryFixtureError("runtime_deadline_exceeded")
        timeout = min(timeout, max(1, int(remaining)))
    started = time.monotonic()
    try:
        result = base_runtime.bounded_command(argv, timeout=timeout, cap=cap, env=base_runtime._minimal_env())
    except Exception:
        raise ReentryFixtureError("docker_command_failed") from None
    elapsed = round(time.monotonic() - started, 3)
    if result.timed_out:
        raise ReentryFixtureError("docker_command_timeout")
    if result.truncated:
        raise ReentryFixtureError("docker_command_output_limit")
    if base_runtime.leak_scan(result.output, candidates):
        raise ReentryFixtureError("docker_output_leak")
    if result.code != 0:
        raise ReentryFixtureError("docker_command_failed")
    return result.output, {"exit_code": result.code, "timeout": False, "output_bytes": len(result.output),
                           "elapsed_seconds": elapsed}


def _docker_names(kind: str, *, filter_args: list[str], candidates: tuple[bytes, ...] = (),
                  deadline: float | None = None) -> list[str]:
    output, _meta = _bounded_output([_docker(), kind, "ls", *filter_args, "--format", "{{.Name}}"],
                                    timeout=MAX_COMMAND, candidates=candidates, deadline=deadline)
    return [line.strip() for line in output.decode("utf-8", errors="strict").splitlines() if line.strip()]


def _exact_image_preflight(candidates: tuple[bytes, ...] = (), *, deadline: float | None = None) -> dict[str, str]:
    format_arg = ('{{.Id}}|{{.Os}}|{{.Architecture}}|{{index .Config.Labels "org.picketfence.wp5.owner"}}|'
                  '{{index .Config.Labels "org.picketfence.wp5.phase"}}')
    output, _meta = _bounded_output([_docker(), "image", "inspect", "--format", format_arg, IMAGE_ID],
                                    timeout=MAX_COMMAND, candidates=candidates, deadline=deadline)
    fields = output.decode("ascii", errors="strict").strip().split("|")
    if fields != [IMAGE_ID, "linux", "arm64", OWNER, IMAGE_PHASE]:
        raise ReentryFixtureError("runtime_image_identity_mismatch")
    tag_output, _tag_meta = _bounded_output(
        [_docker(), "image", "inspect", "--format", "{{.Id}}", IMAGE_TAG], timeout=MAX_COMMAND,
        candidates=candidates, deadline=deadline,
    )
    if tag_output.decode("ascii", errors="strict").strip() != IMAGE_ID:
        raise ReentryFixtureError("runtime_image_identity_mismatch")
    return {"image_id": IMAGE_ID, "tag": IMAGE_TAG, "platform": "linux/arm64",
            "owner": OWNER, "phase": IMAGE_PHASE}


def _project_container_ids(candidates: tuple[bytes, ...] = (), *, deadline: float | None = None) -> list[str]:
    output, _meta = _bounded_output(
        [_docker(), "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}"],
        timeout=MAX_COMMAND, candidates=candidates, deadline=deadline,
    )
    return [line.strip() for line in output.decode("ascii", errors="strict").splitlines() if line.strip()]


def _resources_snapshot(candidates: tuple[bytes, ...] = (), *, deadline: float | None = None) -> dict[str, Any]:
    containers = _project_container_ids(candidates, deadline=deadline)
    volumes = _docker_names("volume", filter_args=["--filter", f"name={VOLUME}"], candidates=candidates, deadline=deadline)
    networks = _docker_names("network", filter_args=["--filter", f"name={NETWORK}"], candidates=candidates, deadline=deadline)
    project_volumes = _docker_names("volume", filter_args=["--filter", f"label=com.docker.compose.project={PROJECT}"], candidates=candidates, deadline=deadline)
    project_networks = _docker_names("network", filter_args=["--filter", f"label=com.docker.compose.project={PROJECT}"], candidates=candidates, deadline=deadline)
    return {
        "container_count": len(containers),
        "container_ids": containers,
        "volume_names": sorted(name for name in volumes if name == VOLUME),
        "network_names": sorted(name for name in networks if name == NETWORK),
        "project_volume_names": sorted(project_volumes),
        "project_network_names": sorted(project_networks),
    }


def _port_is_free() -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", PORT))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def preflight_absent(candidates: tuple[bytes, ...] = (), *, deadline: float | None = None) -> dict[str, Any]:
    image = _exact_image_preflight(candidates, deadline=deadline)
    resources = _resources_snapshot(candidates, deadline=deadline)
    if (resources["container_count"] or resources["volume_names"] or resources["network_names"] or
            resources["project_volume_names"] or resources["project_network_names"]):
        raise ReentryFixtureError("runtime_project_resources_present")
    if not _port_is_free():
        raise ReentryFixtureError("runtime_port_unavailable")
    return {"image": image, "resources_absent": True, "port_127_0_0_1_19443_free": True}


def _compose_prefix(env_file: Path) -> list[str]:
    return [
        _docker(), "compose", "--project-name", PROJECT, "--file", str(COMPOSE_FILE),
        "--env-file", str(env_file),
    ]


def _compose(env_file: Path, *args: str, timeout: int = MAX_COMMAND, cap: int = COMMAND_OUTPUT_CAP,
             candidates: tuple[bytes, ...] = (), deadline: float | None = None) -> tuple[bytes, dict[str, Any]]:
    return _bounded_output([*_compose_prefix(env_file), *args], timeout=timeout, cap=cap,
                            candidates=candidates, deadline=deadline)


def _inspect_resource(kind: str, name: str, *, candidates: tuple[bytes, ...] = (),
                      deadline: float | None = None) -> list[str] | None:
    fmt = '{{.Name}}|{{index .Labels "org.picketfence.wp5.owner"}}|{{index .Labels "org.picketfence.wp5.phase"}}|{{index .Labels "com.docker.compose.project"}}'
    output, meta = _bounded_output([_docker(), kind, "inspect", "--format", fmt, name], timeout=MAX_COMMAND,
                                   candidates=candidates, deadline=deadline)
    fields = output.decode("utf-8", errors="strict").strip().split("|")
    if len(fields) != 4:
        raise ReentryFixtureError("runtime_resource_identity_mismatch")
    return fields


def verify_owned_resources(*, allow_partial: bool = False,
                           candidates: tuple[bytes, ...] = (), deadline: float | None = None) -> dict[str, Any]:
    ids = _project_container_ids(candidates, deadline=deadline)
    if len(ids) > 1:
        raise ReentryFixtureError("runtime_resource_identity_mismatch")
    container_fields: list[str] | None = None
    if ids:
        fmt = ('{{.Id}}|{{index .Config.Labels "com.docker.compose.project"}}|'
               '{{index .Config.Labels "com.docker.compose.service"}}|'
               '{{index .Config.Labels "org.picketfence.wp5.owner"}}|'
               '{{index .Config.Labels "org.picketfence.wp5.phase"}}|{{.Image}}')
        output, _meta = _bounded_output([_docker(), "inspect", "--format", fmt, ids[0]],
                                        timeout=MAX_COMMAND, candidates=candidates, deadline=deadline)
        container_fields = output.decode("ascii", errors="strict").strip().split("|")
        if len(container_fields) != 6 or container_fields[1:] != [PROJECT, "keycloak", OWNER, RUNTIME_PHASE, IMAGE_ID]:
            raise ReentryFixtureError("runtime_resource_identity_mismatch")
    elif not allow_partial:
        raise ReentryFixtureError("runtime_resource_missing")

    names: dict[str, list[str]] = {}
    for kind, exact in (("volume", VOLUME), ("network", NETWORK)):
        found = _docker_names(kind, filter_args=["--filter", f"label=com.docker.compose.project={PROJECT}"],
                              candidates=candidates, deadline=deadline)
        names[kind] = sorted(found)
        if any(name != exact for name in names[kind]) or len(names[kind]) > 1:
            raise ReentryFixtureError("runtime_resource_identity_mismatch")
        if not names[kind]:
            names[kind] = _docker_names(kind, filter_args=["--filter", f"name={exact}"],
                                        candidates=candidates, deadline=deadline)
            names[kind] = sorted(name for name in names[kind] if name == exact)
        if len(names[kind]) > 1:
            raise ReentryFixtureError("runtime_resource_identity_mismatch")
        if names[kind]:
            fields = _inspect_resource(kind, exact, candidates=candidates, deadline=deadline)
            if fields != [exact, OWNER, RUNTIME_PHASE, PROJECT]:
                raise ReentryFixtureError("runtime_resource_identity_mismatch")
    if ids and (not names["volume"] or not names["network"]):
        raise ReentryFixtureError("runtime_resource_identity_mismatch")
    if not allow_partial and (not names["volume"] or not names["network"]):
        raise ReentryFixtureError("runtime_resource_identity_mismatch")
    return {"container_count": len(ids), "container_id": ids[0] if ids else None,
            "container_owned": bool(ids), "volume_names": names["volume"],
            "network_names": names["network"], "support_resources_owned": bool(names["volume"] and names["network"])}


def _resources_absent(candidates: tuple[bytes, ...] = (), *, deadline: float | None = None) -> bool:
    resources = _resources_snapshot(candidates, deadline=deadline)
    return not any((resources["container_count"], resources["volume_names"], resources["network_names"],
                    resources["project_volume_names"], resources["project_network_names"]))


def _compose_config_contract() -> dict[str, Any]:
    if not COMPOSE_FILE.is_file() or COMPOSE_FILE.is_symlink():
        raise ReentryFixtureError("compose_input_invalid")
    return {
        "compose_sha256": sha256(COMPOSE_FILE.read_bytes()),
        "service": "keycloak",
        "image_id": IMAGE_ID,
        "pull_policy": "never",
        "build": False,
        "command": ["start-dev", "--import-realm", "--https-port=8443"],
        "https_client_auth": "request",
        "observer_flag": "FAPI_DEMO_AS_PEER_OBSERVER",
        "reentry_flag": "FAPI_DEMO_AS_PEER_REENTRY_PROBE",
        "trust_anchor": "/opt/keycloak/conf/trust/ca.crt",
        "loopback_mapping": "127.0.0.1:19443:8443",
        "cpu_limit": 2,
        "memory_limit": "4g",
        "pids_limit": 256,
        "owner": OWNER,
        "phase": RUNTIME_PHASE,
        "named_volume": VOLUME,
        "network": NETWORK,
        "network_internal": False,
        "network_driver": "default_bridge",
        "read_only_mounts": ["realm/fapi-demo-realm.json", "tls/server.crt", "tls/server.key", "ca/ca.crt"],
        "route_b_client_mount": False,
    }


def create_run_intent() -> dict[str, Any]:
    if RUN_INTENT.exists() or RUN_INTENT.is_symlink() or RUN_ATTEMPT.exists() or RUN_RECEIPT.exists():
        raise ReentryFixtureError("receipt_path_exists")
    prep, pki = verify_prep_receipt()
    candidates = fixture_candidate_secrets()
    review = _review_receipt()
    preflight = preflight_absent(candidates)
    contract = _compose_config_contract()
    manifest = input_manifest()
    data: dict[str, Any] = {
        "schema": "wp5-as-reentry-probe-runtime-intent-v1",
        "status": "prepared_for_root_review",
        "created_at": utc_text(),
        "scope": "actual_same_par_request_handler_reentry_probe_only",
        "fixture_root": str(FIXTURE_ROOT),
        "prep_receipt": str(PREP_RECEIPT),
        "prep_receipt_sha256": sha256(PREP_RECEIPT.read_bytes()),
        "prep_file_count": prep["file_count"],
        "prep_files": prep["files"],
        "pki_leaf_sha256": pki,
        "image_review": review,
        "image": preflight["image"],
        "preflight": {"owner_resources_absent": preflight["resources_absent"],
                      "loopback_port_free": preflight["port_127_0_0_1_19443_free"]},
        "project": PROJECT,
        "named_volume": VOLUME,
        "network": NETWORK,
        "owner": OWNER,
        "phase": RUNTIME_PHASE,
        "compose": contract,
        "tls": {
            "server_name": "localhost", "server_certificate_trust_required": True,
            "client_auth_mode": "request", "client_certificate": "host-only Route B cert",
            "client_trust": "one fresh CA mounted read-only in Keycloak",
            "accepted_protocols": ["TLSv1.2", "TLSv1.3"], "certificate_keylog": False,
        },
        "request": {
            "mode_count": 3, "par_requests_per_mode": 1,
            "method": "POST", "path": "/" + PAR_PATH,
            "body_sha256": sha256(PAR_BODY), "body_bytes": len(PAR_BODY),
            "body_has_oauth_credentials": False,
            "accepted_statuses": [400, 401], "http_status_must_match_all_modes": True,
            "auxiliary_readiness_path": "/" + READY_PATH,
            "auxiliary_readiness_must_have_no_observer_or_probe_row": True,
        },
        "modes": [{"name": mode["name"], "observer": mode["observer"], "probe": mode["probe"]}
                  for mode in MODES],
        "acceptance": {
            "observer_on_probe_off": "one healthy PAR peer row; zero re-entry rows",
            "observer_on_probe_on": "one healthy PAR peer row; same-ID contiguous re-entry counts begin at 2 and reach at least 2",
            "observer_off_probe_on": "zero observer rows and zero re-entry rows",
            "strict_log_parsers": ["WP5_AS_PEER_OBS", "WP5_AS_PEER_REENTRY"],
            "oauth_success_or_stock_kong_claims": False,
            "new_listener_negative_coverage": False,
        },
        "limits": {
            "per_http_request_seconds": MAX_REQUEST,
            "per_mode_startup_seconds": MAX_STARTUP,
            "total_runtime_seconds": MAX_RUNTIME,
            "cleanup_reserve_seconds": CLEANUP_RESERVE,
            "log_bytes_per_container_max": MAX_LOG,
            "pull": False, "build": False,
            "normal_env_or_compose": False,
        },
        "input_manifest": manifest,
        "commands": {
            "compose_up": "docker compose --project-name wp5-as-reentry-probe --file tests/harness/docker-compose.wp5-observer-reentry.yml --env-file <fixed-mode-env> up -d --pull never --no-build --force-recreate keycloak",
            "compose_stop": "docker compose ... stop --timeout 10 keycloak",
            "compose_rm": "docker compose ... rm --stop --force keycloak",
            "compose_down_cleanup": "docker compose ... down --volumes --timeout 10",
        },
        "docker_started": False,
    }
    _write_exclusive(RUN_INTENT, data)
    return data


def _read_intent() -> tuple[dict[str, Any], str]:
    if RUN_INTENT.is_symlink() or not RUN_INTENT.is_file() or stat.S_IMODE(RUN_INTENT.stat().st_mode) != 0o600:
        raise ReentryFixtureError("run_intent_missing")
    raw = RUN_INTENT.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ReentryFixtureError("run_intent_mismatch") from None
    review = _review_receipt()
    prep, pki = verify_prep_receipt()
    if value.get("schema") != "wp5-as-reentry-probe-runtime-intent-v1" or \
            value.get("scope") != "actual_same_par_request_handler_reentry_probe_only" or \
            value.get("input_manifest") != input_manifest() or \
            value.get("prep_receipt_sha256") != sha256(PREP_RECEIPT.read_bytes()) or \
            value.get("prep_files") != prep.get("files") or value.get("pki_leaf_sha256") != pki or \
            value.get("image_review") != review or value.get("image") != {
                "image_id": IMAGE_ID, "tag": IMAGE_TAG, "platform": "linux/arm64",
                "owner": OWNER, "phase": IMAGE_PHASE,
            } or value.get("compose") != _compose_config_contract():
        raise ReentryFixtureError("run_intent_mismatch")
    return value, sha256(raw)


def tls_request(method: str, path: str, *, correlation: str | None, root: Path = FIXTURE_ROOT,
                deadline: float | None = None, timeout: int = MAX_REQUEST) -> tuple[int, str]:
    allowed = (method, path) == ("POST", PAR_PATH) or (method, path) == ("GET", READY_PATH)
    if not allowed or (method == "POST" and correlation is None) or \
            (correlation is not None and ID_RE.fullmatch(correlation) is None):
        raise ReentryFixtureError("request_identity_invalid")
    candidate_secrets = fixture_candidate_secrets(root)
    context = base_runtime.create_ssl_context(
        root / "ca/ca.crt", root / "clients/route-b.crt", root / "clients/route-b.key", check_hostname=True,
    )
    end = time.monotonic() + min(timeout, MAX_REQUEST)
    if deadline is not None:
        end = min(end, deadline)
    if end <= time.monotonic():
        raise ReentryFixtureError("runtime_deadline_exceeded")
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls: ssl.SSLSocket | None = None
    try:
        raw.settimeout(min(5.0, end - time.monotonic()))
        raw.connect(("127.0.0.1", PORT))
        tls = context.wrap_socket(raw, server_hostname="localhost", do_handshake_on_connect=False)
        with tls:
            tls.settimeout(min(5.0, end - time.monotonic()))
            tls.do_handshake()
            protocol = base_runtime._protocol_name(tls)
            if protocol not in ("TLSv1.2", "TLSv1.3"):
                raise ReentryFixtureError("tls_peer_handshake_failed")
            headers = ["Host: localhost:19443", "Connection: close", "Accept: */*"]
            body = b""
            if method == "POST":
                assert correlation is not None
                headers.extend(("Content-Type: application/x-www-form-urlencoded",
                                f"X-Fapi-Demo-Observation-ID: {correlation}"))
                body = PAR_BODY
            request = f"{method} /{path} HTTP/1.1\r\n" + "\r\n".join(headers)
            request += f"\r\nContent-Length: {len(body)}\r\n\r\n" + body.decode("ascii")
            tls.settimeout(min(5.0, end - time.monotonic()))
            tls.sendall(request.encode("ascii"))
            status, response = base_runtime._read_response(tls, end)
            if base_runtime.leak_scan(response, candidate_secrets):
                raise ReentryFixtureError("http_response_leak")
            return status, protocol
    except ReentryFixtureError:
        raise
    except ssl.SSLCertVerificationError:
        raise ReentryFixtureError("tls_server_verification_failed") from None
    except (ssl.SSLError, ssl.CertificateError):
        raise ReentryFixtureError("tls_peer_handshake_failed") from None
    except (TimeoutError, socket.timeout):
        raise ReentryFixtureError("tls_socket_timeout") from None
    except OSError:
        raise ReentryFixtureError("tls_socket_failure") from None
    except base_runtime.FixtureError:
        raise ReentryFixtureError("http_request_failed") from None
    finally:
        try:
            raw.close()
        except OSError:
            pass


def wait_ready(*, mode_deadline: float, root: Path = FIXTURE_ROOT) -> dict[str, Any]:
    attempts = 0
    while time.monotonic() < mode_deadline:
        attempts += 1
        try:
            status, protocol = tls_request("GET", READY_PATH, correlation=None, root=root,
                                          deadline=mode_deadline, timeout=MAX_REQUEST)
            if status in (404, 405):
                return {"attempts": attempts, "http_status": status, "protocol": protocol,
                        "path": "/" + READY_PATH, "observer_or_probe_row_expected": False}
            if status < 500:
                raise ReentryFixtureError("readiness_status_invalid")
        except ReentryFixtureError as error:
            if error.code not in {"tls_socket_failure", "tls_socket_timeout", "tls_peer_handshake_failed",
                                  "tls_server_verification_failed", "http_request_failed"}:
                raise
        time.sleep(min(1.0, max(0.0, mode_deadline - time.monotonic())))
    raise ReentryFixtureError("runtime_startup_timeout")


def _validate_healthy_observer(rows: list[dict[str, Any]], correlation: str,
                               expected_thumb: str) -> dict[str, Any]:
    matches = [row for row in rows if row["correlation_id"] == correlation]
    if len(rows) != 1 or len(matches) != 1:
        raise ReentryFixtureError("observer_mode_rows_invalid")
    row = matches[0]
    if (row["endpoint"], row["method"], row["path"]) != ("par", "POST", PAR_PATH) or \
            row["error"] != "none" or row["peer_present"] is not True or row["pkix"] is not True or \
            row["valid_now"] is not True or row["client_auth_eku"] is not True or \
            not 1 <= int(row["chain_count"]) <= 16 or row["leaf_sha256"] != expected_thumb:
        raise ReentryFixtureError("observer_mode_join_invalid")
    return dict(row)


def validate_mode_logs(mode: dict[str, Any], correlation: str, expected_thumb: str,
                       raw: bytes) -> dict[str, Any]:
    try:
        observer_rows = base_runtime.parse_observer_logs(raw)
    except Exception:
        raise ReentryFixtureError("observer_parse_failed") from None
    try:
        probe_rows = reentry_parser.parse_reentry_rows(raw)
    except Exception:
        raise ReentryFixtureError("reentry_parse_failed") from None
    if mode["observer"]:
        observer = _validate_healthy_observer(observer_rows, correlation, expected_thumb)
    elif observer_rows:
        raise ReentryFixtureError("observer_off_emitted_row")
    else:
        observer = None
    if mode["probe"]:
        if mode["observer"]:
            try:
                joined = reentry_parser.validate_par_evidence(raw, correlation)
            except Exception:
                raise ReentryFixtureError("probe_mode_evidence_invalid") from None
            if [row["correlation_id"] for row in probe_rows] != [correlation] * len(probe_rows):
                raise ReentryFixtureError("probe_mode_rows_invalid")
            counts = [int(row["count"]) for row in joined["reentry_rows"]]
            if len(counts) < 1 or counts[0] != 2 or counts != list(range(2, 2 + len(counts))):
                raise ReentryFixtureError("probe_mode_evidence_invalid")
        else:
            if probe_rows:
                raise ReentryFixtureError("reentry_off_emitted_row")
            counts = []
    else:
        if probe_rows:
            raise ReentryFixtureError("probe_off_emitted_row")
        counts = []
    return {"observer_rows": len(observer_rows), "reentry_rows": len(probe_rows),
            "reentry_counts": counts, "observer_evidence": observer}


def validate_three_mode_statuses(results: list[dict[str, Any]]) -> int:
    if len(results) != 3:
        raise ReentryFixtureError("mode_http_status_mismatch")
    correlation_ids = [row.get("correlation_id") for row in results]
    if any(not isinstance(value, str) or not ID_RE.fullmatch(value) for value in correlation_ids) or \
            len(set(correlation_ids)) != 3:
        raise ReentryFixtureError("request_identity_invalid")
    statuses = [int(row["http_status"]) for row in results]
    if any(status not in (400, 401) for status in statuses):
        raise ReentryFixtureError("http_status_not_par_negative")
    if len(set(statuses)) != 1:
        raise ReentryFixtureError("mode_http_status_mismatch")
    return statuses[0]


def _capture_logs(env_file: Path, candidates: tuple[bytes, ...], *, deadline: float) -> tuple[bytes, dict[str, Any]]:
    raw, meta = _compose(env_file, "logs", "--no-color", "--no-log-prefix", "keycloak",
                         timeout=MAX_COMMAND, cap=MAX_LOG, candidates=candidates, deadline=deadline)
    if base_runtime.leak_scan(raw, candidates):
        raise ReentryFixtureError("docker_output_leak")
    return raw, meta


def _wait_port_released(timeout: int = 30, interval: float = 1,
                        deadline: float | None = None) -> bool:
    end = time.monotonic() + min(max(timeout, 0), 30)
    if deadline is not None:
        end = min(end, deadline)
    delay = min(max(interval, 0.05), 2)
    while True:
        if _port_is_free():
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(min(delay, max(0.0, end - time.monotonic())))


def _mode_result(mode: dict[str, Any], candidates: tuple[bytes, ...], expected_thumb: str,
                 runtime_deadline: float, proof_deadline: float, state: dict[str, Any]) -> dict[str, Any]:
    env_path = FIXTURE_ROOT / "env" / str(mode["env"])
    mode_started = time.monotonic()
    mode_deadline = min(proof_deadline, mode_started + MAX_STARTUP)
    state["active_env"] = env_path
    state["active_container"] = False
    state["active_service_stopped"] = False
    state["active_log_scanned"] = False
    # A failed `up` can leave labeled resources behind; cleanup can safely inspect them.
    state["started"] = True
    _compose(env_path, "up", "-d", "--pull", "never", "--no-build", "--force-recreate", "keycloak",
             timeout=MAX_STARTUP, candidates=candidates, deadline=mode_deadline)
    state["active_container"] = True
    state["active_service_stopped"] = False
    state["owned_resources"] = verify_owned_resources(candidates=candidates, deadline=mode_deadline)
    readiness = wait_ready(mode_deadline=mode_deadline)
    if time.monotonic() >= proof_deadline or time.monotonic() >= runtime_deadline - CLEANUP_RESERVE:
        raise ReentryFixtureError("runtime_deadline_exceeded")
    correlation = secrets.token_hex(16)
    if not ID_RE.fullmatch(correlation):
        raise ReentryFixtureError("request_identity_invalid")
    status, protocol = tls_request("POST", PAR_PATH, correlation=correlation,
                                  deadline=min(proof_deadline, runtime_deadline - CLEANUP_RESERVE),
                                  timeout=MAX_REQUEST)
    if status not in (400, 401):
        raise ReentryFixtureError("http_status_not_par_negative")
    _compose(env_path, "stop", "--timeout", "10", "keycloak", timeout=MAX_COMMAND,
             candidates=candidates, deadline=proof_deadline)
    state["active_service_stopped"] = True
    raw, log_meta = _capture_logs(env_path, candidates, deadline=proof_deadline)
    state["active_log_scanned"] = True
    evidence = validate_mode_logs(mode, correlation, expected_thumb, raw)
    summary = {
        "mode": mode["name"], "observer_enabled": mode["observer"], "probe_enabled": mode["probe"],
        "correlation_id": correlation, "http_status": status, "tls_protocol": protocol,
        "readiness": readiness, "observer_rows": evidence["observer_rows"],
        "reentry_rows": evidence["reentry_rows"], "reentry_counts": evidence["reentry_counts"],
        "observer_evidence": evidence["observer_evidence"], "log_bytes": len(raw),
        "log_sha256": sha256(raw), "log_scan": "complete_no_leaks",
        "log_command": log_meta, "elapsed_seconds": round(time.monotonic() - mode_started, 3),
    }
    del raw
    _compose(env_path, "rm", "--stop", "--force", "keycloak", timeout=MAX_COMMAND,
             candidates=candidates, deadline=proof_deadline)
    state["active_container"] = False
    state["active_service_stopped"] = False
    state["active_log_scanned"] = False
    state["owned_resources"] = verify_owned_resources(allow_partial=True, candidates=candidates,
                                                       deadline=proof_deadline)
    return summary


def _cleanup(state: dict[str, Any], candidates: tuple[bytes, ...], total_deadline: float) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ownership": "not_checked", "stop": "not_needed", "failure_log_scan": "not_needed",
        "compose_down": "not_attempted", "project_resources_absent": False,
        "port_release": "not_attempted", "fixture_removed": False,
    }
    if not state.get("started"):
        try:
            result["project_resources_absent"] = _resources_absent(candidates, deadline=total_deadline)
            result["ownership"] = "not_started"
        except ReentryFixtureError:
            result["ownership"] = "preflight_unverified"
        result["port_release"] = "not_started"
        return result
    env_path: Path = state.get("active_env") or FIXTURE_ROOT / "env" / str(MODES[-1]["env"])
    owner_ok = False
    try:
        owned = verify_owned_resources(allow_partial=True, candidates=candidates, deadline=total_deadline)
        result["ownership"] = "pass"
        owner_ok = True
        if owned["container_count"]:
            if not state.get("active_service_stopped"):
                _compose(env_path, "stop", "--timeout", "10", "keycloak", timeout=30,
                         candidates=candidates, deadline=total_deadline)
                result["stop"] = "pass"
                state["active_service_stopped"] = True
            else:
                result["stop"] = "already_stopped"
            if not state.get("active_log_scanned"):
                try:
                    raw, _meta = _capture_logs(env_path, candidates, deadline=total_deadline)
                    observer_rows = base_runtime.parse_observer_logs(raw)
                    probe_rows = reentry_parser.parse_reentry_rows(raw)
                    result["failure_log_scan"] = {
                        "status": "complete", "bytes": len(raw), "sha256": sha256(raw),
                        "observer_rows": len(observer_rows), "reentry_rows": len(probe_rows),
                    }
                    del raw
                except Exception as error:
                    code = error.code if isinstance(error, ReentryFixtureError) else "scan_failed"
                    result["failure_log_scan"] = {"status": code}
        if owned["container_count"] or owned["volume_names"] or owned["network_names"]:
            _compose(env_path, "down", "--volumes", "--timeout", "10", timeout=30,
                     candidates=candidates, deadline=total_deadline)
            result["compose_down"] = "pass"
    except ReentryFixtureError as error:
        result["ownership"] = error.code if not owner_ok else "cleanup_command_failed"
    try:
        result["project_resources_absent"] = _resources_absent(candidates, deadline=total_deadline)
    except ReentryFixtureError:
        result["resources_absence_check"] = "failed"
    port_started = time.monotonic()
    result["port_release"] = "released" if _wait_port_released(30, 1, total_deadline) else "timeout"
    result["port_wait_seconds"] = round(time.monotonic() - port_started, 3)
    if result["project_resources_absent"]:
        try:
            verify_fixture_tree()
            shutil.rmtree(FIXTURE_ROOT)
            result["fixture_removed"] = not FIXTURE_ROOT.exists()
        except Exception:
            result["fixture_cleanup"] = "failed"
    else:
        result["fixture_cleanup"] = "retained_until_owned_resources_absent"
    result["complete"] = (result["ownership"] == "pass" and result["project_resources_absent"] and
                          result["port_release"] == "released" and result["fixture_removed"])
    return result


def run_fixture() -> dict[str, Any]:
    if RUN_ATTEMPT.exists() or RUN_ATTEMPT.is_symlink() or RUN_RECEIPT.exists() or RUN_RECEIPT.is_symlink():
        raise ReentryFixtureError("runtime_attempt_already_exists")
    intent, intent_sha = _read_intent()
    prep, pki = verify_prep_receipt()
    candidates = fixture_candidate_secrets()
    started_at = time.monotonic()
    total_deadline = started_at + MAX_RUNTIME
    proof_deadline = total_deadline - CLEANUP_RESERVE
    attempt = {"schema": "wp5-as-reentry-probe-attempt-v1", "created_at": utc_text(),
               "intent_sha256": intent_sha, "scope": "one_three_mode_reentry_runtime_attempt"}
    _write_exclusive(RUN_ATTEMPT, attempt)
    receipt: dict[str, Any] = {
        "schema": "wp5-as-reentry-probe-runtime-receipt-v1", "result": "fail",
        "scope": "actual_same_par_request_handler_reentry_probe_only", "project": PROJECT,
        "image_id": IMAGE_ID, "runtime_jar_sha256": RUNTIME_JAR_SHA256,
        "run_intent_sha256": intent_sha, "attempt_receipt_sha256": sha256(RUN_ATTEMPT.read_bytes()),
        "prep_receipt_sha256": sha256(PREP_RECEIPT.read_bytes()), "pki_leaf_sha256": pki,
        "input_manifest": input_manifest(), "started_at": utc_text(), "phase": "preflight",
        "preflight": None, "modes": [], "shared_par_http_status": None,
        "failure_category": "none", "failure_mode": "none", "cleanup": "pending",
        "cleanup_steps": {}, "log_output_persisted": False, "http_response_body_persisted": False,
        "oauth_success_claimed": False, "stock_kong_claimed": False,
        "new_listener_negative_coverage_claimed": False,
    }
    state: dict[str, Any] = {
        "started": False, "active_env": None, "active_container": False,
        "active_service_stopped": False, "active_log_scanned": False,
    }
    failure = "none"
    current_mode = "preflight"
    normal_modes_complete = False
    try:
        if intent.get("input_manifest") != input_manifest() or intent.get("pki_leaf_sha256") != pki:
            raise ReentryFixtureError("run_intent_mismatch")
        receipt["preflight"] = preflight_absent(candidates, deadline=proof_deadline)
        receipt["phase"] = "three_mode_runtime"
        for mode in MODES:
            if time.monotonic() >= proof_deadline:
                raise ReentryFixtureError("runtime_deadline_exceeded")
            current_mode = str(mode["name"])
            mode_result = _mode_result(mode, candidates, pki["route_b_leaf_sha256"],
                                       total_deadline, proof_deadline, state)
            receipt["modes"].append(mode_result)
        receipt["shared_par_http_status"] = validate_three_mode_statuses(receipt["modes"])
        if [row["mode"] for row in receipt["modes"]] != [mode["name"] for mode in MODES]:
            raise ReentryFixtureError("mode_http_status_mismatch")
        receipt["acceptance"] = {
            "mode1_one_healthy_observer_zero_probe": receipt["modes"][0]["observer_rows"] == 1 and receipt["modes"][0]["reentry_rows"] == 0,
            "mode2_one_healthy_observer_reentry_two_or_more": receipt["modes"][1]["observer_rows"] == 1 and
                len(receipt["modes"][1]["reentry_counts"]) >= 1 and receipt["modes"][1]["reentry_counts"][0] == 2,
            "mode3_both_markers_off": receipt["modes"][2]["observer_rows"] == 0 and receipt["modes"][2]["reentry_rows"] == 0,
            "http_status_same_across_modes": len({row["http_status"] for row in receipt["modes"]}) == 1,
        }
        if not all(receipt["acceptance"].values()):
            raise ReentryFixtureError("probe_mode_evidence_invalid")
        receipt["result"] = "pass"
        receipt["phase"] = "matrix_complete"
        normal_modes_complete = True
    except ReentryFixtureError as error:
        failure = error.code
    except Exception:
        failure = "run_interrupted"
    finally:
        receipt["failure_category"] = failure
        receipt["failure_mode"] = current_mode if failure != "none" else "none"
        cleanup = _cleanup(state, candidates, total_deadline)
        receipt["cleanup_steps"] = cleanup
        receipt["cleanup"] = "complete" if cleanup.get("complete", False) else (
            "not_needed" if not state.get("started") else "pending"
        )
        if failure == "none" and not normal_modes_complete:
            failure = "run_interrupted"
            receipt["failure_category"] = failure
        if receipt["cleanup"] not in ("complete", "not_needed") and failure == "none":
            failure = "runtime_cleanup_failed"
            receipt["failure_category"] = failure
        receipt["result"] = "pass" if failure == "none" and receipt["cleanup"] == "complete" else "fail"
        receipt["phase"] = "terminal"
        receipt["runtime_seconds"] = round(time.monotonic() - started_at, 3)
        receipt["finished_at"] = utc_text()
        try:
            _write_exclusive(RUN_RECEIPT, receipt)
        except ReentryFixtureError:
            # A pre-existing terminal receipt is never replaced.
            raise
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare", help="create fresh host-only TLS material; no Docker calls")
    sub.add_parser("intent", help="record exact runtime scope after read-only local Docker preflight")
    run = sub.add_parser("run", help="one three-mode isolated runtime attempt after Root review")
    run.add_argument("--approved-single-attempt", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_fixture()
            summary = {"result": result["result"], "fixture_root": result["fixture_root"],
                       "prep_receipt": str(PREP_RECEIPT), "file_count": result["file_count"],
                       "pki_leaf_sha256": result["pki_leaf_sha256"]}
        elif args.command == "intent":
            result = create_run_intent()
            summary = {"result": result["status"], "intent": str(RUN_INTENT),
                       "image_id": IMAGE_ID, "project": PROJECT, "preflight": result["preflight"]}
        elif not args.approved_single_attempt:
            raise ReentryFixtureError("runtime_approval_flag_required")
        else:
            result = run_fixture()
            summary = {"result": result["result"], "receipt": str(RUN_RECEIPT),
                       "failure_category": result["failure_category"], "cleanup": result["cleanup"],
                       "mode_count": len(result["modes"]), "shared_par_http_status": result["shared_par_http_status"]}
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0 if result.get("result") in ("prepared", "prepared_for_root_review", "pass") else 1
    except ReentryFixtureError as error:
        print(json.dumps({"result": "rejected", "reason": error.code}, sort_keys=True))
        return 1
    except (OSError, ValueError):
        print(json.dumps({"result": "rejected", "reason": "fixture_io_or_value_failure"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
