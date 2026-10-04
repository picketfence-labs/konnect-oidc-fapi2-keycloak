#!/usr/bin/env python3
"""Prepare and, after a separately reviewed authorization, run the isolated WP5 TLS fixture."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import re
import selectors
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from observation_parser import ObservationError, parse_observer_rows  # noqa: E402


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = Path("/private/tmp/wp5-as-mtls-observer-20261004-v3")
PREP_RECEIPT = Path("/private/tmp/wp5-as-mtls-observer-prep-receipt-20261004-v3.json")
RUN_INTENT = Path("/private/tmp/wp5-as-mtls-observer-run-intent-20261004-v3.json")
RUN_RECEIPT = Path("/private/tmp/wp5-as-mtls-observer-run-receipt-20261004-v3.json")
COMPOSE_FILE = ROOT / "tests/harness/docker-compose.wp5-observer.yml"
IMAGE_TAG = "wp5-as-peer-observer:20261004-minimal-v3"
IMAGE_ID = "sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953"
IMAGE_PHASE = "observer-image-build-only"
OWNER = "wp5-luna"
RUNTIME_PHASE = "observer-direct-runtime"
PROJECT = "wp5-as-mtls-observer"
VOLUME = "wp5-as-mtls-observer-data"
NETWORK = "wp5-as-mtls-observer_default"
PORT = 19443
MAX_LOG = 32 * 1024 * 1024
MAX_COMMAND = 60
MAX_REQUEST = 10
MAX_STARTUP = 180
MAX_RUNTIME = 12 * 60
OBSERVER_MARKER = "WP5_AS_PEER_OBS v=1"
OBSERVER_FIELDS = (
    "v", "observed_at", "correlation_id", "endpoint", "method", "path", "peer_present",
    "chain_count", "pkix", "valid_now", "client_auth_eku", "leaf_sha256", "error",
)

ENDPOINTS: dict[tuple[str, str], tuple[str, tuple[int, ...]]] = {
    ("GET", "realms/fapi-demo/.well-known/openid-configuration"): ("discovery", (200,)),
    ("GET", "realms/fapi-demo/protocol/openid-connect/certs"): ("jwks", (200,)),
    ("POST", "realms/fapi-demo/protocol/openid-connect/ext/par/request"): ("par", (400, 401)),
    ("POST", "realms/fapi-demo/protocol/openid-connect/token"): ("token", (400, 401)),
    ("POST", "realms/fapi-demo/protocol/openid-connect/revoke"): ("revoke", (400, 401)),
}
ERRORS = {
    "none", "no_request_context", "request_context_unavailable", "request_marker_unavailable",
    "request_unavailable", "correlation_invalid", "peer_absent", "peer_validation_failed", "observer_failure",
}
ID_RE = re.compile(r"[0-9a-f]{32}\Z")
THUMB_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
CERTIFICATE_ALERTS = frozenset({
    "TLSV1_ALERT_BAD_CERTIFICATE", "TLSV1_ALERT_CERTIFICATE_EXPIRED",
    "TLSV1_ALERT_CERTIFICATE_UNKNOWN", "TLSV1_ALERT_UNKNOWN_CA",
    "SSLV3_ALERT_BAD_CERTIFICATE", "SSLV3_ALERT_CERTIFICATE_EXPIRED",
    "SSLV3_ALERT_CERTIFICATE_UNKNOWN", "SSLV3_ALERT_UNKNOWN_CA",
})
TLS_PROTOCOLS = frozenset({"TLSv1.2", "TLSv1.3", "unavailable"})
TLS_STAGES = frozenset({"connect", "handshake", "request_send", "response_read"})
TLS_DIAGNOSTIC_CATEGORIES = frozenset({
    "peer_certificate_alert", "server_certificate_verify", "tls_failure",
    "socket_timeout", "socket_failure", "http_received", "http_failure",
})
TLS_ALERT_ENUMS = CERTIFICATE_ALERTS | frozenset({
    "TLSV1_ALERT_INTERNAL_ERROR", "TLSV1_ALERT_HANDSHAKE_FAILURE",
    "SSLV3_ALERT_HANDSHAKE_FAILURE",
})
LEAK_PATTERNS = (
    ("pem_private_key", re.compile(rb"-----BEGIN (?:EC |RSA |PRIVATE )?PRIVATE KEY-----")),
    ("pem_certificate", re.compile(rb"-----BEGIN CERTIFICATE-----")),
    ("authorization_value", re.compile(rb"(?i)(?:authorization\s*[:=]\s*bearer|bearer\s+)[A-Za-z0-9._~+/-]{12,}")),
    ("cookie_value", re.compile(rb"(?i)(?:set-cookie|cookie)\s*[:=]\s*[^\r\n]{8,}")),
    ("jwt_value", re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)


class FixtureError(Exception):
    def __init__(self, code: str, diagnostic: dict[str, str] | None = None):
        super().__init__(code)
        self.code = code
        self.diagnostic = sanitize_tls_diagnostic(diagnostic) if diagnostic is not None else None


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    endpoint: str
    accepted_status: tuple[int, ...]


OPERATIONS = tuple(Operation(method, path, endpoint, statuses)
                   for (method, path), (endpoint, statuses) in ENDPOINTS.items())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def input_manifest() -> dict[str, Any]:
    files = {
        "tests/harness/wp5_observer/runtime_fixture.py": Path(__file__).resolve(),
        "tests/harness/wp5_observer/observation_parser.py": Path(__file__).resolve().with_name("observation_parser.py"),
        "tests/harness/docker-compose.wp5-observer.yml": COMPOSE_FILE,
    }
    hashes = {name: sha256(path.read_bytes()) for name, path in sorted(files.items())}
    encoded = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"files": hashes, "sha256": sha256(encoded)}


def sanitize_tls_diagnostic(value: dict[str, str] | None) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"category", "alert", "protocol", "stage"}:
        return {"category": "tls_failure", "alert": "none", "protocol": "unavailable", "stage": "handshake"}
    category = value.get("category")
    alert = value.get("alert")
    protocol = value.get("protocol")
    stage = value.get("stage")
    return {
        "category": category if category in TLS_DIAGNOSTIC_CATEGORIES else "tls_failure",
        "alert": alert if alert in TLS_ALERT_ENUMS else "none",
        "protocol": protocol if protocol in TLS_PROTOCOLS else "unavailable",
        "stage": stage if stage in TLS_STAGES else "handshake",
    }


def parse_observer_logs(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_LOG:
        raise FixtureError("log_limit_exceeded")
    try:
        return parse_observer_rows(raw)
    except ObservationError as error:
        raise FixtureError(f"observer_parser_{error.code}") from None


def leak_scan(raw: bytes, candidate_secrets: tuple[bytes, ...] = ()) -> dict[str, int]:
    """Scan in memory; return only fixed categories and counts."""
    found: dict[str, int] = {}
    for category, pattern in LEAK_PATTERNS:
        count = len(pattern.findall(raw))
        if count:
            found[category] = count
    for secret in candidate_secrets:
        if secret and secret in raw:
            found["fixture_material"] = found.get("fixture_material", 0) + 1
    return found


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, mode)


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        raise FixtureError("cryptography_unavailable") from None
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


def _make_ca(name: str, x509, hashes, ec, NameOID, now: dt.datetime):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(name: str, issuer_key, issuer_cert, x509, hashes, ec, NameOID, ExtendedKeyUsageOID,
               now: dt.datetime, *, server: bool = False, dns_san: bool = False, ip_san: bool = False,
               expired: bool = False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    start = now - dt.timedelta(days=30 if expired else 1)
    end = now - dt.timedelta(days=1) if expired else now + dt.timedelta(days=30)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server
            else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    )
    if server:
        names = []
        if dns_san:
            names.append(x509.DNSName("localhost"))
        if ip_san:
            import ipaddress
            names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(issuer_key, hashes.SHA256())
    return key, cert


def _pem_cert(cert, serialization) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key, serialization) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def prepare_fixture(root: Path = FIXTURE_ROOT, receipt: Path | None = PREP_RECEIPT) -> dict[str, Any]:
    """Create a new private fixture; fail closed if any target already exists."""
    root = root.absolute()
    if root.exists() or root.is_symlink():
        raise FixtureError("fixture_path_exists")
    if receipt is not None and (receipt.exists() or receipt.is_symlink()):
        raise FixtureError("prep_receipt_exists")
    x509, hashes, serialization, ec, eku, name_oid = _crypto()
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    created: list[Path] = []
    try:
        root.mkdir(mode=0o700, parents=False)
        for relative in ("ca", "tls", "clients", "realm"):
            directory = root / relative
            directory.mkdir(mode=0o700)
            created.append(directory)
        trusted_key, trusted_ca = _make_ca("WP5 isolated fixture CA", x509, hashes, ec, name_oid, now)
        outside_key, outside_ca = _make_ca("WP5 untrusted fixture CA", x509, hashes, ec, name_oid, now)
        identities = {
            "server": _make_leaf("localhost", trusted_key, trusted_ca, x509, hashes, ec, name_oid, eku, now,
                                  server=True, dns_san=True, ip_san=True),
            "route-a": _make_leaf("kong-fapi-mtls", trusted_key, trusted_ca, x509, hashes, ec, name_oid, eku, now),
            "route-b": _make_leaf("kong-fapi-pkj-mtls", trusted_key, trusted_ca, x509, hashes, ec, name_oid, eku, now),
            "metadata": _make_leaf("third-party-metadata", trusted_key, trusted_ca, x509, hashes, ec, name_oid, eku, now),
            "untrusted": _make_leaf("untrusted", outside_key, outside_ca, x509, hashes, ec, name_oid, eku, now),
            "expired": _make_leaf("expired", trusted_key, trusted_ca, x509, hashes, ec, name_oid, eku, now, expired=True),
        }
        materials: dict[str, bytes] = {
            "ca/ca.crt": _pem_cert(trusted_ca, serialization),
            "ca/outside-ca.crt": _pem_cert(outside_ca, serialization),
        }
        for identity, (key, cert) in identities.items():
            destination = "tls" if identity.startswith("server") else "clients"
            stem = identity
            materials[f"{destination}/{stem}.crt"] = _pem_cert(cert, serialization)
            materials[f"{destination}/{stem}.key"] = _pem_key(key, serialization)
        materials["realm/fapi-demo-realm.json"] = b'{"realm":"fapi-demo","enabled":true}\n'
        modes: dict[str, int] = {}
        cert_fingerprints: dict[str, str] = {}
        for relative, content in materials.items():
            target = root / relative
            write_exclusive(target, content, 0o600)
            created.append(target)
            modes[relative] = 0o600
            if relative.endswith(".crt"):
                cert_fingerprints[relative] = sha256(content)
        peer_thumbprints = {
            identity: base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).rstrip(b"=").decode("ascii")
            for identity, (_, cert) in identities.items() if identity != "server"
        }
        env_specs = {"observer-off.env": "false", "observer-on.env": "true"}
        for filename, enabled in env_specs.items():
            data = (f"WP5_FIXTURE_ROOT={root}\nWP5_OBSERVER_ENABLED={enabled}\n").encode()
            write_exclusive(root / filename, data, 0o600)
            created.append(root / filename)
            modes[filename] = 0o600
        manifest = input_manifest()
        result = {
            "schema": "wp5-observer-fixture-prep-v3",
            "result": "prepared",
            "fixture_root": str(root),
            "file_count": len(materials) + len(env_specs),
            "directory_mode": "0700",
            "file_mode": "0600",
            "realm": "fapi-demo",
            "accounts_created": 0,
            "oauth_secrets_created": 0,
            "certificates": cert_fingerprints,
            "peer_thumbprints": peer_thumbprints,
            "compose_sha256": sha256(COMPOSE_FILE.read_bytes()),
            "input_manifest": manifest,
            "files": modes,
        }
        if receipt is not None:
            write_exclusive(receipt, (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode())
        return result
    except Exception:
        # A partial private fixture is left intact for explicit inspection; never silently erase keys.
        raise


def fixture_candidate_secrets(root: Path | None = None) -> tuple[bytes, ...]:
    root = root or FIXTURE_ROOT
    candidates = []
    for path in sorted(root.rglob("*.key")):
        if path.is_symlink() or not path.is_file():
            raise FixtureError("fixture_key_path_invalid")
        candidates.append(path.read_bytes())
    for path in sorted(root.rglob("*.crt")):
        if path.is_symlink() or not path.is_file():
            raise FixtureError("fixture_cert_path_invalid")
        candidates.append(path.read_bytes())
    return tuple(candidates)


def _minimal_env() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "DOCKER_CLI_HINTS": "false"}
    if os.environ.get("HOME"):
        env["HOME"] = os.environ["HOME"]
    if os.environ.get("TMPDIR"):
        env["TMPDIR"] = os.environ["TMPDIR"]
    # In particular, do not pass .env-like variables or SSLKEYLOGFILE to Compose/Python children.
    return env


@dataclass
class CommandResult:
    code: int
    timed_out: bool
    output: bytes
    truncated: bool


def bounded_command(argv: list[str], *, timeout: int = MAX_COMMAND, cap: int = MAX_LOG,
                    env: dict[str, str] | None = None) -> CommandResult:
    try:
        process = subprocess.Popen(argv, cwd=ROOT, env=env or _minimal_env(), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
    except OSError:
        raise FixtureError("command_start_failed") from None
    assert process.stdout is not None
    os.set_blocking(process.stdout.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout
    timed_out = truncated = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(0.25, remaining))
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, min(65536, cap + 1 - len(output)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > cap:
                    truncated = True
                    break
                output.extend(chunk)
            if truncated:
                break
            code = process.poll()
            if code is not None and not selector.get_map():
                break
        if timed_out or truncated:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
        return CommandResult(process.wait(timeout=2), timed_out, bytes(output), truncated)
    except subprocess.TimeoutExpired:
        raise FixtureError("command_reap_failed") from None
    finally:
        selector.close()
        process.stdout.close()


def _run_command(argv: list[str], *, timeout: int = MAX_COMMAND, cap: int = 1024 * 1024) -> bytes:
    result = bounded_command(argv, timeout=timeout, cap=cap)
    if result.timed_out:
        raise FixtureError("command_timeout")
    if result.truncated:
        raise FixtureError("command_output_limit")
    if result.code != 0:
        raise FixtureError("command_failed")
    if leak_scan(result.output, fixture_candidate_secrets() if FIXTURE_ROOT.exists() else ()):
        raise FixtureError("command_output_leak")
    return result.output


def _docker() -> str:
    path = shutil.which("docker", path=_minimal_env()["PATH"])
    if not path:
        raise FixtureError("docker_unavailable")
    return path


def _compose_prefix(env_file: Path) -> list[str]:
    return [_docker(), "compose", "--project-name", PROJECT, "--file", str(COMPOSE_FILE),
            "--env-file", str(env_file)]


def _exact_image_preflight() -> None:
    output = _run_command([_docker(), "image", "inspect", "--format",
        '{{.Id}}|{{.Os}}|{{.Architecture}}|{{index .Config.Labels "org.picketfence.wp5.owner"}}|{{index .Config.Labels "org.picketfence.wp5.phase"}}',
        IMAGE_ID])
    fields = output.decode("ascii", errors="strict").strip().split("|")
    if fields != [IMAGE_ID, "linux", "arm64", OWNER, IMAGE_PHASE]:
        raise FixtureError("runtime_image_identity_mismatch")


def _resource_names(kind: str, filters: list[str]) -> set[str]:
    output = _run_command([_docker(), kind, "ls", *filters, "--format", "{{.Name}}"], cap=1024 * 1024)
    return {line.strip() for line in output.decode("utf-8", errors="strict").splitlines() if line.strip()}


def preflight_absent() -> None:
    _exact_image_preflight()
    containers = _run_command([_docker(), "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}"], cap=1024 * 1024)
    if containers.strip():
        raise FixtureError("runtime_project_container_exists")
    volumes = _resource_names("volume", ["--filter", f"name={VOLUME}"])
    networks = _resource_names("network", ["--filter", f"name={NETWORK}"])
    if VOLUME in volumes:
        raise FixtureError("runtime_volume_exists")
    if NETWORK in networks:
        raise FixtureError("runtime_network_exists")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", PORT))
    except OSError:
        raise FixtureError("runtime_port_unavailable") from None
    finally:
        probe.close()


def _label_format() -> str:
    return ("{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|"
            "{{index .Config.Labels \"org.picketfence.wp5.owner\"}}|"
            "{{index .Config.Labels \"org.picketfence.wp5.phase\"}}|{{.Image}}|"
            "{{index .Config.Labels \"com.docker.compose.service\"}}")


def verify_owned_resources(*, allow_partial: bool = False) -> None:
    raw = _run_command([_docker(), "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}"], cap=1024 * 1024)
    ids = [item for item in raw.decode("ascii", errors="strict").splitlines() if item]
    if len(ids) > 1 or (not ids and not allow_partial):
        raise FixtureError("runtime_owned_container_missing")
    for container_id in ids:
        fields = _run_command([_docker(), "inspect", "--format", _label_format(), container_id]).decode().strip().split("|")
        if len(fields) != 6 or fields[1:] != [PROJECT, OWNER, RUNTIME_PHASE, IMAGE_ID, "keycloak"]:
            raise FixtureError("runtime_container_ownership_mismatch")
    vol_label_fmt = '{{index .Labels "org.picketfence.wp5.owner"}}|{{index .Labels "org.picketfence.wp5.phase"}}'
    volumes = _resource_names("volume", ["--filter", f"name={VOLUME}"])
    networks = _resource_names("network", ["--filter", f"name={NETWORK}"])
    if any(name != VOLUME for name in volumes) or any(name != NETWORK for name in networks):
        raise FixtureError("runtime_resource_name_mismatch")
    if (not ids and (volumes or networks)) and not allow_partial:
        raise FixtureError("runtime_owned_container_missing")
    if volumes:
        volume_fields = _run_command([_docker(), "volume", "inspect", "--format", vol_label_fmt, VOLUME]).decode().strip().split("|")
    else:
        volume_fields = []
    if volumes and volume_fields != [OWNER, RUNTIME_PHASE]:
        raise FixtureError("runtime_volume_ownership_mismatch")
    if networks:
        network_fields = _run_command([_docker(), "network", "inspect", "--format", vol_label_fmt, NETWORK]).decode().strip().split("|")
    else:
        network_fields = []
    if networks and network_fields != [OWNER, RUNTIME_PHASE]:
        raise FixtureError("runtime_network_ownership_mismatch")
    if ids and (not volumes or not networks):
        raise FixtureError("runtime_owned_support_resource_missing")


def create_ssl_context(ca_file: Path, cert_file: Path | None = None, key_file: Path | None = None,
                       *, check_hostname: bool = True) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = check_hostname
    context.keylog_filename = None
    context.load_verify_locations(cafile=str(ca_file))
    if (cert_file is None) != (key_file is None):
        raise FixtureError("client_identity_incomplete")
    if cert_file is not None and key_file is not None:
        context.load_cert_chain(str(cert_file), str(key_file))
    return context


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FixtureError("request_deadline_exceeded")
    return min(5.0, remaining)


MAX_RESPONSE = 64 * 1024


def _read_headers(sock: ssl.SSLSocket, deadline: float, cap: int = 16 * 1024) -> tuple[int, bytes, dict[str, str], bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(min(2048, cap + 1 - len(data)))
        if not chunk:
            raise FixtureError("http_response_incomplete")
        data.extend(chunk)
        if len(data) > cap:
            raise FixtureError("http_header_limit")
    header = bytes(data).split(b"\r\n\r\n", 1)[0]
    first = header.split(b"\r\n", 1)[0]
    match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [ -~]{0,100}", first)
    if match is None:
        raise FixtureError("http_status_invalid")
    headers: dict[str, str] = {}
    for item in header.split(b"\r\n")[1:]:
        if not item or b":" not in item:
            raise FixtureError("http_header_invalid")
        name, value = item.split(b":", 1)
        try:
            key = name.decode("ascii").lower()
            text = value.strip().decode("ascii")
        except UnicodeDecodeError:
            raise FixtureError("http_header_invalid") from None
        if not re.fullmatch(r"[a-z0-9-]{1,64}", key) or key in headers:
            raise FixtureError("http_header_invalid")
        headers[key] = text
    remainder = bytes(data).split(b"\r\n\r\n", 1)[1]
    return int(match.group(1)), remainder, headers, header + b"\r\n\r\n"


def _decode_chunked_body(wire: bytes) -> bytes | None:
    """Decode one complete, bounded chunked body; return None while more bytes are needed."""
    position = 0
    decoded = bytearray()

    def line() -> bytes | None:
        nonlocal position
        end = wire.find(b"\r\n", position)
        if end < 0:
            if len(wire) - position > 4096:
                raise FixtureError("http_chunk_line_limit")
            return None
        if end - position > 4096:
            raise FixtureError("http_chunk_line_limit")
        value = wire[position:end]
        position = end + 2
        return value

    while True:
        size_line = line()
        if size_line is None:
            return None
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}(?:;[!#$%&'*+.^_`|~0-9A-Za-z=-]{0,64})?", size_line):
            raise FixtureError("http_chunk_size_invalid")
        size = int(size_line.split(b";", 1)[0], 16)
        if size == 0:
            while True:
                trailer = line()
                if trailer is None:
                    return None
                if not trailer:
                    if position != len(wire):
                        raise FixtureError("http_response_extra_bytes")
                    return bytes(decoded)
                if b":" not in trailer or not re.fullmatch(rb"[A-Za-z0-9-]{1,64}:[ -~]{0,256}", trailer):
                    raise FixtureError("http_chunk_trailer_invalid")
        if size > MAX_RESPONSE or len(decoded) + size > MAX_RESPONSE:
            raise FixtureError("http_body_limit")
        if len(wire) - position < size + 2:
            return None
        decoded.extend(wire[position:position + size])
        position += size
        if wire[position:position + 2] != b"\r\n":
            raise FixtureError("http_chunk_terminator_invalid")
        position += 2


def _read_response(sock: ssl.SSLSocket, deadline: float) -> tuple[int, bytes]:
    status, remainder, headers, header_bytes = _read_headers(sock, deadline)
    content_length = headers.get("content-length")
    transfer = headers.get("transfer-encoding", "").lower()
    if content_length is not None and not re.fullmatch(r"[0-9]{1,6}", content_length):
        raise FixtureError("http_content_length_invalid")
    if content_length is not None and transfer:
        raise FixtureError("http_framing_ambiguous")
    if content_length is not None:
        expected = int(content_length)
        if expected > MAX_RESPONSE:
            raise FixtureError("http_body_limit")
        body = bytearray(remainder)
        while len(body) < expected:
            sock.settimeout(_remaining(deadline))
            chunk = sock.recv(min(4096, expected - len(body)))
            if not chunk:
                raise FixtureError("http_body_incomplete")
            body.extend(chunk)
        if len(body) != expected:
            # recv never asks beyond expected; extra bytes indicate pipelining or framing drift.
            raise FixtureError("http_response_extra_bytes")
        return status, header_bytes + body
    if transfer:
        if transfer != "chunked":
            raise FixtureError("http_transfer_encoding_unsupported")
        wire = bytearray(remainder)
        decoded: bytes | None = _decode_chunked_body(bytes(wire))
        while decoded is None:
            if len(wire) >= MAX_RESPONSE:
                raise FixtureError("http_body_limit")
            sock.settimeout(_remaining(deadline))
            chunk = sock.recv(min(4096, MAX_RESPONSE + 1 - len(wire)))
            if not chunk:
                raise FixtureError("http_chunked_body_incomplete")
            wire.extend(chunk)
            if len(wire) > MAX_RESPONSE:
                raise FixtureError("http_body_limit")
            decoded = _decode_chunked_body(bytes(wire))
        return status, header_bytes + wire + b"\x00" + decoded
    # Connection: close is part of each fixed request. A close-delimited body is read to EOF.
    body = bytearray(remainder)
    if len(body) > MAX_RESPONSE:
        raise FixtureError("http_body_limit")
    while True:
        try:
            sock.settimeout(_remaining(deadline))
            chunk = sock.recv(min(4096, MAX_RESPONSE + 1 - len(body)))
        except ssl.SSLZeroReturnError:
            break
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > MAX_RESPONSE:
            raise FixtureError("http_body_limit")
    return status, header_bytes + body


def _alert_category(reason: str) -> str:
    return "certificate" if reason in CERTIFICATE_ALERTS else "other"


def _protocol_name(tls: ssl.SSLSocket | None) -> str:
    if tls is None:
        return "unavailable"
    try:
        value = tls.version()
    except (OSError, ssl.SSLError):
        return "unavailable"
    return value if value in ("TLSv1.2", "TLSv1.3") else "unavailable"


def _tls_diagnostic(category: str, alert: str, protocol: str, stage: str) -> dict[str, str]:
    return sanitize_tls_diagnostic({
        "category": category, "alert": alert, "protocol": protocol, "stage": stage,
    })


def tls_request(method: str, path: str, *, correlation: str | None, cert_file: Path | None,
                key_file: Path | None, ca_file: Path, server_name: str = "localhost",
                header_values: tuple[str, ...] | None = None, deadline_seconds: int = MAX_REQUEST,
                runtime_deadline: float | None = None,
                diagnostic_sink: dict[str, str] | None = None) -> int:
    if (method, path) not in ENDPOINTS and path != "realms/fapi-demo/unknown":
        raise FixtureError("request_not_allowlisted")
    if correlation is not None and ID_RE.fullmatch(correlation) is None:
        raise FixtureError("request_id_invalid")
    context = create_ssl_context(ca_file, cert_file, key_file, check_hostname=True)
    deadline = time.monotonic() + deadline_seconds
    if runtime_deadline is not None:
        deadline = min(deadline, runtime_deadline)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls: ssl.SSLSocket | None = None
    stage = "connect"
    protocol = "unavailable"

    def update_sink(category: str, alert: str = "none") -> dict[str, str]:
        diagnostic = _tls_diagnostic(category, alert, protocol, stage)
        if diagnostic_sink is not None:
            diagnostic_sink.clear()
            diagnostic_sink.update(diagnostic)
        return diagnostic

    try:
        update_sink("socket_failure")
        raw.settimeout(_remaining(deadline))
        raw.connect(("127.0.0.1", PORT))
        stage = "handshake"
        update_sink("tls_failure")
        tls = context.wrap_socket(raw, server_hostname=server_name, do_handshake_on_connect=False)
        with tls:
            tls.settimeout(_remaining(deadline))
            tls.do_handshake()
            protocol = _protocol_name(tls)
            headers = ["Host: localhost:19443", "Connection: close", "Accept: */*"]
            if header_values is None:
                if correlation is not None:
                    headers.append(f"X-Fapi-Demo-Observation-ID: {correlation}")
            else:
                if not header_values or any(len(value) > 64 or not value.isascii() or
                                            any(ord(char) < 0x20 or ord(char) > 0x7e for char in value)
                                            for value in header_values):
                    raise FixtureError("request_header_value_invalid")
                headers.extend(f"X-Fapi-Demo-Observation-ID: {value}" for value in header_values)
            request = f"{method} /{path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n"
            if method == "POST":
                request += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n"
            request += "\r\n"
            stage = "request_send"
            update_sink("http_failure")
            tls.settimeout(_remaining(deadline))
            tls.sendall(request.encode("ascii"))
            stage = "response_read"
            update_sink("http_failure")
            status, full_response = _read_response(tls, deadline)
            if leak_scan(full_response, fixture_candidate_secrets()):
                raise FixtureError("http_response_leak_detected",
                                   _tls_diagnostic("http_failure", "none", protocol, stage))
            update_sink("http_received")
            return status
    except FixtureError as error:
        if error.diagnostic is None:
            error.diagnostic = update_sink("http_failure")
        raise
    except ssl.SSLCertVerificationError:
        raise FixtureError("server_certificate_verification_failed",
                           update_sink("server_certificate_verify")) from None
    except ssl.SSLError as error:
        reason = getattr(error, "reason", None)
        alert = reason if reason in TLS_ALERT_ENUMS else "none"
        if reason in CERTIFICATE_ALERTS:
            raise FixtureError("tls_peer_certificate_alert",
                               update_sink("peer_certificate_alert", alert)) from None
        raise FixtureError("tls_failure_unclassified",
                           update_sink("tls_failure", alert)) from None
    except (TimeoutError, socket.timeout):
        raise FixtureError("tls_socket_timeout", update_sink("socket_timeout")) from None
    except OSError:
        raise FixtureError("tls_socket_failure", update_sink("socket_failure")) from None
    finally:
        try:
            raw.close()
        except OSError:
            pass


def tls_negative(kind: str, *, cert_file: Path, key_file: Path, ca_file: Path,
                 correlation: str, runtime_deadline: float | None = None) -> dict[str, str]:
    if kind not in ("untrusted", "expired"):
        raise FixtureError("tls_negative_not_allowlisted")
    diagnostic: dict[str, str] = {}
    try:
        tls_request("GET", "realms/fapi-demo/.well-known/openid-configuration", correlation=correlation,
                    cert_file=cert_file, key_file=key_file, ca_file=ca_file,
                    runtime_deadline=runtime_deadline, diagnostic_sink=diagnostic)
    except FixtureError as error:
        fixed = error.diagnostic or sanitize_tls_diagnostic(diagnostic)
        if error.code == "tls_peer_certificate_alert" and fixed["alert"] in CERTIFICATE_ALERTS:
            return {"result": "certificate_rejected", "alert": fixed["alert"],
                    "protocol": fixed["protocol"], "stage": fixed["stage"]}
        if error.diagnostic is None:
            error.diagnostic = fixed
        raise
    raise FixtureError("tls_negative_received_http",
                       sanitize_tls_diagnostic({**diagnostic, "category": "http_received"}))


def server_verification_negative(*, cert_file: Path, key_file: Path, ca_file: Path,
                                 server_name: str, runtime_deadline: float | None = None) -> dict[str, str]:
    context = create_ssl_context(ca_file, cert_file, key_file, check_hostname=True)
    deadline = time.monotonic() + MAX_REQUEST
    if runtime_deadline is not None:
        deadline = min(deadline, runtime_deadline)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls: ssl.SSLSocket | None = None
    stage = "connect"
    protocol = "unavailable"

    def diagnostic(category: str, alert: str = "none") -> dict[str, str]:
        return _tls_diagnostic(category, alert, protocol, stage)

    try:
        raw.settimeout(_remaining(deadline))
        raw.connect(("127.0.0.1", PORT))
        stage = "handshake"
        try:
            tls = context.wrap_socket(raw, server_hostname=server_name, do_handshake_on_connect=False)
            with tls:
                tls.settimeout(_remaining(deadline))
                tls.do_handshake()
                protocol = _protocol_name(tls)
                raise FixtureError("server_verification_unexpectedly_passed",
                                   diagnostic("http_received"))
        except ssl.SSLCertVerificationError as error:
            if error.reason != "CERTIFICATE_VERIFY_FAILED":
                raise FixtureError("server_verification_reason_unexpected",
                                   diagnostic("tls_failure")) from None
            protocol = _protocol_name(tls)
            return diagnostic("server_certificate_verify")
        except FixtureError:
            raise
        except ssl.SSLError as error:
            reason = getattr(error, "reason", None)
            alert = reason if reason in TLS_ALERT_ENUMS else "none"
            raise FixtureError("server_verification_unclassified_tls_failure",
                               diagnostic("tls_failure", alert)) from None
    except (TimeoutError, socket.timeout):
        raise FixtureError("server_verification_timeout", diagnostic("socket_timeout")) from None
    except OSError:
        raise FixtureError("server_verification_socket_failure", diagnostic("socket_failure")) from None
    finally:
        raw.close()


def _client_thumbprint(cert_path: Path) -> str:
    x509, hashes, serialization, *_ = _crypto()
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    digest = cert.fingerprint(hashes.SHA256())
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _id() -> str:
    return secrets.token_hex(16)


def _id_row(rows: list[dict[str, Any]], correlation: str, op: Operation, thumb: str) -> dict[str, Any]:
    matches = [row for row in rows if row["correlation_id"] == correlation]
    if len(matches) != 1:
        raise FixtureError("observer_id_join_not_one_to_one")
    row = matches[0]
    if (row["endpoint"], row["method"], row["path"]) != (op.endpoint, op.method, op.path):
        raise FixtureError("observer_id_join_endpoint_mismatch")
    if row["error"] != "none" or not row["peer_present"] or not row["pkix"] or not row["valid_now"] or not row["client_auth_eku"]:
        raise FixtureError("observer_peer_validation_failed")
    if row["leaf_sha256"] != thumb:
        raise FixtureError("observer_identity_mismatch")
    return row


def _check_status(op: Operation, status: int) -> None:
    if status not in op.accepted_status:
        raise FixtureError("http_status_outside_contract")


def _wait_tls_ready(timeout: int = MAX_STARTUP, runtime_deadline: float | None = None) -> None:
    deadline = time.monotonic() + timeout
    if runtime_deadline is not None:
        deadline = min(deadline, runtime_deadline)
    cert, key = FIXTURE_ROOT / "clients/metadata.crt", FIXTURE_ROOT / "clients/metadata.key"
    context = create_ssl_context(FIXTURE_ROOT / "ca/ca.crt", cert, key)
    while time.monotonic() < deadline:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(min(3, max(0.1, deadline - time.monotonic())))
            raw.connect(("127.0.0.1", PORT))
            with context.wrap_socket(raw, server_hostname="localhost"):
                return
        except (OSError, ssl.SSLError):
            raw.close()
            time.sleep(1)
    raise FixtureError("runtime_tls_readiness_timeout")


def _compose(env_file: str, *args: str, timeout: int = MAX_COMMAND, cap: int = MAX_LOG,
             runtime_deadline: float | None = None) -> bytes:
    env_path = FIXTURE_ROOT / env_file
    if runtime_deadline is not None:
        remaining = runtime_deadline - time.monotonic()
        if remaining <= 0:
            raise FixtureError("runtime_deadline_exceeded")
        timeout = min(timeout, max(1, int(remaining)))
    output = _run_command([*_compose_prefix(env_path), *args], timeout=timeout, cap=cap)
    return output


def _capture_logs(env_file: str) -> tuple[bytes, list[dict[str, Any]]]:
    raw = _compose(env_file, "logs", "--no-color", "--no-log-prefix", "keycloak", cap=MAX_LOG)
    candidates = fixture_candidate_secrets()
    leaks = leak_scan(raw, candidates)
    if leaks:
        raise FixtureError("runtime_log_leak_detected")
    return raw, parse_observer_logs(raw)


def verify_fixture_tree(root: Path | None = None) -> None:
    root = root or FIXTURE_ROOT
    if root != FIXTURE_ROOT or root.is_symlink() or not root.is_dir() or (root.stat().st_mode & 0o777) != 0o700:
        raise FixtureError("fixture_root_identity_invalid")
    expected_dirs = {"ca", "tls", "clients", "realm"}
    expected_files = {
        "ca/ca.crt", "ca/outside-ca.crt", "tls/server.crt", "tls/server.key",
        "realm/fapi-demo-realm.json", "observer-off.env", "observer-on.env",
    }
    for identity in ("route-a", "route-b", "metadata", "untrusted", "expired"):
        expected_files.add(f"clients/{identity}.crt")
        expected_files.add(f"clients/{identity}.key")
    actual_dirs: set[str] = set()
    actual_files: set[str] = set()
    for directory, subdirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in subdirs:
            item = base / name
            if item.is_symlink() or not item.is_dir() or (item.stat().st_mode & 0o777) != 0o700:
                raise FixtureError("fixture_directory_invalid")
            actual_dirs.add(item.relative_to(root).as_posix())
        for name in files:
            item = base / name
            if item.is_symlink() or not item.is_file() or (item.stat().st_mode & 0o777) != 0o600:
                raise FixtureError("fixture_file_invalid")
            actual_files.add(item.relative_to(root).as_posix())
    if actual_dirs != expected_dirs or actual_files != expected_files:
        raise FixtureError("fixture_inventory_mismatch")


def wait_port_released(timeout: int = 30, interval: float = 1) -> bool:
    deadline = time.monotonic() + max(0, min(timeout, 30))
    delay = max(0.05, min(interval, 2))
    while True:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", PORT))
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
        finally:
            probe.close()
        time.sleep(min(delay, max(0, deadline - time.monotonic())))


def _resources_absent() -> bool:
    containers = _run_command([_docker(), "ps", "-aq", "--filter",
                               f"label=com.docker.compose.project={PROJECT}"], cap=1024 * 1024)
    volumes = _resource_names("volume", ["--filter", f"name={VOLUME}"])
    networks = _resource_names("network", ["--filter", f"name={NETWORK}"])
    return not containers.strip() and VOLUME not in volumes and NETWORK not in networks


def run_fixture() -> dict[str, Any]:
    """Run exactly one bounded OFF→ON fixture after the independent scope review."""
    if RUN_INTENT.exists() or RUN_INTENT.is_symlink() or RUN_RECEIPT.exists() or RUN_RECEIPT.is_symlink():
        raise FixtureError("runtime_attempt_already_exists")
    verify_fixture_tree(FIXTURE_ROOT)
    if PREP_RECEIPT.is_symlink() or not PREP_RECEIPT.is_file() or (PREP_RECEIPT.stat().st_mode & 0o777) != 0o600:
        raise FixtureError("prep_receipt_identity_invalid")
    prep_receipt = json.loads(PREP_RECEIPT.read_text(encoding="utf-8"))
    current_manifest = input_manifest()
    if (prep_receipt.get("schema") != "wp5-observer-fixture-prep-v3" or
            prep_receipt.get("fixture_root") != str(FIXTURE_ROOT) or
            prep_receipt.get("input_manifest") != current_manifest):
        raise FixtureError("prep_receipt_identity_mismatch")
    expected_thumbprints = prep_receipt.get("peer_thumbprints")
    identities = ("metadata", "route-a", "route-b", "untrusted", "expired")
    if not isinstance(expected_thumbprints, dict) or set(expected_thumbprints) != set(identities):
        raise FixtureError("prep_receipt_thumbprint_inventory_invalid")
    if any(not isinstance(value, str) or THUMB_RE.fullmatch(value) is None for value in expected_thumbprints.values()):
        raise FixtureError("prep_receipt_thumbprint_value_invalid")
    actual_thumbprints = {identity: _client_thumbprint(FIXTURE_ROOT / f"clients/{identity}.crt") for identity in identities}
    if actual_thumbprints != expected_thumbprints:
        raise FixtureError("prep_receipt_thumbprint_mismatch")
    preflight_absent()
    candidate_secrets = fixture_candidate_secrets()

    write_exclusive(RUN_INTENT, json.dumps({
        "schema": "wp5-observer-runtime-intent-v3", "project": PROJECT, "image_id": IMAGE_ID,
        "port": PORT, "prep_receipt_sha256": sha256(PREP_RECEIPT.read_bytes()),
        "input_manifest": current_manifest,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    receipt: dict[str, Any] = {
        "schema": "wp5-observer-runtime-receipt-v3", "result": "fail", "project": PROJECT,
        "image_id": IMAGE_ID, "port": PORT, "phase": "preflight_passed", "cases": {},
        "prep_receipt_sha256": sha256(PREP_RECEIPT.read_bytes()),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "operation_ledger": [], "observer_rows_off": None, "observer_rows_on": None,
        "expected_peer_thumbprints": expected_thumbprints, "repeat_handler_dedup": "not_run",
        "input_manifest": current_manifest,
        "cleanup": "pending", "raw_output_persisted": False,
        "diagnostic_capture": {"attempted": False, "complete": False, "phase": "not_run",
                               "scan_category": "not_run", "rows_parsed": 0, "rows_joined": 0,
                               "partial_rows": []},
    }
    started = False
    active_env_file = "observer-off.env"
    active_service_stopped = False
    normal_log_scan_complete = False
    current_case = "runtime_preflight"
    failure = "none"
    failure_case = "none"
    failure_phase = "none"
    failure_diagnostic: dict[str, str] | None = None
    runtime_deadline = time.monotonic() + MAX_RUNTIME
    started_at = time.monotonic()
    off_rows: list[dict[str, Any]] = []
    on_rows: list[dict[str, Any]] = []
    log_hashes: list[str] = []
    log_bytes: list[int] = []
    status_off: dict[tuple[str, str, str], int] = {}
    status_on: dict[tuple[str, str, str], int] = {}

    def begin(case: str, phase: str) -> None:
        nonlocal current_case
        current_case = case
        receipt["phase"] = phase
        receipt["cases"][case] = "running"

    def passed(case: str) -> None:
        receipt["cases"][case] = "pass"

    def check_live() -> None:
        if time.monotonic() >= runtime_deadline:
            raise FixtureError("runtime_deadline_exceeded")

    def append_operation(mode: str, case: str, identity: str, op: Operation, cid: str, status: int,
                         observer: dict[str, Any] | None = None, outcome: str = "completed") -> dict[str, Any]:
        key = (identity, op.method, op.path)
        status_map = status_off if mode == "off" else status_on
        if mode not in ("control", "concurrent") and key in status_map:
            raise FixtureError("http_operation_duplicate")
        if mode not in ("control", "concurrent"):
            status_map[key] = status
        entry: dict[str, Any] = {
            "case": case, "mode": "on" if mode == "concurrent" else mode,
            "identity": identity, "endpoint": op.endpoint, "method": op.method, "path": op.path,
            "correlation_id": cid, "http_status": status, "outcome": outcome,
            "observer": "disabled" if mode == "off" else "pending_join",
        }
        if observer is not None:
            entry["observer"] = {
                "peer_present": observer["peer_present"], "chain_count": observer["chain_count"],
                "pkix": observer["pkix"], "valid_now": observer["valid_now"],
                "client_auth_eku": observer["client_auth_eku"], "error": observer["error"],
                "leaf_sha256": observer["leaf_sha256"],
            }
        receipt["operation_ledger"].append(entry)
        _check_status(op, status)
        return entry

    cert_paths = {identity: (FIXTURE_ROOT / f"clients/{identity}.crt", FIXTURE_ROOT / f"clients/{identity}.key")
                  for identity in ("metadata", "route-a", "route-b")}
    matrix: list[tuple[str, Operation]] = []
    for op in OPERATIONS:
        if op.method == "GET":
            matrix.append(("metadata", op))
        else:
            matrix.extend((identity, op) for identity in ("route-a", "route-b"))
    on_ids: dict[str, tuple[str, Operation, str, dict[str, Any]]] = {}
    negative_ids: set[str] = set()

    def observer_fields(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "peer_present": row["peer_present"], "chain_count": row["chain_count"],
            "pkix": row["pkix"], "valid_now": row["valid_now"],
            "client_auth_eku": row["client_auth_eku"], "error": row["error"],
            "leaf_sha256": row["leaf_sha256"],
        }

    def capture_failure_logs() -> None:
        nonlocal active_service_stopped
        capture = receipt["diagnostic_capture"]
        capture.update({"attempted": True, "complete": False, "phase": receipt.get("phase", "unknown"),
                        "scan_category": "not_started", "rows_parsed": 0, "rows_joined": 0,
                        "negative_id_rows": 0, "unmatched_rows": 0, "partial_rows": [],
                        "validated_rows": [], "error_counts": {code: 0 for code in sorted(ERRORS) if code != "none"}})
        if normal_log_scan_complete:
            capture["scan_category"] = "prior_scan_complete"
            capture["complete"] = True
            return
        try:
            verify_owned_resources(allow_partial=True)
            capture["ownership_check"] = "pass"
        except FixtureError as error:
            capture["ownership_check"] = error.code
            capture["scan_category"] = "ownership_unverified"
            return
        if not active_service_stopped:
            try:
                _compose(active_env_file, "stop", "--timeout", "10", timeout=MAX_COMMAND)
                capture["stop_category"] = "pass"
                active_service_stopped = True
            except FixtureError as error:
                capture["stop_category"] = error.code
            except Exception:
                capture["stop_category"] = "stop_unexpected_failure"
        else:
            capture["stop_category"] = "already_stopped"
        try:
            raw, rows = _capture_logs(active_env_file)
        except FixtureError as error:
            capture["scan_category"] = error.code
            return
        except Exception:
            capture["scan_category"] = "log_scan_unexpected_failure"
            return
        capture["rows_parsed"] = len(rows)
        capture["log_sha256"] = sha256(raw)
        capture["log_bytes"] = len(raw)
        capture["validated_rows"] = [
            {field: row[field] for field in OBSERVER_FIELDS}
            for row in rows[:256]
        ]
        for row in rows:
            if row["error"] in capture["error_counts"]:
                capture["error_counts"][row["error"]] += 1
        log_hashes.append(sha256(raw))
        log_bytes.append(len(raw))
        joined_rows: list[dict[str, Any]] = []
        for row in rows[:256]:
            correlation = row["correlation_id"]
            if correlation in negative_ids:
                capture["negative_id_rows"] += 1
                continue
            expected = on_ids.get(correlation)
            if expected is None:
                capture["unmatched_rows"] += 1
                continue
            identity, operation, _case, ledger_entry = expected
            try:
                verified = _id_row([row], correlation, operation, expected_thumbprints[identity])
            except FixtureError:
                capture["unmatched_rows"] += 1
                continue
            fields = observer_fields(verified)
            ledger_entry["observer"] = fields
            joined_rows.append({
                "observed_at": verified["observed_at"], "correlation_id": correlation,
                "endpoint": verified["endpoint"], "method": verified["method"],
                "path": verified["path"], **fields,
            })
        capture["partial_rows"] = joined_rows[:256]
        capture["rows_joined"] = len(joined_rows)
        capture["scan_category"] = "complete"
        capture["complete"] = True
        if active_env_file == "observer-on.env":
            receipt["observer_rows_on"] = len(rows)
        else:
            receipt["observer_rows_off"] = len(rows)

    def metadata_liveness(case: str) -> str:
        begin(case, case)
        discovery = next(op for op in OPERATIONS if op.endpoint == "discovery")
        cid = _id()
        cert, key = cert_paths["metadata"]
        status = tls_request("GET", discovery.path, correlation=cid, cert_file=cert, key_file=key,
                             ca_file=FIXTURE_ROOT / "ca/ca.crt", runtime_deadline=runtime_deadline)
        entry = append_operation("control", case, "metadata", discovery, cid, status,
                                 outcome="before_or_after_tls_negative")
        on_ids[cid] = ("metadata", discovery, case, entry)
        passed(case)
        return cid

    try:
        begin("off_start", "observer_off_start")
        started = True  # A failed Compose up can leave only its owner-labeled network or volume.
        _compose("observer-off.env", "up", "-d", "--no-build", "--pull", "never", "--force-recreate",
                 timeout=MAX_COMMAND, runtime_deadline=runtime_deadline)
        verify_owned_resources()
        passed(current_case)

        begin("off_tls_readiness", "observer_off_tls_readiness")
        _wait_tls_ready(runtime_deadline=runtime_deadline)
        passed(current_case)
        for identity, op in matrix:
            check_live()
            case = f"off_{identity.replace('-', '_')}_{op.endpoint}"
            begin(case, "observer_off_http_matrix")
            cid = _id()
            cert, key = cert_paths[identity]
            status = tls_request(op.method, op.path, correlation=cid, cert_file=cert, key_file=key,
                                 ca_file=FIXTURE_ROOT / "ca/ca.crt", runtime_deadline=runtime_deadline)
            append_operation("off", case, identity, op, cid, status)
            passed(case)
        if len(status_off) != 8:
            raise FixtureError("observer_off_matrix_incomplete")

        begin("off_log_scan", "observer_off_log_scan")
        verify_owned_resources()
        _compose("observer-off.env", "stop", "--timeout", "10", runtime_deadline=runtime_deadline)
        active_service_stopped = True
        off_raw, off_rows = _capture_logs("observer-off.env")
        if leak_scan(off_raw, candidate_secrets):
            raise FixtureError("runtime_log_leak_detected")
        if off_rows:
            raise FixtureError("observer_off_emitted_row")
        receipt["observer_rows_off"] = 0
        log_hashes.append(sha256(off_raw))
        log_bytes.append(len(off_raw))
        passed(current_case)
        del off_raw
        normal_log_scan_complete = True

        active_env_file = "observer-on.env"
        active_service_stopped = False
        normal_log_scan_complete = False
        begin("on_start", "observer_on_start")
        verify_owned_resources()
        _compose("observer-on.env", "up", "-d", "--no-build", "--pull", "never", "--force-recreate",
                 timeout=MAX_COMMAND, runtime_deadline=runtime_deadline)
        verify_owned_resources()
        passed(current_case)

        begin("on_tls_readiness", "observer_on_tls_readiness")
        _wait_tls_ready(runtime_deadline=runtime_deadline)
        passed(current_case)
        for identity, op in matrix:
            check_live()
            case = f"on_{identity.replace('-', '_')}_{op.endpoint}"
            begin(case, "observer_on_http_matrix")
            cid = _id()
            cert, key = cert_paths[identity]
            status = tls_request(op.method, op.path, correlation=cid, cert_file=cert, key_file=key,
                                 ca_file=FIXTURE_ROOT / "ca/ca.crt", runtime_deadline=runtime_deadline)
            entry = append_operation("on", case, identity, op, cid, status)
            on_ids[cid] = (identity, op, case, entry)
            passed(case)
        if status_off != status_on:
            raise FixtureError("observer_off_on_http_status_changed")

        token_op = next(op for op in OPERATIONS if op.endpoint == "token")
        begin("on_concurrent_route_pair", "observer_on_concurrent_route_pair")
        def concurrent_request(identity: str) -> tuple[str, str, int]:
            cid = _id()
            cert, key = cert_paths[identity]
            status = tls_request(token_op.method, token_op.path, correlation=cid, cert_file=cert, key_file=key,
                                 ca_file=FIXTURE_ROOT / "ca/ca.crt", runtime_deadline=runtime_deadline)
            return cid, identity, status
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(concurrent_request, identity) for identity in ("route-a", "route-b")]
            concurrent_results = [future.result(timeout=MAX_REQUEST + 2) for future in futures]
        concurrent_ids = [row[0] for row in concurrent_results]
        if len(set(concurrent_ids)) != 2:
            raise FixtureError("observer_concurrent_ids_collide")
        for cid, identity, status in concurrent_results:
            case = f"on_concurrent_{identity.replace('-', '_')}_token"
            if status != status_on[(identity, token_op.method, token_op.path)]:
                raise FixtureError("concurrent_http_status_changed")
            cert, _ = cert_paths[identity]
            entry = append_operation("concurrent", case, identity, token_op, cid, status, outcome="completed_concurrently")
            on_ids[cid] = (identity, token_op, case, entry)
        passed(current_case)

        discovery = next(op for op in OPERATIONS if op.endpoint == "discovery")
        jwks = next(op for op in OPERATIONS if op.endpoint == "jwks")
        begin("on_no_client_certificate", "observer_on_no_client_certificate")
        no_cert_id = _id()
        no_cert_status = tls_request("GET", discovery.path, correlation=no_cert_id, cert_file=None, key_file=None,
            ca_file=FIXTURE_ROOT / "ca/ca.crt", runtime_deadline=runtime_deadline)
        no_cert_entry = {"case": "on_no_client_certificate", "mode": "on", "identity": "none",
            "endpoint": "discovery", "method": "GET", "path": discovery.path, "correlation_id": no_cert_id,
            "http_status": no_cert_status, "outcome": "completed", "observer": "pending_join"}
        receipt["operation_ledger"].append(no_cert_entry)
        _check_status(discovery, no_cert_status)
        passed(current_case)

        begin("on_malformed_correlation", "observer_on_malformed_correlation")
        malformed_status = tls_request("GET", discovery.path, correlation=None, cert_file=cert_paths["route-a"][0],
            key_file=cert_paths["route-a"][1], ca_file=FIXTURE_ROOT / "ca/ca.crt", header_values=("invalid",),
            runtime_deadline=runtime_deadline)
        malformed_entry = {"case": current_case, "mode": "on", "identity": "route-a", "endpoint": "discovery",
            "method": "GET", "path": discovery.path, "correlation_id": "none", "http_status": malformed_status,
            "outcome": "completed", "observer": "pending_join"}
        receipt["operation_ledger"].append(malformed_entry)
        _check_status(discovery, malformed_status)
        passed(current_case)

        begin("on_duplicate_correlation", "observer_on_duplicate_correlation")
        duplicate_id = _id()
        duplicate_status = tls_request("GET", jwks.path, correlation=duplicate_id, cert_file=cert_paths["route-a"][0],
            key_file=cert_paths["route-a"][1], ca_file=FIXTURE_ROOT / "ca/ca.crt",
            header_values=(duplicate_id, duplicate_id), runtime_deadline=runtime_deadline)
        duplicate_entry = {"case": current_case, "mode": "on", "identity": "route-a", "endpoint": "jwks",
            "method": "GET", "path": jwks.path, "correlation_id": "none", "attempted_correlation_id": duplicate_id,
            "http_status": duplicate_status, "outcome": "completed", "observer": "pending_join"}
        receipt["operation_ledger"].append(duplicate_entry)
        _check_status(jwks, duplicate_status)
        passed(current_case)

        unknown_path = "realms/fapi-demo/unknown"
        begin("on_unknown_path", "observer_on_unknown_path")
        unknown_id = _id()
        unknown_status = tls_request("GET", unknown_path, correlation=unknown_id, cert_file=cert_paths["route-a"][0],
            key_file=cert_paths["route-a"][1], ca_file=FIXTURE_ROOT / "ca/ca.crt", runtime_deadline=runtime_deadline)
        receipt["operation_ledger"].append({"case": current_case, "mode": "on", "identity": "route-a",
            "endpoint": "unknown", "method": "GET", "path": unknown_path, "correlation_id": unknown_id,
            "http_status": unknown_status, "outcome": "completed", "observer": "no_record_expected"})
        if unknown_status not in (404, 405):
            raise FixtureError("unknown_path_status_outside_contract")
        passed(current_case)

        negative_cases = (
            ("on_client_tls_untrusted", "untrusted", "untrusted"),
            ("on_client_tls_expired", "expired", "expired"),
            ("on_wrong_server_ca", "wrong_server_ca", "metadata"),
            ("on_wrong_server_san", "wrong_server_san", "metadata"),
        )
        for case, kind, identity in negative_cases:
            check_live()
            before_id = metadata_liveness(f"{case}_before_control")
            begin(case, case)
            negative_entry: dict[str, Any] = {
                "case": case, "mode": "on", "identity": identity, "endpoint": "discovery",
                "method": "GET", "path": discovery.path, "correlation_id": "none",
                "http_status": None, "fixture_kind": kind, "diagnostic": None,
                "before_control_id": before_id, "after_control_id": None,
                "outcome": "running", "observer": "no_record_expected",
            }
            receipt["operation_ledger"].append(negative_entry)
            try:
                if kind in ("untrusted", "expired"):
                    attempted_id = _id()
                    negative_ids.add(attempted_id)
                    negative_entry["correlation_id"] = attempted_id
                    tls_result = tls_negative(kind, cert_file=FIXTURE_ROOT / f"clients/{identity}.crt",
                        key_file=FIXTURE_ROOT / f"clients/{identity}.key", ca_file=FIXTURE_ROOT / "ca/ca.crt",
                        correlation=attempted_id, runtime_deadline=runtime_deadline)
                    negative_entry["outcome"] = "peer_alert_no_http_response"
                elif kind == "wrong_server_ca":
                    attempted_id = "none"
                    tls_result = server_verification_negative(cert_file=cert_paths["metadata"][0],
                        key_file=cert_paths["metadata"][1], ca_file=FIXTURE_ROOT / "ca/outside-ca.crt",
                        server_name="localhost", runtime_deadline=runtime_deadline)
                    negative_entry["outcome"] = "server_certificate_rejected_no_http_response"
                else:
                    attempted_id = "none"
                    tls_result = server_verification_negative(cert_file=cert_paths["metadata"][0],
                        key_file=cert_paths["metadata"][1], ca_file=FIXTURE_ROOT / "ca/ca.crt",
                        server_name="wrong-host.invalid", runtime_deadline=runtime_deadline)
                    negative_entry["outcome"] = "server_certificate_rejected_no_http_response"
            except FixtureError as error:
                negative_entry["outcome"] = "failed"
                negative_entry["diagnostic"] = error.diagnostic
                negative_entry["failure_category"] = error.code
                raise
            negative_entry["correlation_id"] = attempted_id
            negative_entry["diagnostic"] = tls_result
            passed(case)
            after_id = metadata_liveness(f"{case}_after_control")
            negative_entry["after_control_id"] = after_id

        begin("on_log_scan_and_join", "observer_on_log_scan_and_join")
        verify_owned_resources()
        _compose("observer-on.env", "stop", "--timeout", "10", runtime_deadline=runtime_deadline)
        active_service_stopped = True
        on_raw, on_rows = _capture_logs("observer-on.env")
        if leak_scan(on_raw, candidate_secrets):
            raise FixtureError("runtime_log_leak_detected")
        if len(on_rows) != len(on_ids) + 3:
            raise FixtureError("observer_on_row_count_mismatch")
        seen_ids: set[str] = set()
        for cid, (identity, op, case, ledger_entry) in on_ids.items():
            if cid in seen_ids:
                raise FixtureError("observer_correlation_id_reused")
            seen_ids.add(cid)
            row = _id_row(on_rows, cid, op, expected_thumbprints[identity])
            ledger_entry["observer"] = {
                "peer_present": row["peer_present"], "chain_count": row["chain_count"], "pkix": row["pkix"],
                "valid_now": row["valid_now"], "client_auth_eku": row["client_auth_eku"],
                "error": row["error"], "leaf_sha256": row["leaf_sha256"],
            }
        absent = [row for row in on_rows if row["correlation_id"] == no_cert_id]
        if len(absent) != 1 or (absent[0]["endpoint"], absent[0]["method"], absent[0]["path"],
            absent[0]["error"], absent[0]["peer_present"]) != (
                "discovery", "GET", discovery.path, "peer_absent", False):
            raise FixtureError("observer_no_cert_result_invalid")
        no_cert_entry["observer"] = {"peer_present": False, "chain_count": 0, "pkix": False,
            "valid_now": False, "client_auth_eku": False, "error": "peer_absent", "leaf_sha256": "none"}
        invalid_rows = [row for row in on_rows if row["correlation_id"] == "none"]
        actual_invalid = {(row["endpoint"], row["method"], row["path"], row["error"]) for row in invalid_rows}
        expected_invalid = {
            ("discovery", "GET", discovery.path, "correlation_invalid"),
            ("jwks", "GET", jwks.path, "correlation_invalid"),
        }
        if len(invalid_rows) != 2 or actual_invalid != expected_invalid:
            raise FixtureError("observer_invalid_header_control_failed")
        for row in invalid_rows:
            entry = malformed_entry if row["path"] == discovery.path else duplicate_entry
            entry["observer"] = {"peer_present": False, "chain_count": 0, "pkix": False,
                "valid_now": False, "client_auth_eku": False, "error": row["error"], "leaf_sha256": "none"}
        if any(row["path"] == unknown_path for row in on_rows):
            raise FixtureError("observer_unknown_path_recorded")
        if any(row["correlation_id"] in negative_ids for row in on_rows):
            raise FixtureError("tls_negative_emitted_observer_row")
        for case, _kind, _identity in negative_cases:
            entry = next(item for item in receipt["operation_ledger"] if item["case"] == case)
            if entry["before_control_id"] not in seen_ids or entry["after_control_id"] not in seen_ids:
                raise FixtureError("tls_negative_liveness_control_missing")
        receipt["observer_rows_on"] = len(on_rows)
        log_hashes.append(sha256(on_raw))
        log_bytes.append(len(on_raw))
        receipt["log_sha256"] = log_hashes
        receipt["log_bytes"] = log_bytes
        receipt["runtime_seconds"] = round(time.monotonic() - started_at, 3)
        passed(current_case)
        del on_raw
        normal_log_scan_complete = True
        receipt["diagnostic_capture"] = {
            "attempted": True, "complete": True, "phase": "observer_on_log_scan_and_join",
            "scan_category": "complete", "rows_parsed": len(on_rows), "rows_joined": len(on_ids),
            "negative_id_rows": 0, "unmatched_rows": 0, "partial_rows": [],
        }
        receipt["phase"] = "matrix_complete"
        receipt["result"] = "pass"
        current_case = "cleanup"
    except FixtureError as error:
        failure = error.code
        failure_case = current_case
        failure_phase = receipt.get("phase", "runtime_unknown")
        failure_diagnostic = error.diagnostic
        if current_case in receipt["cases"]:
            receipt["cases"][current_case] = "fail"
    except Exception:
        failure = "runtime_unexpected_internal_failure"
        failure_case = current_case
        failure_phase = receipt.get("phase", "runtime_unknown")
        if current_case in receipt["cases"]:
            receipt["cases"][current_case] = "fail"
    finally:
        receipt["failure_category"] = failure
        receipt["failure_case"] = failure_case
        receipt["failure_phase"] = failure_phase
        receipt["failure_diagnostic"] = failure_diagnostic
        if started:
            receipt["phase"] = "cleanup"
            receipt["cases"]["cleanup"] = "running"
            cleanup_steps: dict[str, Any] = {
                "ownership": "not_checked", "stop": "not_needed", "log_scan": "not_needed",
                "down": "not_attempted", "resources_absent": False,
                "port_release": "not_attempted", "fixture_removed": False,
            }
            owner_verified = False
            try:
                verify_owned_resources(allow_partial=True)
                owner_verified = True
                cleanup_steps["ownership"] = "pass"
            except FixtureError as error:
                cleanup_steps["ownership"] = error.code
            except Exception:
                cleanup_steps["ownership"] = "ownership_check_failed"

            if owner_verified:
                if failure != "none" and not normal_log_scan_complete:
                    try:
                        capture_failure_logs()
                        cleanup_steps["log_scan"] = receipt["diagnostic_capture"].get("scan_category", "unknown")
                        cleanup_steps["stop"] = receipt["diagnostic_capture"].get("stop_category", "not_attempted")
                    except Exception:
                        cleanup_steps["log_scan"] = "diagnostic_capture_failed"
                if not active_service_stopped:
                    try:
                        _compose(active_env_file, "stop", "--timeout", "10", timeout=MAX_COMMAND)
                        active_service_stopped = True
                        cleanup_steps["stop"] = "pass"
                    except FixtureError as error:
                        cleanup_steps["stop"] = error.code
                    except Exception:
                        cleanup_steps["stop"] = "stop_unexpected_failure"
                try:
                    _compose(active_env_file, "down", "--volumes", "--timeout", "10", timeout=MAX_COMMAND)
                    cleanup_steps["down"] = "pass"
                except FixtureError as error:
                    cleanup_steps["down"] = error.code
                except Exception:
                    cleanup_steps["down"] = "down_unexpected_failure"
            try:
                cleanup_steps["resources_absent"] = _resources_absent()
            except FixtureError as error:
                cleanup_steps["resources_absent_category"] = error.code
            except Exception:
                cleanup_steps["resources_absent_category"] = "resource_check_failed"

            try:
                port_started = time.monotonic()
                port_released = wait_port_released(timeout=30, interval=1)
                cleanup_steps["port_release"] = "released" if port_released else "timeout"
                cleanup_steps["port_wait_seconds"] = round(time.monotonic() - port_started, 3)
            except Exception:
                port_released = False
                cleanup_steps["port_release"] = "check_failed"

            if cleanup_steps["resources_absent"]:
                try:
                    verify_fixture_tree()
                    shutil.rmtree(FIXTURE_ROOT)
                    cleanup_steps["fixture_removed"] = not FIXTURE_ROOT.exists()
                except FixtureError as error:
                    cleanup_steps["fixture_category"] = error.code
                except OSError:
                    cleanup_steps["fixture_category"] = "runtime_cleanup_io_failure"
            else:
                cleanup_steps["fixture_category"] = "retained_until_owned_resources_absent"

            complete = (cleanup_steps["resources_absent"] and cleanup_steps["fixture_removed"] and
                        cleanup_steps["port_release"] == "released")
            receipt["cleanup_steps"] = cleanup_steps
            receipt["cleanup"] = "complete" if complete else "pending"
            if complete:
                receipt["cases"]["cleanup"] = "pass"
            else:
                receipt["cases"]["cleanup"] = "fail"
                if not cleanup_steps["resources_absent"]:
                    receipt["cleanup_category"] = "runtime_cleanup_incomplete"
                elif not cleanup_steps["fixture_removed"]:
                    receipt["cleanup_category"] = "runtime_fixture_cleanup_incomplete"
                else:
                    receipt["cleanup_category"] = "runtime_port_release_timeout"
        else:
            receipt["cleanup"] = "not_needed"
            receipt["cleanup_steps"] = {"resources_absent": True, "port_release": "not_started",
                                         "fixture_removed": False}
        if receipt["cleanup"] != "complete" and failure == "none":
            failure = "runtime_cleanup_failed"
            failure_case = "cleanup"
            failure_phase = "cleanup"
            failure_diagnostic = None
            receipt["failure_category"] = failure
            receipt["failure_case"] = failure_case
            receipt["failure_phase"] = failure_phase
            receipt["failure_diagnostic"] = failure_diagnostic
        receipt["result"] = "pass" if failure == "none" and receipt["cleanup"] == "complete" else "fail"
        receipt["phase"] = "terminal"
        receipt["input_manifest"] = input_manifest()
        receipt["log_sha256"] = log_hashes
        receipt["log_bytes"] = log_bytes
        write_exclusive(RUN_RECEIPT, (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return receipt

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare", help="create fresh private certs and a minimal realm; no Docker calls")
    run = sub.add_parser("run", help="one isolated Docker runtime attempt after independent scope review")
    run.add_argument("--approved-single-attempt", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_fixture()
            summary = {"result": result["result"], "fixture_root": result["fixture_root"],
                       "prep_receipt": str(PREP_RECEIPT), "file_count": result["file_count"]}
        elif not args.approved_single_attempt:
            raise FixtureError("runtime_attempt_flag_required")
        else:
            result = run_fixture()
            cases = result.get("cases", {})
            summary = {"result": result.get("result"), "receipt": str(RUN_RECEIPT),
                       "failure_case": result.get("failure_case"),
                       "failure_category": result.get("failure_category"),
                       "failure_phase": result.get("failure_phase"),
                       "failure_diagnostic": result.get("failure_diagnostic"),
                       "cases_passed": sum(value == "pass" for value in cases.values()),
                       "cases_failed": sum(value == "fail" for value in cases.values()),
                       "observer_rows_off": result.get("observer_rows_off"),
                       "observer_rows_on": result.get("observer_rows_on"),
                       "diagnostic_capture": {key: result.get("diagnostic_capture", {}).get(key)
                                              for key in ("attempted", "complete", "phase", "scan_category",
                                                          "rows_parsed", "rows_joined")},
                       "cleanup": result.get("cleanup")}
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0 if result.get("result") in ("prepared", "pass") else 1
    except FixtureError as error:
        print(json.dumps({"result": "rejected", "reason": error.code}, sort_keys=True))
        return 1
    except (OSError, ValueError):
        print(json.dumps({"result": "rejected", "reason": "fixture_io_or_value_failure"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
