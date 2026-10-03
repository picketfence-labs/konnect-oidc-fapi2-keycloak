#!/usr/bin/env python3
"""Test-only TLS capture server for the isolated WP3 Gateway harness.

This helper returns only booleans, counts, SHA-256 fingerprints, and an
in-memory request counter over the private mTLS channel. It never logs or
persists fingerprints or raw request values.
"""

import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import re
import socket
import ssl
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote_to_bytes


HOST_ENV = "WP3_CAPTURE_HOST"
PORT_ENV = "WP3_CAPTURE_PORT"
TLS_CERT_ENV = "WP3_CAPTURE_TLS_CERT_FILE"
TLS_KEY_ENV = "WP3_CAPTURE_TLS_KEY_FILE"
CLIENT_CA_ENV = "WP3_CAPTURE_CLIENT_CA_FILE"
API_PIN_ENV = "WP3_CAPTURE_API_UPSTREAM_CERT_FILE"
TOKEN_SHA_ENV = "WP3_CAPTURE_EXPECTED_TOKEN_SHA256"
ROUTE_CERT_SHA_ENV = "WP3_CAPTURE_EXPECTED_ROUTE_CERT_SHA256"
DEPARTMENT_ENV = "WP3_CAPTURE_EXPECTED_DEPARTMENT"
ROUTE_ENV = "WP3_CAPTURE_EXPECTED_ROUTE"

API_UPSTREAM_COMMON_NAME = "api-gateway-upstream"
FORWARDED_CERT_HEADER = "X-Client-Cert"
DEPARTMENT_HEADER = "X-Demo-Department"
ROUTE_HEADER = "X-Demo-Route"
CERTIFICATE_BEGIN = b"-----BEGIN CERTIFICATE-----"
CERTIFICATE_END = b"-----END CERTIFICATE-----"
MAX_PUBLIC_CERT_BYTES = 128 * 1024
MAX_CAPTURE_HEADERS = 4096
LOOPBACK_COUNT_PORT = 9444
CLIENT_CERT_STOCK_HEADERS = {
    "pem": "x-client-cert",
    "serial": "x-client-cert-serial",
    "issuer_dn": "x-client-cert-issuer-dn",
    "subject_dn": "x-client-cert-subject-dn",
    "fingerprint": "x-client-cert-fingerprint",
    "chain": "x-client-cert-chain",
}
CLIENT_CERT_SPOOF_SENTINELS = {
    "X-Client-Cert": "WP3-SPOOF-CERT-PEM",
    "X-Client-Cert-Serial": "WP3-SPOOF-CERT-SERIAL",
    "X-Client-Cert-Issuer-DN": "WP3-SPOOF-CERT-ISSUER-DN",
    "X-Client-Cert-Subject-DN": "WP3-SPOOF-CERT-SUBJECT-DN",
    "X-Client-Cert-Fingerprint": "WP3-SPOOF-CERT-FINGERPRINT",
    "X-Client-Cert-Chain": "WP3-SPOOF-CERT-CHAIN",
    "x-cLiEnT-cErT-SuBjEcT-Dn": "WP3-SPOOF-CERT-SUBJECT-CASE",
    "x_client_cert_Fingerprint": "WP3-SPOOF-CERT-FINGERPRINT-UNDERSCORE",
    "X-Client-Cert-UnknownSuffix": "WP3-SPOOF-CERT-UNKNOWN-SUFFIX",
    "x-cLiEnT-cErT-UnknownSuffix": "WP3-SPOOF-CERT-UNKNOWN-CASE",
    "x_client_cert_UnknownAlias": "WP3-SPOOF-CERT-UNKNOWN-UNDERSCORE",
}
CLIENT_CERT_STOCK_HEADER_NAMES = frozenset(CLIENT_CERT_STOCK_HEADERS.values())
CLIENT_CERT_SPOOF_SENTINEL_VALUES = frozenset(CLIENT_CERT_SPOOF_SENTINELS.values())

# The stdlib parser defaults to 100 fields. The isolated Gateway harness also
# checks that rejected 101/1000+ header cases never arrive here, so allow those
# counts to reach the handler without making any Gateway limit decisions.
http.client._MAXHEADERS = MAX_CAPTURE_HEADERS


class ConfigurationError(Exception):
    """A safe, fixed configuration failure with no path or input details."""


@dataclass(frozen=True)
class CaptureConfig:
    host: str
    port: int
    tls_cert_file: Path
    tls_key_file: Path
    client_ca_file: Path
    api_upstream_cert_file: Path
    expected_api_upstream_der: bytes
    expected_token_sha256: bytes | None
    expected_route_cert_sha256: str | None
    expected_department: str | None
    expected_route: str | None

    @classmethod
    def from_env(cls, env=os.environ):
        host = env.get(HOST_ENV, "0.0.0.0")
        try:
            port = int(env.get(PORT_ENV, "9443"), 10)
        except (TypeError, ValueError) as error:
            raise ConfigurationError("invalid listener port") from error
        if not host or not 1 <= port <= 65535:
            raise ConfigurationError("invalid listener address")

        tls_cert_file = required_file_path(env, TLS_CERT_ENV)
        tls_key_file = required_file_path(env, TLS_KEY_ENV)
        client_ca_file = required_file_path(env, CLIENT_CA_ENV)
        api_upstream_cert_file = required_file_path(env, API_PIN_ENV)

        try:
            expected_api_upstream_der = read_single_pem_certificate(
                api_upstream_cert_file
            )
        except (OSError, ValueError, ssl.SSLError) as error:
            raise ConfigurationError("invalid API upstream public certificate pin") from error

        expected_token_sha256 = optional_hex_digest(env, TOKEN_SHA_ENV)
        expected_route_cert_sha256 = optional_base64url_digest(env, ROUTE_CERT_SHA_ENV)
        expected_department = optional_claim_value(env, DEPARTMENT_ENV)
        expected_route = optional_claim_value(env, ROUTE_ENV)

        return cls(
            host=host,
            port=port,
            tls_cert_file=tls_cert_file,
            tls_key_file=tls_key_file,
            client_ca_file=client_ca_file,
            api_upstream_cert_file=api_upstream_cert_file,
            expected_api_upstream_der=expected_api_upstream_der,
            expected_token_sha256=expected_token_sha256,
            expected_route_cert_sha256=expected_route_cert_sha256,
            expected_department=expected_department,
            expected_route=expected_route,
        )


def required_file_path(env, name):
    value = env.get(name)
    if not value:
        raise ConfigurationError("required fixture file is missing")
    path = Path(value)
    try:
        if not path.is_file():
            raise ConfigurationError("required fixture file is invalid")
    except OSError as error:
        raise ConfigurationError("required fixture file is unreadable") from error
    return path


def read_single_pem_certificate(path):
    content = Path(path).read_bytes()
    if not content or len(content) > MAX_PUBLIC_CERT_BYTES:
        raise ValueError("invalid certificate size")
    if content.count(CERTIFICATE_BEGIN) != 1 or content.count(CERTIFICATE_END) != 1:
        raise ValueError("expected one PEM certificate")
    stripped = content.strip()
    if not stripped.startswith(CERTIFICATE_BEGIN) or not stripped.endswith(CERTIFICATE_END):
        raise ValueError("invalid PEM certificate framing")
    encoded = stripped[len(CERTIFICATE_BEGIN) : -len(CERTIFICATE_END)]
    compact = b"".join(encoded.split())
    if not compact:
        raise ValueError("empty PEM certificate")
    base64.b64decode(compact, validate=True)
    # The standard-library decoder gives the same DER representation returned
    # by the upstream TLS socket, without pulling a crypto package into the image.
    return ssl.PEM_cert_to_DER_cert(stripped.decode("ascii"))


def optional_hex_digest(env, name):
    value = env.get(name)
    if value is None or value == "":
        return None
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", value):
        raise ConfigurationError("invalid expected token digest")
    return bytes.fromhex(value)


def optional_base64url_digest(env, name):
    value = env.get(name)
    if value is None or value == "":
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ConfigurationError("invalid expected certificate digest")
    decoded = base64.urlsafe_b64decode(value + "=")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != hashlib.sha256().digest_size or not hmac.compare_digest(canonical, value):
        raise ConfigurationError("invalid expected certificate digest")
    return value


def optional_claim_value(env, name):
    value = env.get(name)
    if value is None or value == "":
        return None
    if len(value) > 256 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ConfigurationError("invalid expected claim value")
    return value


def base64url_sha256(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode("ascii")


def text_equal(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except UnicodeEncodeError:
        return False


def safe_header_values(headers, name):
    values = headers.get_all(name)
    return list(values) if values else []


def duplicate_field_count(names):
    counts = {}
    for name in names:
        lowered = name.lower()
        counts[lowered] = counts.get(lowered, 0) + 1
    return sum(count - 1 for count in counts.values() if count > 1)


def fingerprint_matches_der(value, der):
    if not isinstance(value, str):
        return False
    compact = value.strip().replace(":", "").replace("-", "")
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", compact):
        return False
    try:
        observed = bytes.fromhex(compact)
    except ValueError:
        return False
    expected = hashlib.sha1(der).digest()
    return hmac.compare_digest(observed, expected)


def normalized_header_name(name):
    return name.lower().replace("_", "-")


def decode_forwarded_leaf(encoded_values):
    """Return only (valid, DER bytes, percent-encoded); never return PEM text."""
    if len(encoded_values) != 1:
        return False, None, False
    value = encoded_values[0]
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False, None, False
    if not encoded or re.search(rb"%(?![0-9A-Fa-f]{2})", encoded):
        return False, None, False
    percent_encoded = bool(re.search(rb"%[0-9A-Fa-f]{2}", encoded))
    if not percent_encoded:
        return False, None, False
    try:
        pem = unquote_to_bytes(encoded)
        der = pem_bytes_to_der(pem)
    except (ValueError, UnicodeError, ssl.SSLError):
        return False, None, percent_encoded
    return True, der, percent_encoded


def pem_bytes_to_der(pem):
    if not isinstance(pem, bytes) or not pem or len(pem) > MAX_PUBLIC_CERT_BYTES:
        raise ValueError("invalid PEM size")
    if pem.count(CERTIFICATE_BEGIN) != 1 or pem.count(CERTIFICATE_END) != 1:
        raise ValueError("expected one PEM certificate")
    stripped = pem.strip()
    if not stripped.startswith(CERTIFICATE_BEGIN) or not stripped.endswith(CERTIFICATE_END):
        raise ValueError("invalid PEM certificate framing")
    encoded = stripped[len(CERTIFICATE_BEGIN) : -len(CERTIFICATE_END)]
    compact = b"".join(encoded.split())
    if not compact:
        raise ValueError("empty PEM certificate")
    base64.b64decode(compact, validate=True)
    return ssl.PEM_cert_to_DER_cert(stripped.decode("ascii"))


def common_name_from_peer_info(peer_info):
    if not isinstance(peer_info, dict):
        return None
    values = []
    for relative_names in peer_info.get("subject", ()):
        for key, value in relative_names:
            if key == "commonName" and isinstance(value, str):
                values.append(value)
    return values[0] if len(values) == 1 else None


def api_peer_identity_matches(peer_der, peer_info, expected_der):
    pin_matches = bool(peer_der) and hmac.compare_digest(peer_der, expected_der)
    common_name = common_name_from_peer_info(peer_info)
    cn_matches = text_equal(common_name, API_UPSTREAM_COMMON_NAME)
    return pin_matches and cn_matches, pin_matches, cn_matches


def summarize_request_headers(headers, config):
    names = [name for name, _ in headers.raw_items()]
    normalized_names = [normalized_header_name(name) for name in names]
    x_fapi_names = [name for name in normalized_names if name.startswith("x-fapi-")]
    x_demo_names = [name for name in normalized_names if name.startswith("x-demo-")]
    x_client_cert_names = [
        name for name in normalized_names if name.startswith("x-client-cert")
    ]
    client_assertion_names = [
        name for name in normalized_names if name.startswith("client-assertion")
    ]
    x_fapi_underscore_count = sum(
        1
        for original, normalized in zip(names, normalized_names)
        if normalized.startswith("x-fapi-") and "_" in original
    )
    x_demo_underscore_count = sum(
        1
        for original, normalized in zip(names, normalized_names)
        if normalized.startswith("x-demo-") and "_" in original
    )
    x_client_cert_underscore_count = sum(
        1
        for original, normalized in zip(names, normalized_names)
        if normalized.startswith("x-client-cert") and "_" in original
    )
    exact_client_cert_values = safe_header_values(headers, FORWARDED_CERT_HEADER)
    cert_valid, route_der, cert_percent_encoded = decode_forwarded_leaf(
        exact_client_cert_values
    )
    stock_detail_counts = {
        key: len(safe_header_values(headers, name))
        for key, name in CLIENT_CERT_STOCK_HEADERS.items()
        if key != "pem"
    }
    unexpected_x_client_cert_count = sum(
        1 for name in x_client_cert_names if name not in CLIENT_CERT_STOCK_HEADER_NAMES
    )
    x_client_cert_duplicate_count = duplicate_field_count(x_client_cert_names)
    caller_spoof_sentinel_match_count = sum(
        sum(
            1
            for sentinel in CLIENT_CERT_SPOOF_SENTINEL_VALUES
            if sentinel.casefold() in value.casefold()
        )
        for _name, value in headers.raw_items()
    )
    fingerprint_values = safe_header_values(headers, "X-Client-Cert-Fingerprint")
    fingerprint_matches_leaf = (
        cert_valid
        and len(fingerprint_values) == 1
        and fingerprint_matches_der(fingerprint_values[0], route_der)
    )

    authorization_values = safe_header_values(headers, "Authorization")
    bearer_token = None
    if len(authorization_values) == 1:
        authorization = authorization_values[0]
        scheme, separator, credential = authorization.partition(" ")
        if (
            separator
            and scheme.lower() == "bearer"
            and credential
            and not any(char.isspace() for char in credential)
        ):
            try:
                credential.encode("ascii")
                bearer_token = credential
            except UnicodeEncodeError:
                bearer_token = None

    actual_token_sha256 = (
        hashlib.sha256(bearer_token.encode("ascii")).digest()
        if bearer_token is not None
        else None
    )
    token_matches_expected = None
    if actual_token_sha256 is not None and config.expected_token_sha256 is not None:
        token_matches_expected = hmac.compare_digest(
            actual_token_sha256, config.expected_token_sha256
        )

    route_thumbprint = base64url_sha256(route_der) if cert_valid else None
    route_cert_matches_expected = None
    if route_thumbprint is not None and config.expected_route_cert_sha256 is not None:
        route_cert_matches_expected = text_equal(
            route_thumbprint, config.expected_route_cert_sha256
        )

    department_values = safe_header_values(headers, DEPARTMENT_HEADER)
    route_values = safe_header_values(headers, ROUTE_HEADER)
    department_matches_expected = None
    if config.expected_department is not None:
        department_matches_expected = (
            len(department_values) == 1
            and text_equal(department_values[0], config.expected_department)
        )
    route_matches_expected = None
    if config.expected_route is not None:
        route_matches_expected = (
            len(route_values) == 1 and text_equal(route_values[0], config.expected_route)
        )

    unexpected_x_demo_count = sum(
        1
        for name in x_demo_names
        if name not in {DEPARTMENT_HEADER.lower(), ROUTE_HEADER.lower()}
    )
    cookie_count = len(safe_header_values(headers, "Cookie"))
    assertion_count = len(safe_header_values(headers, "client_assertion"))
    assertion_type_count = len(safe_header_values(headers, "client_assertion_type"))
    client_assertion_unknown_suffix_count = sum(
        1
        for name in client_assertion_names
        if name not in {"client-assertion", "client-assertion-type"}
    )

    return {
        "request_header_count": len(names),
        "authorization_header_count": len(authorization_values),
        "authorization_single_bearer": bearer_token is not None,
        # These fingerprints exist only in the private, mTLS-protected response
        # for the WP3 harness to compare in memory. The helper never logs them.
        "authorization_sha256": (
            actual_token_sha256.hex() if actual_token_sha256 is not None else None
        ),
        "authorization_matches_expected_token": token_matches_expected,
        "cookie_header_count": cookie_count,
        "cookie_absent": cookie_count == 0,
        "client_assertion_header_count": assertion_count,
        "client_assertion_type_header_count": assertion_type_count,
        "client_assertion_like_header_count": len(client_assertion_names),
        "client_assertion_unknown_suffix_header_count": client_assertion_unknown_suffix_count,
        "client_assertion_headers_absent": len(client_assertion_names) == 0,
        "x_fapi_header_count": len(x_fapi_names),
        "x_fapi_duplicate_header_count": duplicate_field_count(x_fapi_names),
        "x_fapi_underscore_prefix_count": x_fapi_underscore_count,
        "x_fapi_headers_absent": len(x_fapi_names) == 0,
        "x_demo_header_count": len(x_demo_names),
        "x_demo_duplicate_header_count": duplicate_field_count(x_demo_names),
        "x_demo_underscore_prefix_count": x_demo_underscore_count,
        "x_demo_unexpected_header_count": unexpected_x_demo_count,
        "x_demo_unexpected_headers_absent": (
            unexpected_x_demo_count == 0 and x_demo_underscore_count == 0
        ),
        "department_header_count": len(department_values),
        "department_header_matches_expected_claim": department_matches_expected,
        "route_header_count": len(route_values),
        "route_header_matches_expected_claim": route_matches_expected,
        "x_client_cert_like_header_count": len(x_client_cert_names),
        "x_client_cert_unknown_suffix_header_count": unexpected_x_client_cert_count,
        "x_client_cert_duplicate_header_count": x_client_cert_duplicate_count,
        "x_client_cert_underscore_alias_count": x_client_cert_underscore_count,
        "x_client_cert_stock_detail_counts": stock_detail_counts,
        "x_client_cert_stock_details_complete": (
            len(exact_client_cert_values) == 1
            and all(count == 1 for count in stock_detail_counts.values())
        ),
        "x_client_cert_fingerprint_matches_forwarded_leaf": fingerprint_matches_leaf,
        "caller_spoof_sentinel_match_count": caller_spoof_sentinel_match_count,
        "x_client_cert_header_count": len(exact_client_cert_values),
        "forwarded_certificate_single_url_encoded_pem_leaf": cert_valid and cert_percent_encoded,
        "forwarded_certificate_thumbprint_prefix12": (
            route_thumbprint[:12] if route_thumbprint is not None else None
        ),
        "forwarded_certificate_thumbprint": route_thumbprint,
        "forwarded_certificate_matches_expected_route": route_cert_matches_expected,
    }


class QuietCaptureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler_class, config):
        super().__init__(address, handler_class)
        self.capture_config = config
        self._request_count = 0
        self._request_count_lock = threading.Lock()

    def next_request_count(self):
        with self._request_count_lock:
            self._request_count += 1
            return self._request_count

    def current_request_count(self):
        with self._request_count_lock:
            return self._request_count

    def handle_error(self, request, client_address):
        # TLS alerts and parse failures must never dump request or certificate data.
        return


class LoopbackCountHandler(http.server.BaseHTTPRequestHandler):
    """Container-local observer; never bound to the Compose network interface."""

    server_version = "WP3-Count/1"
    sys_version = ""

    def do_GET(self):
        if self.path != "/count":
            self.send_error(404)
            return
        count = self.server.capture_server.current_request_count()
        data = json.dumps({"request_count": count}, separators=(",", ":")).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def log_message(self, format, *args):
        return

    def log_error(self, format, *args):
        return


def build_loopback_count_server(capture_server, port=LOOPBACK_COUNT_PORT):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), LoopbackCountHandler)
    server.capture_server = capture_server
    server.daemon_threads = True
    return server


class CaptureHandler(BaseHTTPRequestHandler):
    server_version = "WP3-Capture/1"
    sys_version = ""

    def _send_json(self, status, payload):
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _pinned_api_peer(self):
        try:
            peer_der = self.connection.getpeercert(binary_form=True)
            peer_info = self.connection.getpeercert()
        except (OSError, ssl.SSLError):
            return False, False, False
        return api_peer_identity_matches(
            peer_der,
            peer_info,
            self.server.capture_config.expected_api_upstream_der,
        )

    def _peer_gate(self):
        peer_allowed, _, _ = self._pinned_api_peer()
        if not peer_allowed:
            self._send_json(401, {"error": "request_rejected"})
            return False
        return True

    @staticmethod
    def _is_evidence_target(request_target):
        return (
            isinstance(request_target, str)
            and (request_target == "/evidence" or request_target.startswith("/evidence?"))
        )

    def do_GET(self):
        if not self._peer_gate():
            return
        if self.path == "/healthz":
            _, pin_matches, cn_matches = self._pinned_api_peer()
            self._send_json(
                200,
                {
                    "status": "ok",
                    "api_peer_pin_matches": pin_matches,
                    "api_peer_common_name_matches": cn_matches,
                    "request_count": self.server.current_request_count(),
                },
            )
            return
        if not self._is_evidence_target(self.path):
            self._send_json(404, {"error": "not_found"})
            return

        request_count = self.server.next_request_count()
        evidence = summarize_request_headers(self.headers, self.server.capture_config)
        evidence.update(
            {
                "status": "captured",
                "api_peer_pin_matches": True,
                "api_peer_common_name_matches": True,
                "request_count": request_count,
            }
        )
        self._send_json(200, evidence)

    def send_error(self, code, message=None, explain=None):
        # Generic parser/method failures are also gated by the exact peer pin.
        if not self._peer_gate():
            return
        status = code if isinstance(code, int) and 400 <= code <= 599 else 400
        self._send_json(status, {"error": "request_rejected"})

    def handle_expect_100(self):
        if not self._peer_gate():
            return False
        self._send_json(405, {"error": "request_rejected"})
        return False

    def log_message(self, format, *args):
        return

    def log_error(self, format, *args):
        return


def build_server_context(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(config.client_ca_file))
    context.load_cert_chain(
        certfile=str(config.tls_cert_file), keyfile=str(config.tls_key_file)
    )
    return context


def serve(config):
    context = build_server_context(config)
    server = QuietCaptureServer(
        (config.host, config.port), CaptureHandler, config
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    count_server = build_loopback_count_server(server)
    count_thread = threading.Thread(target=count_server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    count_thread.start()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        count_server.shutdown()
        count_server.server_close()
        count_thread.join(timeout=3)
        server.server_close()
        if count_thread.is_alive():
            raise RuntimeError("local count observer did not stop")


def main():
    try:
        config = CaptureConfig.from_env()
        serve(config)
    except KeyboardInterrupt:
        return 0
    except Exception:
        # Do not expose paths, exception text, headers, certificates, or key data.
        print("WP3 capture server failed closed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
