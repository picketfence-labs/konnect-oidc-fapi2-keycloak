#!/usr/bin/env python3
"""Isolated stock OIDC PAR/revocation capture relay for WP5 5a (test-only)."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


ISSUER = "https://localhost:8444/realms/fapi-demo"
CLIENT_ID = "kong-fapi-pkj-mtls"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
PAR_PATH = "/realms/fapi-demo/protocol/openid-connect/ext/par/request"
REVOKE_PATH = "/realms/fapi-demo/protocol/openid-connect/revoke"
TOKEN_HINTS = frozenset({"access_token", "refresh_token"})
ID_RE = re.compile(r"[0-9a-f]{32}\Z")
MAX_BODY = 128 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_EVENTS = 32
MAX_REQUEST_SECONDS = 10
PAR_SUCCESS = frozenset({201})
REVOKE_SUCCESS = frozenset({200})
EVENT_FIELDS = (
    "operation_id", "operation", "stage", "endpoint", "method", "path",
    "algorithm", "audience_is_issuer", "issuer_subject_match", "ttl_seconds",
    "remaining_ttl_seconds", "jti_distinct", "stock_form_client_id_present", "token_kind", "relay_attempted", "forwarded",
    "token_distinct", "http_status", "oauth_error_enum", "result",
)
OAUTH_ERROR_ENUMS = frozenset({
    "invalid_client", "invalid_request", "invalid_grant", "unauthorized_client",
    "unsupported_grant_type", "unsupported_response_type", "invalid_scope", "access_denied",
    "server_error", "temporarily_unavailable", "unknown",
})
PAR_FORM_FIELDS = frozenset({
    "client_id", "client_assertion_type", "client_assertion", "response_type",
    "redirect_uri", "scope", "state", "nonce", "code_challenge",
    "code_challenge_method", "response_mode",
})
REVOKE_FORM_FIELDS = frozenset({
    "client_id", "client_assertion_type", "client_assertion", "token", "token_type_hint",
})


class RelayError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise RelayError("assertion_encoding")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise RelayError("assertion_encoding") from None


def _json_unique(raw: bytes) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RelayError("assertion_duplicate_json_key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except RelayError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise RelayError("assertion_json") from None
    if not isinstance(value, dict):
        raise RelayError("assertion_json")
    return value


def _load_public_key(path: Path):
    try:
        key = load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError):
        raise RelayError("public_key_unavailable") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise RelayError("public_key_type")
    return key


def verify_stock_assertion(
    token: str,
    public_key,
    expected_kid: str,
    *,
    now: int | None = None,
    minimum_remaining: int = 5,
) -> dict[str, Any]:
    """Verify PS256 and return a summary; the internal jti stays memory-only."""
    if not isinstance(token, str) or len(token) > 16384:
        raise RelayError("assertion_size")
    parts = token.split(".")
    if len(parts) != 3:
        raise RelayError("assertion_shape")
    header = _json_unique(_b64url_decode(parts[0]))
    claims = _json_unique(_b64url_decode(parts[1]))
    signature = _b64url_decode(parts[2])
    if header.get("alg") != "PS256" or header.get("kid") != expected_kid:
        raise RelayError("assertion_header")
    if any(name in header for name in ("jku", "x5u", "crit")):
        raise RelayError("assertion_header")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    try:
        public_key.verify(
            signature,
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except Exception:
        raise RelayError("assertion_signature") from None

    iss = claims.get("iss")
    sub = claims.get("sub")
    aud = claims.get("aud")
    iat = claims.get("iat")
    exp = claims.get("exp")
    jti = claims.get("jti")
    if iss != CLIENT_ID or sub != CLIENT_ID:
        raise RelayError("assertion_identity")
    if aud != ISSUER or not isinstance(aud, str):
        raise RelayError("assertion_audience")
    if type(iat) is not int or type(exp) is not int or not isinstance(jti, str) or not jti or len(jti) > 128:
        raise RelayError("assertion_time_or_id")
    ttl = exp - iat
    current = int(time.time()) if now is None else now
    remaining = exp - current
    if ttl <= 0 or ttl > 60 or remaining < minimum_remaining:
        raise RelayError("assertion_ttl")
    if iat > current:
        raise RelayError("assertion_future_iat")
    return {
        "algorithm": "PS256",
        "audience_is_issuer": True,
        "issuer_subject_match": True,
        "ttl_seconds": ttl,
        "remaining_ttl_seconds": remaining,
        "jti": jti,
    }


def parse_stock_form(raw: bytes, content_type: str, operation: str) -> tuple[str, str | None, bytes | None, bool]:
    if (len(raw) > MAX_BODY or not isinstance(content_type, str) or len(content_type) > 128
        or not content_type.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in content_type)
        or content_type.split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded"):
        raise RelayError("form_contract")
    try:
        text = raw.decode("ascii")
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True, strict_parsing=True, max_num_fields=64)
    except (UnicodeDecodeError, ValueError):
        raise RelayError("form_contract") from None
    fields: dict[str, list[str]] = {}
    for key, value in pairs:
        fields.setdefault(key, []).append(value)
    if any(len(values) != 1 for values in fields.values()):
        raise RelayError("duplicate_form_parameter")
    assertions = fields.get("client_assertion", [])
    assertion_types = fields.get("client_assertion_type", [])
    if len(assertions) != 1 or assertion_types != [ASSERTION_TYPE]:
        raise RelayError("assertion_form")
    if operation == "par":
        if not fields.keys() <= PAR_FORM_FIELDS:
            raise RelayError("par_unknown_field")
        client_id_present = "client_id" in fields
        if client_id_present and fields["client_id"] != [CLIENT_ID]:
            raise RelayError("par_client_id")
        if fields.get("response_type") != ["code"]:
            raise RelayError("par_response_type")
        if "response_mode" in fields and fields["response_mode"] != ["query"]:
            raise RelayError("par_response_mode")
        return assertions[0], None, None, client_id_present
    if operation != "revoke":
        raise RelayError("operation")
    hints = fields.get("token_type_hint", [])
    tokens = fields.get("token", [])
    if len(tokens) != 1 or len(hints) != 1 or hints[0] not in TOKEN_HINTS:
        raise RelayError("revoke_form")
    token = tokens[0]
    if not re.fullmatch(r"[A-Za-z0-9._~+/-]{1,8192}", token):
        raise RelayError("revoke_form")
    if not fields.keys() <= REVOKE_FORM_FIELDS:
        raise RelayError("revoke_form")
    client_id_present = "client_id" in fields
    if client_id_present and fields["client_id"] != [CLIENT_ID]:
        raise RelayError("revoke_form")
    return assertions[0], hints[0], hashlib.sha256(token.encode("ascii")).digest(), client_id_present


def _relay_context(ca: Path, cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca))
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    context.keylog_filename = None
    context.set_alpn_protocols(["http/1.1"])
    return context


def relay_once(
    raw_body: bytes,
    operation: str,
    operation_id: str,
    paths: dict[str, Path],
    content_type: str,
    assertion: str,
    public_key,
    expected_kid: str,
) -> tuple[int, list[tuple[str, str]], bytes]:
    if not ID_RE.fullmatch(operation_id):
        raise RelayError("operation_id")
    path = PAR_PATH if operation == "par" else REVOKE_PATH if operation == "revoke" else None
    if path is None:
        raise RelayError("operation")
    deadline = time.monotonic() + MAX_REQUEST_SECONDS
    raw_socket: socket.socket | None = None
    sock: ssl.SSLSocket | None = None
    timer: threading.Timer | None = None

    def interrupt() -> None:
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RelayError("as_deadline_exceeded")
        raw_socket = socket.create_connection(("keycloak", 8443), timeout=remaining)
        raw_socket.settimeout(max(0.001, deadline - time.monotonic()))
        context = _relay_context(paths["ca"], paths["route_cert"], paths["route_key"])
        sock = context.wrap_socket(raw_socket, server_hostname="keycloak")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RelayError("as_deadline_exceeded")
        sock.settimeout(remaining)
        timer = threading.Timer(remaining, interrupt)
        timer.daemon = True
        timer.start()
        verify_stock_assertion(assertion, public_key, expected_kid)
        request = (
            f"POST {path} HTTP/1.1\r\n"
            "Host: keycloak:8443\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(raw_body)}\r\n"
            f"X-Fapi-Demo-Observation-ID: {operation_id}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request + raw_body)
        response = http.client.HTTPResponse(sock, method="POST")
        response.begin()
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise RelayError("as_response_too_large")
        headers = []
        allowed = {"content-type", "cache-control", "pragma", "expires", "date", "www-authenticate"}
        for name, value in response.getheaders():
            if name.lower() in allowed and "\r" not in value and "\n" not in value:
                headers.append((name, value))
        return response.status, headers, body
    except RelayError:
        raise
    except Exception:
        raise RelayError("as_transport_failure") from None
    finally:
        if timer is not None:
            timer.cancel()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        elif raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass


def _oauth_error_enum(body: bytes, status: int, operation: str) -> str:
    accepted = PAR_SUCCESS if operation == "par" else REVOKE_SUCCESS
    if status in accepted:
        return "none"
    try:
        value = _json_unique(body)
    except RelayError:
        return "unknown"
    error = value.get("error")
    return error if isinstance(error, str) and error in OAUTH_ERROR_ENUMS else "unknown"


class RelayState:
    def __init__(self, root: Path):
        self.paths = {
            "ca": root / "ca/ca.crt",
            "route_cert": root / "tls/route-b.crt",
            "route_key": root / "tls/route-b.key",
            "server_cert": root / "tls/harness.crt",
            "server_key": root / "tls/harness.key",
            "public_key": root / "keys/route-b-public.pem",
            "kid": root / "keys/route-b-kid.txt",
        }
        self.public_key = _load_public_key(self.paths["public_key"])
        self.kid = self.paths["kid"].read_text(encoding="ascii").strip()
        self.seen_jti: set[str] = set()
        self.seen_revoke_token_digests: set[bytes] = set()
        self.seen_revoke_kinds: set[str] = set()
        self.par_claim_reserved = False
        self.events: list[dict[str, Any]] = []
        self.in_flight = 0
        self.lock = threading.Lock()
        self.stage = "par_claim_gate"
        self.failed = False
        self.overflow = False

    def process(self, operation: str, raw: bytes, content_type: str) -> tuple[int, list[tuple[str, str]], bytes]:
        with self.lock:
            if self.failed or self.overflow:
                return 400, [("Content-Type", "application/json")], b'{"error":"invalid_request"}'
            if len(self.events) + self.in_flight >= MAX_EVENTS:
                self.failed = True
                self.overflow = True
                return 400, [("Content-Type", "application/json")], b'{"error":"invalid_request"}'
            if (operation == "par" and self.stage != "par_claim_gate") or (
                operation == "revoke" and self.stage != "session_logout"
            ):
                self.failed = True
                return 400, [("Content-Type", "application/json")], b'{"error":"invalid_request"}'
            self.in_flight += 1
        path = PAR_PATH if operation == "par" else REVOKE_PATH
        event: dict[str, Any] = {
            "operation_id": secrets.token_hex(16),
            "operation": operation,
            "stage": self.stage,
            "endpoint": operation,
            "method": "POST",
            "path": path,
            "algorithm": "unknown",
            "audience_is_issuer": False,
            "issuer_subject_match": False,
            "ttl_seconds": 0,
            "remaining_ttl_seconds": 0,
            "jti_distinct": False,
            "stock_form_client_id_present": False,
            "token_kind": "not_applicable",
            "token_distinct": True if operation == "par" else False,
            "relay_attempted": False,
            "forwarded": False,
            "http_status": 0,
            "oauth_error_enum": "none",
            "result": "pending",
        }
        try:
            token, token_kind, token_digest, client_id_present = parse_stock_form(raw, content_type, operation)
            event["stock_form_client_id_present"] = client_id_present
            summary = verify_stock_assertion(token, self.public_key, self.kid)
            event.update({key: value for key, value in summary.items() if key != "jti"})
            event["token_kind"] = token_kind or "not_applicable"
            jti = summary["jti"]
            with self.lock:
                if jti in self.seen_jti:
                    raise RelayError("assertion_replay")
                self.seen_jti.add(jti)
                if operation == "par":
                    if self.par_claim_reserved:
                        raise RelayError("par_replay")
                    self.par_claim_reserved = True
                else:
                    if token_digest in self.seen_revoke_token_digests:
                        raise RelayError("revoke_token_replay")
                    if token_kind in self.seen_revoke_kinds:
                        raise RelayError("revoke_kind_replay")
                    self.seen_revoke_token_digests.add(token_digest)
                    self.seen_revoke_kinds.add(token_kind)
            event["jti_distinct"] = True
            event["token_distinct"] = True
            event["relay_attempted"] = True
            status, headers, body = relay_once(
                raw, operation, event["operation_id"], self.paths, content_type,
                token, self.public_key, self.kid,
            )
            event["forwarded"] = True
            event["http_status"] = status
            event["oauth_error_enum"] = _oauth_error_enum(body, status, operation)
            accepted = PAR_SUCCESS if operation == "par" else REVOKE_SUCCESS
            event["result"] = "as_accepted" if status in accepted else "as_rejected"
            if status not in accepted:
                self.failed = True
            if operation == "par" and status in PAR_SUCCESS:
                self.stage = "par_complete"
            return status, headers, body
        except RelayError as error:
            event["result"] = error.code
            self.failed = True
            return 400, [("Content-Type", "application/json")], b'{"error":"invalid_request"}'
        except Exception:
            event["result"] = "internal_failure"
            self.failed = True
            return 400, [("Content-Type", "application/json")], b'{"error":"invalid_request"}'
        finally:
            with self.lock:
                self.in_flight = max(0, self.in_flight - 1)
                if len(self.events) < MAX_EVENTS:
                    self.events.append({key: event[key] for key in EVENT_FIELDS})
                else:
                    self.failed = True
                    self.overflow = True

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "stage": self.stage,
                "failed": self.failed,
                "overflow": self.overflow,
                "events": list(self.events),
            }

    def advance_to_session_logout(self) -> bool:
        """Allow fixture revocations only after one accepted PAR and one session callback."""
        with self.lock:
            if (self.failed or self.overflow or self.in_flight != 0 or self.stage != "par_complete"
                or len(self.events) != 1 or self.events[0].get("operation") != "par"
                or self.events[0].get("result") != "as_accepted" or self.events[0].get("http_status") != 201):
                return False
            self.stage = "session_logout"
            return True


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "WP5StockRelay"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self._deadline_timer = threading.Timer(MAX_REQUEST_SECONDS, self._interrupt_client)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def _interrupt_client(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        timer = getattr(self, "_deadline_timer", None)
        if timer is not None:
            timer.cancel()
        super().finish()

    def do_GET(self):
        if self.path == "/_status":
            body = json.dumps(self.server.state.snapshot(), sort_keys=True, separators=(",", ":")).encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/health":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        self._fixed_error(404)

    def do_POST(self):
        if self.path == "/_control/session-ready":
            if self.headers.get("Transfer-Encoding") is not None or self.headers.get("Content-Length") != "0":
                self._fixed_error(400)
                return
            if not self.server.state.advance_to_session_logout():
                self._fixed_error(409)
                return
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        operation = {" /par": "par", " /revoke": "revoke"}.get(" " + self.path)
        if operation is None:
            self._fixed_error(404)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._fixed_error(400)
            return
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isdigit() or len(raw_length) > 8:
            self._fixed_error(400)
            return
        length = int(raw_length)
        if length > MAX_BODY:
            self._fixed_error(413)
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._fixed_error(400)
            return
        status, headers, body = self.server.state.process(
            operation, raw, self.headers.get("Content-Type", ""),
        )
        self.send_response(status)
        for name, value in headers:
            if name.lower() not in {"content-length", "connection", "transfer-encoding"}:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def _fixed_error(self, status: int):
        body = b'{"error":"invalid_request"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *_args):
        return


def _serve_tls(server: ThreadingHTTPServer, cert: Path, key: Path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)


def serve(root: Path):
    state = RelayState(root)
    relay_server = ThreadingHTTPServer(("0.0.0.0", 9443), RelayHandler)
    relay_server.state = state
    _serve_tls(relay_server, state.paths["server_cert"], state.paths["server_key"])
    thread = threading.Thread(target=relay_server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    finally:
        relay_server.shutdown()
        relay_server.server_close()


def main():
    root = Path(os.environ.get("WP5_STOCK_ROOT", "/run/wp5-stock"))
    serve(root)


if __name__ == "__main__":
    main()
