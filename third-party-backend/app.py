#!/usr/bin/env python3
"""Fixed-destination business API client behind the third-party Kong."""

import hmac
import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import socketserver
import ssl
import stat
import threading
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import MappingProxyType


API_HOST = "kong-api"
API_PORT = 8443
API_PATH = "/fapi-api/evidence"
UPSTREAM_TIMEOUT = 5
MAX_RESPONSE_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 8192
ROUTES = MappingProxyType({
    "/evidence/route-a": ("route-a", "third-party-fapi-mtls", "tls_client_auth"),
    "/evidence/route-b": ("route-b", "third-party-fapi-pkj-mtls", "private_key_jwt"),
})
TEXT_FIELDS = ("department", "logical_route", "department_header", "logical_route_header")
THUMBPRINT_FIELDS = (
    "token_certificate_thumbprint", "forwarded_client_certificate_thumbprint",
    "api_gateway_tls_peer_certificate_thumbprint",
)


class RejectedEvidence(ValueError):
    pass


@dataclass(frozen=True)
class TLSFiles:
    ca: str = "/etc/fapi/ca.crt"
    certificate: str = "/etc/fapi/tls.crt"
    key: str = "/etc/fapi/tls.key"
    gateway_pin: str = "/etc/fapi/third-party-backend-hop.crt"
    route_a_certificate: str = "/etc/fapi/route-a.crt"
    route_a_key: str = "/etc/fapi/route-a.key"
    route_b_certificate: str = "/etc/fapi/route-b.crt"
    route_b_key: str = "/etc/fapi/route-b.key"

    @classmethod
    def from_environment(cls):
        # Only local TLS file locations are configurable. No URL/host override.
        return cls(**{
            name: os.environ.get("BACKEND_TLS_" + name.upper(), field.default)
            for name, field in cls.__dataclass_fields__.items()
        })


def verified_context(purpose, ca):
    context = ssl.create_default_context(purpose, cafile=ca)
    # Match the verifier's compatibility with the existing development CA.
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def create_contexts(files):
    inbound = verified_context(ssl.Purpose.CLIENT_AUTH, files.ca)
    inbound.verify_mode = ssl.CERT_REQUIRED
    inbound.load_cert_chain(files.certificate, files.key)
    outbound = {}
    for route, certificate, key in (
        ("route-a", files.route_a_certificate, files.route_a_key),
        ("route-b", files.route_b_certificate, files.route_b_key),
    ):
        context = verified_context(ssl.Purpose.SERVER_AUTH, files.ca)
        context.load_cert_chain(certificate, key)
        outbound[route] = context
    pin = ssl.PEM_cert_to_DER_cert(Path(files.gateway_pin).read_text(encoding="ascii"))
    if not pin:
        raise ValueError("missing gateway certificate pin")
    return inbound, MappingProxyType(outbound), pin


def trusted_peer(peer, pin):
    return bool(peer and pin and hmac.compare_digest(peer, pin))


def bearer_token(headers):
    values = headers.get_all("Authorization", [])
    if len(values) != 1 or len(values[0]) > MAX_TOKEN_BYTES + 7:
        return None
    match = re.fullmatch(r"(?i:Bearer) ([A-Za-z0-9\-._~+/]+=*)", values[0])
    return match.group(1) if match else None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RejectedEvidence("duplicate field")
        result[key] = value
    return result


def project_evidence(body, expected):
    try:
        source = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise RejectedEvidence("invalid JSON") from error
    if not isinstance(source, dict):
        raise RejectedEvidence("invalid object")
    result = {}
    for name, value in zip(("route", "azp", "client_authentication"), expected):
        if source.get(name) != value:
            raise RejectedEvidence("wrong route identity")
        result[name] = value
    for name in TEXT_FIELDS:
        value = source.get(name)
        if name not in source or (value is not None and (
            not isinstance(value, str) or len(value) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        )):
            raise RejectedEvidence("invalid text")
        result[name] = value
    for name in THUMBPRINT_FIELDS:
        value = source.get(name)
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
            raise RejectedEvidence("invalid thumbprint")
        result[name] = value
    for name in ("token_signature_verified", "binding_verified", "header_claims_match"):
        value = source.get(name)
        if type(value) is not bool or (name != "header_claims_match" and value is not True):
            raise RejectedEvidence("invalid verification")
        result[name] = value
    if result["token_certificate_thumbprint"] != result["forwarded_client_certificate_thumbprint"]:
        raise RejectedEvidence("inconsistent binding")
    if result["header_claims_match"] and (
        not all(result[name] for name in TEXT_FIELDS)
        or result["department"] != result["department_header"]
        or result["logical_route"] != result["logical_route_header"]
    ):
        raise RejectedEvidence("inconsistent headers")
    return result


def fetch_evidence(token, expected, context):
    connection = http.client.HTTPSConnection(
        API_HOST, API_PORT, timeout=UPSTREAM_TIMEOUT, context=context,
    )
    try:
        connection.putrequest("GET", API_PATH, skip_accept_encoding=True)
        connection.putheader("Authorization", "Bearer " + token)
        connection.putheader("Accept", "application/json")
        connection.endheaders()
        response = connection.getresponse()
        if response.status in (401, 403):
            return response.status, {"error": "upstream_unauthorized"}
        if response.status != 200:
            return 502, {"error": "upstream_unavailable"}
        content_types = response.headers.get_all("Content-Type", [])
        lengths = response.headers.get_all("Content-Length", [])
        if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise RejectedEvidence("invalid content type")
        if lengths and (len(lengths) != 1 or len(lengths[0]) > 10 or not re.fullmatch(r"[0-9]+", lengths[0])
                        or int(lengths[0]) > MAX_RESPONSE_BYTES):
            raise RejectedEvidence("invalid length")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES or (lengths and len(body) != int(lengths[0])):
            raise RejectedEvidence("invalid body size")
        return 200, project_evidence(body, expected)
    except (socket.timeout, TimeoutError):
        return 504, {"error": "upstream_timeout"}
    except (OSError, http.client.HTTPException, RejectedEvidence):
        return 502, {"error": "upstream_unavailable"}
    finally:
        connection.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "third-party-backend/0.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(UPSTREAM_TIMEOUT)

    def json_response(self, status, body):
        data = json.dumps(body, separators=(",", ":"), allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self.json_response(code, {"error": "request_rejected"})

    def do_GET(self):
        if not trusted_peer(self.connection.getpeercert(binary_form=True), self.server.gateway_pin):
            return self.json_response(401, {"error": "untrusted_gateway"})
        if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Length", ["0"]) != ["0"]:
            return self.json_response(400, {"error": "request_rejected"})
        if self.path == "/healthz":
            return self.json_response(200, {"status": "ok"})
        expected = ROUTES.get(self.path)
        if expected is None:
            return self.json_response(404, {"error": "not_found"})
        token = bearer_token(self.headers)
        if token is None:
            return self.json_response(401, {"error": "invalid_token"})
        status, result = fetch_evidence(token, expected, self.server.route_contexts[expected[0]])
        self.json_response(status, result)

    def log_message(self, message, *args):
        return


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        return


def create_server(host="0.0.0.0", port=9444, files=None):
    context, routes, pin = create_contexts(files or TLSFiles.from_environment())
    server = QuietServer((host, port), Handler)
    server.gateway_pin = pin
    server.route_contexts = routes
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


READY_SOCKET = "/run/fapi/ready.sock"


def public_config_hash(files):
    public = {name: hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(getattr(files, name)).read_text(encoding="ascii"))).hexdigest()
              for name in ("ca", "certificate", "gateway_pin", "route_a_certificate", "route_b_certificate")}
    public["target"] = [API_HOST, API_PORT, API_PATH]
    public["routes"] = dict(ROUTES)
    return hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_ready_status(value):
    if not isinstance(value, dict) or set(value) != {"schema_version", "ready", "generation", "config_sha256", "pid"}:
        raise ValueError("invalid readiness status")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["ready"] is not True \
        or type(value["pid"]) is not int or value["pid"] <= 0 \
        or not isinstance(value["generation"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["generation"]) \
        or not isinstance(value["config_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["config_sha256"]):
        raise ValueError("invalid readiness status")
    return value


class ReadyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            if self.request.recv(16) != b"READY\n":
                return
            # Revalidate all loaded identity files and key/cert pairing locally.
            # The public hash covers certificates/config only, never private keys.
            create_contexts(self.server.files)
            if public_config_hash(self.server.files) != self.server.config_hash:
                return
            status = {"schema_version": 1, "ready": True, "generation": self.server.generation,
                      "config_sha256": self.server.config_hash, "pid": os.getpid()}
            self.request.sendall(json.dumps(status, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        except (OSError, ValueError, ssl.SSLError):
            return


class ReadyServer(socketserver.UnixStreamServer):
    def __init__(self, files, path=READY_SOCKET):
        parent = Path(path).parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError("unsafe readiness directory")
        # Never follow/replace an existing socket or stale marker silently.
        self.files = files
        self.config_hash = public_config_hash(files)
        self.generation = uuid.uuid4().hex
        super().__init__(path, ReadyHandler)
        os.chmod(path, 0o600)

    def handle_error(self, request, client_address):
        return


def check_ready(path=READY_SOCKET):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(path)
        connection.sendall(b"READY\n")
        chunks = bytearray()
        while len(chunks) <= 4096:
            chunk = connection.recv(4097 - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > 4096:
            raise ValueError("invalid readiness status")
    return validate_ready_status(json.loads(chunks, object_pairs_hook=unique_object))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-ready", action="store_true")
    args = parser.parse_args()
    if args.check_ready:
        try:
            print(json.dumps(check_ready(), sort_keys=True, separators=(",", ":")))
            return 0
        except (OSError, ValueError):
            return 1
    files = TLSFiles.from_environment()
    server = create_server(files=files)
    readiness = ReadyServer(files)
    thread = threading.Thread(target=readiness.serve_forever, daemon=True)
    thread.start()
    try:
        server.serve_forever()
    finally:
        readiness.shutdown()
        readiness.server_close()
        server.server_close()
        Path(READY_SOCKET).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
