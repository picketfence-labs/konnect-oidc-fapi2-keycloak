#!/usr/bin/env python3
"""API-only upstream verifier for the local FAPI demo."""

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote_to_bytes

import jwt
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.serialization import Encoding


ISSUER = os.environ.get("OIDC_ISSUER", "https://localhost:8444/realms/fapi-demo")
AUDIENCE = os.environ.get("OIDC_AUDIENCE", "fapi-demo-api")
if AUDIENCE != "fapi-demo-api":
    raise RuntimeError("OIDC_AUDIENCE must be fapi-demo-api")
JWKS_URL = os.environ.get(
    "OIDC_JWKS_URL",
    "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/certs",
)
REQUIRED_SCOPES = frozenset(
    filter(None, os.environ.get("OIDC_REQUIRED_SCOPES", "openid").split())
)
if "openid" not in REQUIRED_SCOPES:
    raise RuntimeError("OIDC_REQUIRED_SCOPES must include openid")
ALLOWED_ALGORITHMS = tuple(
    filter(None, os.environ.get("OIDC_ALLOWED_ALGORITHMS", "PS256").split())
)
if ALLOWED_ALGORITHMS != ("PS256",):
    raise RuntimeError("OIDC_ALLOWED_ALGORITHMS must be PS256 only")
API_UPSTREAM_COMMON_NAME = "api-gateway-upstream"
API_UPSTREAM_CERT_FILE = os.environ.get(
    "API_UPSTREAM_CERT_FILE", "/etc/fapi/api-upstream.crt"
)
DEPARTMENT_CLAIM = "https://fapi-demo.example.com/department"
ROUTE_CLAIM = "https://fapi-demo.example.com/route"
AZP_ROUTES = {
    "third-party-fapi-mtls": ("route-a", "tls_client_auth"),
    "third-party-fapi-pkj-mtls": ("route-b", "private_key_jwt"),
}
MAX_FORWARDED_CERT_HEADER_BYTES = 24 * 1024
PEM_CERTIFICATE_BEGIN = b"-----BEGIN CERTIFICATE-----"
PEM_CERTIFICATE_END = b"-----END CERTIFICATE-----"


def verified_ssl_context(purpose=ssl.Purpose.SERVER_AUTH):
    context = ssl.create_default_context(purpose)
    # Python 3.13 enables strict verification by default. Keep CA and hostname
    # verification while accepting development CAs generated before keyUsage
    # was added.
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


JWK_CLIENT = jwt.PyJWKClient(
    JWKS_URL,
    cache_keys=True,
    lifespan=300,
    ssl_context=verified_ssl_context(),
)


def base64url_sha256(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def constant_time_text_equal(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except UnicodeEncodeError:
        return False


def bearer_token(headers):
    values = headers.get_all("Authorization")
    if values is not None:
        if len(values) != 1:
            return None
        authorization = values[0]
    else:
        authorization = headers.get("Authorization", "")
    scheme, separator, value = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and value and " " not in value:
        return value
    return None


def certificate_common_name(certificate):
    values = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(values) != 1:
        raise TokenValidationError("untrusted API Gateway peer")
    return values[0].value


class TokenValidationError(Exception):
    """A credential failure that is safe to reduce to a sanitized response."""


def load_pinned_gateway_certificate(path=API_UPSTREAM_CERT_FILE):
    try:
        certificate = x509.load_pem_x509_certificate(Path(path).read_bytes())
        common_name = certificate_common_name(certificate)
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except (OSError, ValueError, x509.ExtensionNotFound, TokenValidationError) as error:
        raise RuntimeError("API Gateway upstream certificate pin is invalid") from error
    if common_name != API_UPSTREAM_COMMON_NAME or ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        raise RuntimeError("API Gateway upstream certificate pin has the wrong identity")
    return certificate.public_bytes(Encoding.DER)


def verify_api_gateway_peer(peer_der, pinned_peer_der):
    if not peer_der or not pinned_peer_der:
        raise TokenValidationError("untrusted API Gateway peer")
    try:
        certificate = x509.load_der_x509_certificate(peer_der)
        common_name = certificate_common_name(certificate)
    except (ValueError, TokenValidationError) as error:
        raise TokenValidationError("untrusted API Gateway peer") from error
    if common_name != API_UPSTREAM_COMMON_NAME or not hmac.compare_digest(
        peer_der, pinned_peer_der
    ):
        raise TokenValidationError("untrusted API Gateway peer")
    return base64url_sha256(peer_der)


def forwarded_client_certificate_der(headers):
    values = headers.get_all("X-Client-Cert")
    if values is None or len(values) != 1:
        raise TokenValidationError("forwarded client certificate is missing or ambiguous")
    encoded = values[0]
    if not encoded or len(encoded) > MAX_FORWARDED_CERT_HEADER_BYTES or "," in encoded:
        raise TokenValidationError("forwarded client certificate is missing or ambiguous")
    try:
        encoded_bytes = encoded.encode("ascii")
    except UnicodeEncodeError as error:
        raise TokenValidationError("forwarded client certificate is invalid") from error
    if re.search(rb"%(?![0-9A-Fa-f]{2})", encoded_bytes):
        raise TokenValidationError("forwarded client certificate is invalid")
    pem_bytes = unquote_to_bytes(encoded)
    if (
        pem_bytes.count(PEM_CERTIFICATE_BEGIN) != 1
        or pem_bytes.count(PEM_CERTIFICATE_END) != 1
        or not pem_bytes.startswith(PEM_CERTIFICATE_BEGIN)
        or not pem_bytes.rstrip().endswith(PEM_CERTIFICATE_END)
    ):
        raise TokenValidationError("forwarded client certificate is invalid")
    try:
        certificate = x509.load_pem_x509_certificate(pem_bytes)
    except ValueError as error:
        raise TokenValidationError("forwarded client certificate is invalid") from error
    return certificate.public_bytes(Encoding.DER)


def verify_access_token(token):
    try:
        signing_key = JWK_CLIENT.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "require": ["exp", "iat", "iss", "aud", "cnf", "scope", "azp"],
                "verify_nbf": True,
            },
        )
    except Exception as error:
        raise TokenValidationError("JWT validation failed") from error

    scope_claim = claims.get("scope")
    if not isinstance(scope_claim, str):
        raise TokenValidationError("required scope is missing")
    granted_scopes = set(scope_claim.split())
    if not REQUIRED_SCOPES.issubset(granted_scopes):
        raise TokenValidationError("required scope is missing")

    azp = claims.get("azp")
    if not isinstance(azp, str) or azp not in AZP_ROUTES:
        raise TokenValidationError("authorized party is invalid")

    confirmation = claims.get("cnf")
    token_thumbprint = confirmation.get("x5t#S256") if isinstance(confirmation, dict) else None
    if not isinstance(token_thumbprint, str) or not token_thumbprint:
        raise TokenValidationError("certificate binding is missing")
    return claims, token_thumbprint


def verify_forwarded_certificate_binding(headers, token_thumbprint):
    forwarded_der = forwarded_client_certificate_der(headers)
    forwarded_thumbprint = base64url_sha256(forwarded_der)
    if not constant_time_text_equal(token_thumbprint, forwarded_thumbprint):
        raise TokenValidationError("certificate binding mismatch")
    return forwarded_thumbprint


def routing_evidence(headers, claims):
    department = safe_evidence_text(claims.get(DEPARTMENT_CLAIM))
    logical_route = safe_evidence_text(claims.get(ROUTE_CLAIM))
    department_header = safe_evidence_text(headers.get("X-Demo-Department"))
    logical_route_header = safe_evidence_text(headers.get("X-Demo-Route"))
    expected_and_received = (
        department,
        logical_route,
        department_header,
        logical_route_header,
    )
    header_claims_match = all(expected_and_received) and all(
        constant_time_text_equal(claim_value, header_value)
        for claim_value, header_value in (
            (department, department_header),
            (logical_route, logical_route_header),
        )
    )
    return {
        "department": department,
        "logical_route": logical_route,
        "department_header": department_header,
        "logical_route_header": logical_route_header,
        "header_claims_match": header_claims_match,
    }


def safe_evidence_text(value):
    if isinstance(value, str) and len(value) <= 256:
        return value
    return None


def build_evidence(headers, claims, token_thumbprint, forwarded_thumbprint, tls_peer_thumbprint):
    azp = claims["azp"]
    route, client_authentication = AZP_ROUTES[azp]
    evidence = {
        "azp": azp,
        "route": route,
        "client_authentication": client_authentication,
        "token_certificate_thumbprint": token_thumbprint,
        "forwarded_client_certificate_thumbprint": forwarded_thumbprint,
        "api_gateway_tls_peer_certificate_thumbprint": tls_peer_thumbprint,
        "token_signature_verified": True,
        "binding_verified": True,
    }
    evidence.update(routing_evidence(headers, claims))
    return evidence


class Handler(BaseHTTPRequestHandler):
    server_version = "fapi-pop-verifier/0.2"

    def json_response(self, status, body, extra_headers=()):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def invalid_token(self, reason):
        self.json_response(
            401,
            {"error": "invalid_token", "reason": reason},
            (("WWW-Authenticate", 'Bearer error="invalid_token"'),),
        )

    def send_error(self, code, message=None, explain=None):
        try:
            verify_api_gateway_peer(
                self.connection.getpeercert(binary_form=True),
                self.server.pinned_gateway_peer_der,
            )
        except Exception:
            return self.invalid_token("untrusted API Gateway peer")
        self.json_response(code, {"error": "request_rejected"})

    def do_GET(self):
        try:
            # Every endpoint requires the dedicated API Gateway identity. The
            # HTTP certificate header is untrusted until this exact leaf pin passes.
            peer_der = self.connection.getpeercert(binary_form=True)
            tls_peer_thumbprint = verify_api_gateway_peer(
                peer_der, self.server.pinned_gateway_peer_der
            )
        except Exception:
            return self.invalid_token("untrusted API Gateway peer")

        if self.path == "/healthz":
            return self.json_response(200, {"status": "ok"})
        if self.path != "/evidence":
            return self.json_response(404, {"error": "not_found"})

        token = bearer_token(self.headers)
        if not token:
            return self.invalid_token("missing bearer token")
        try:
            claims, token_thumbprint = verify_access_token(token)
            forwarded_thumbprint = verify_forwarded_certificate_binding(
                self.headers, token_thumbprint
            )
        except TokenValidationError as error:
            return self.invalid_token(str(error))
        except Exception:
            return self.invalid_token("invalid credentials")

        try:
            evidence = build_evidence(
                self.headers,
                claims,
                token_thumbprint,
                forwarded_thumbprint,
                tls_peer_thumbprint,
            )
        except Exception:
            return self.invalid_token("invalid credentials")
        return self.json_response(200, evidence)

    def log_message(self, message, *args):
        # The default request line includes the query string, which can contain
        # credentials. Keep request and error details out of the logs.
        return


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        return


def create_server_context():
    context = verified_ssl_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(os.environ.get("TLS_CA_FILE", "/etc/fapi/ca.crt"))
    context.load_cert_chain(
        os.environ.get("TLS_CERT_FILE", "/etc/fapi/tls.crt"),
        os.environ.get("TLS_KEY_FILE", "/etc/fapi/tls.key"),
    )
    return context


def create_server(host="0.0.0.0", port=9443, context=None, pinned_peer_der=None):
    peer_pin = (
        pinned_peer_der
        if pinned_peer_der is not None
        else load_pinned_gateway_certificate()
    )
    server_context = context or create_server_context()
    server = QuietThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.pinned_gateway_peer_der = peer_pin
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    return server


def main():
    server = create_server()
    server.serve_forever()


if __name__ == "__main__":
    main()
