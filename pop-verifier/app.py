#!/usr/bin/env python3
"""mTLS proof-of-possession verifier for the local FAPI demo."""

import base64
import hashlib
import hmac
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt


ISSUER = os.environ.get("OIDC_ISSUER", "https://localhost:8444/realms/fapi-demo")
AUDIENCE = os.environ.get("OIDC_AUDIENCE", "pop-verifier")
JWKS_URL = os.environ.get(
    "OIDC_JWKS_URL",
    "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/certs",
)
REQUIRED_SCOPES = set(filter(None, os.environ.get("OIDC_REQUIRED_SCOPES", "openid").split()))
ALLOWED_ALGORITHMS = tuple(
    filter(None, os.environ.get("OIDC_ALLOWED_ALGORITHMS", "PS256").split())
)
DEPARTMENT_CLAIM = "https://fapi-demo.example.com/department"
ROUTE_CLAIM = "https://fapi-demo.example.com/route"


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


def bearer_token(headers):
    authorization = headers.get("Authorization", "")
    scheme, separator, value = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and value:
        return value
    return None


def routing_evidence(headers, claims):
    department = claims.get(DEPARTMENT_CLAIM)
    logical_route = claims.get(ROUTE_CLAIM)
    department_header = headers.get("X-Demo-Department")
    logical_route_header = headers.get("X-Demo-Route")
    expected_and_received = (
        department,
        logical_route,
        department_header,
        logical_route_header,
    )
    header_claims_match = all(expected_and_received) and all(
        hmac.compare_digest(claim_value, header_value)
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


class TokenValidationError(Exception):
    """A credential failure that is safe to reduce to an invalid_token response."""


def verify_access_token(token, peer_der):
    try:
        signing_key = JWK_CLIENT.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "require": ["exp", "iat", "iss", "aud", "cnf"],
                "verify_nbf": True,
            },
        )
    except jwt.PyJWTError as error:
        raise TokenValidationError("JWT validation failed") from error

    granted_scopes = set(claims.get("scope", "").split())
    if not REQUIRED_SCOPES.issubset(granted_scopes):
        raise TokenValidationError("required scope is missing")

    token_thumbprint = claims.get("cnf", {}).get("x5t#S256")
    peer_thumbprint = base64url_sha256(peer_der)
    if not token_thumbprint or not hmac.compare_digest(token_thumbprint, peer_thumbprint):
        raise TokenValidationError("certificate binding mismatch")

    return claims, token_thumbprint, peer_thumbprint


class Handler(BaseHTTPRequestHandler):
    server_version = "fapi-pop-verifier/0.1"

    def json_response(self, status, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def invalid_token(self, reason):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer error="invalid_token"')
        self.send_header("Content-Type", "application/json")
        data = json.dumps({"error": "invalid_token", "reason": reason}).encode()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self.json_response(200, {"status": "ok"})
        if self.path != "/evidence":
            return self.json_response(404, {"error": "not_found"})

        token = bearer_token(self.headers)
        if not token:
            return self.invalid_token("missing bearer token")

        peer_der = self.connection.getpeercert(binary_form=True)
        if not peer_der:
            return self.invalid_token("missing TLS client certificate")

        try:
            claims, token_thumbprint, peer_thumbprint = verify_access_token(token, peer_der)
        except TokenValidationError as error:
            return self.invalid_token(str(error))

        evidence = {
            "route": self.headers.get("X-Fapi-Route", "unknown"),
            "client_authentication": self.headers.get("X-Fapi-Client-Auth", "unknown"),
            "token_certificate_thumbprint": token_thumbprint,
            "tls_peer_certificate_thumbprint": peer_thumbprint,
            "binding_verified": True,
        }
        evidence.update(routing_evidence(self.headers, claims))
        return self.json_response(200, evidence)

    def log_message(self, message, *args):
        # BaseHTTPRequestHandler logs only method, path, and status. It never logs headers.
        super().log_message(message, *args)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 9443), Handler)
    context = verified_ssl_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(os.environ.get("TLS_CA_FILE", "/etc/fapi/ca.crt"))
    context.load_cert_chain(
        os.environ.get("TLS_CERT_FILE", "/etc/fapi/tls.crt"),
        os.environ.get("TLS_KEY_FILE", "/etc/fapi/tls.key"),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
