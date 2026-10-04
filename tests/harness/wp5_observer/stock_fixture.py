#!/usr/bin/env python3
"""Isolated stage-1 stock Kong PAR fixture for WP5 OMD-02."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
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
import threading
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import stock_flow

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FIXTURE_ROOT = Path("/private/tmp/wp5-as-peer-stock-par-route-b-20261004-v15")
PREP_RECEIPT = Path("/private/tmp/wp5-as-peer-stock-par-prep-receipt-20261004-v15.json")
RUN_INTENT = Path("/private/tmp/wp5-as-peer-stock-par-run-intent-20261004-v15.json")
RUN_RECEIPT = Path("/private/tmp/wp5-as-peer-stock-par-run-receipt-20261004-v15.json")

PROJECT = "wp5-stock-par-route-b-v15"
VOLUME = "wp5-stock-par-route-b-v15-data"
NETWORK = f"{PROJECT}_default"
PHASE = "stock-par-stage2-v15"
OWNER = "wp5-luna"
ISSUER = "https://localhost:8444/realms/fapi-demo"
CLIENT_ID = "kong-fapi-pkj-mtls"
PAR_PATH = "/realms/fapi-demo/protocol/openid-connect/ext/par/request"
PAR_URL = "https://as-spike-harness:9443/par"
REVOKE_URL = "https://as-spike-harness:9443/revoke"

KONG_IMAGE = "kong/kong-gateway:3.16.0.0@sha256:e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4"
KONG_IMAGE_ID = "sha256:d2cd92f969c5960265288b9a54accd213d62801ba6ef001dba75a1c340b96d2d"
RELAY_IMAGE = "sha256:8832f9ad3ee60b05d2d0e87a1e998eec2b211d65634a5d073ce8c2193b6ae831"
KEYCLOAK_IMAGE = "sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953"
IMAGE_IDS = {"kong": KONG_IMAGE_ID, "as-spike-harness": RELAY_IMAGE, "keycloak": KEYCLOAK_IMAGE}
IMAGE_REFS = {"kong": KONG_IMAGE, "as-spike-harness": RELAY_IMAGE, "keycloak": KEYCLOAK_IMAGE}

HOST_PORTS = (8443, 8444, 19445)
MAX_COMMAND_SECONDS = 60
MAX_STARTUP_SECONDS = 180
MAX_TOTAL_SECONDS = 12 * 60
MAX_CLEANUP_SECONDS = 120
MAX_OUTPUT = 32 * 1024 * 1024
MAX_HTTP_BODY = 64 * 1024
MAX_AUX_DISCOVERY = 4
MAX_AUX_JWKS = 2
MAX_AUX_TOKEN = 1
DEMO_USERNAME = "wp5-route-b-demo"
MAX_RUNTIME_SECRET_VALUES = 512
MAX_RUNTIME_SECRET_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_SECRET_VALUE = 2 * 1024 * 1024

KEYCLOAK_ERROR_FIELD_RE = re.compile(rb"\berror\b['\"]?\s*(?:=|:)\s*['\"]?([A-Za-z][A-Za-z0-9_-]{0,63})")
KEYCLOAK_ERROR_VALUES = frozenset((
    "invalid_request", "realm_disabled", "client_not_found", "client_disabled",
    "invalid_client_credentials", "invalid_client", "unauthorized_client", "consent_denied",
    "resolve_required_actions", "user_not_found", "user_disabled", "user_temporarily_disabled",
    "invalid_user_credentials", "invalid_authentication_session", "different_user_authenticating",
    "different_user_authenticated", "user_delete_error", "invalid_user", "username_missing",
    "username_in_use", "email_in_use", "email_already_verified", "org_not_found", "org_disabled",
    "user_org_member_already", "invalid_redirect_uri", "invalid_code", "invalid_token",
    "invalid_token_type", "invalid_saml_response", "invalid_authn_request", "invalid_logout_request",
    "invalid_logout_response", "invalid_artifact", "invalid_artifact_response", "invalid_scope",
    "saml_token_not_found", "invalid_signature", "invalid_registration", "invalid_issuer",
    "invalid_form", "invalid_config", "expired_code", "missing_tx_code", "invalid_tx_code",
    "invalid_input", "cookie_not_found", "already_logged_in", "token_introspection_failed",
    "registration_disabled", "reset_credential_disabled", "rejected_by_user", "not_allowed",
    "federated_identity_account_exists", "ssl_required", "user_session_not_found", "session_expired",
    "email_send_failed", "invalid_email", "identity_provider_login_failure", "identity_provider_error",
    "password_confirm_error", "password_missing", "password_rejected", "code_verifier_missing",
    "invalid_code_verifier", "pkce_verification_failed", "invalid_code_challenge_method",
    "invalid_dpop_proof", "invalid_authorization_details", "not_logged_in", "unknown_identity_provider",
    "illegal_origin", "display_unsupported", "logout_failed", "invalid_destination",
    "missing_required_destination", "invalid_saml_document", "unsupported_nameid_format",
    "invalid_permission_ticket", "access_denied", "invalid_oauth2_device_code",
    "expired_oauth2_device_code", "invalid_oauth2_user_code", "slow_down",
    "generic_authentication_error", "generic", "credential_not_found", "missing_credential_id",
    "delete_credential_failed",
))
KONG_OIDC_KEYWORDS = (
    "nonce", "state", "signature", "issuer", "audience", "algorithm", "jwt", "assertion",
    "credentials", "certificate", "key", "kid", "pkce", "verifier", "code", "token", "expired",
    "missing", "invalid", "unsupported", "authentication", "client", "session", "request",
    "discovery", "user", "mtls", "claim", "claims",
)
KONG_OIDC_KEYWORD_PATTERNS = {
    keyword: re.compile(rb"(?<![A-Za-z0-9])" + keyword.encode("ascii") + rb"(?![A-Za-z0-9])", re.IGNORECASE)
    for keyword in KONG_OIDC_KEYWORDS
}
KONG_OIDC_ERROR_CATEGORIES = (
    "token_endpoint_failure", "authorization_code_failure",
    "client_authentication_failure", "other_oidc_error",
)
STOCK_TOKEN_MARKER = b"WP5_STOCK_TOKEN_DIAG="
STOCK_TOKEN_DIAGNOSTIC_KEYS = frozenset({
    "v", "ssl_client_cert_present", "ssl_client_priv_key_present", "client_assertion_present",
    "client_assertion_type_present", "response_status", "oauth_error_enum",
    "error_description_keyword_presence",
})
STOCK_TOKEN_OAUTH_ERRORS = frozenset(stock_flow.OAUTH_ERROR_ENUMS | {"none", "unknown"})

INPUT_SOURCES = {
    "stock_fixture.py": HERE / "stock_fixture.py",
    "stock_relay.py": HERE / "stock_relay.py",
    "stock_flow.py": HERE / "stock_flow.py",
    "wp2_flow.py": ROOT / "tests/harness/wp2_flow.py",
    "stock_kong_entrypoint.sh": HERE / "stock_kong_entrypoint.sh",
    "bridge_handler.lua": ROOT / "kong/plugins/fapi-client-auth-bridge/handler.lua",
    "bridge_schema.lua": ROOT / "kong/plugins/fapi-client-auth-bridge/schema.lua",
    "stock_token_diag_handler.lua": HERE / "stock_token_diag_plugin/handler.lua",
    "stock_token_diag_schema.lua": HERE / "stock_token_diag_plugin/schema.lua",
}


class StockFixtureError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "internal_failure"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64url(value: int) -> str:
    if value < 0:
        raise StockFixtureError("jwk_integer_invalid")
    return _b64url(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, mode)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _new_ca(now: dt.datetime):
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name("WP5 stock PAR isolated CA")
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _new_leaf(common_name: str, ca_key, ca_cert, now: dt.datetime,
              *, server_names: tuple[str, ...] = (), client: bool = False):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder().subject_name(_name(common_name)).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH,
        ]), critical=False)
    )
    if server_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(item) for item in server_names]), critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _write_key_config(key, route_cert: bytes, ca_cert: bytes, route_key: bytes,
                      issuer: str, kid: str, session_secret: str, cache_salt: str) -> bytes:
    numbers = key.private_numbers()
    public = numbers.public_numbers
    jwk = {
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "PS256",
        "n": _int_b64url(public.n), "e": _int_b64url(public.e),
        "d": _int_b64url(numbers.d), "p": _int_b64url(numbers.p), "q": _int_b64url(numbers.q),
        "dp": _int_b64url(numbers.dmp1), "dq": _int_b64url(numbers.dmq1),
        "qi": _int_b64url(numbers.iqmp),
    }
    cert_id = "22222222-2222-4222-8222-222222222222"
    ca_id = "33333333-3333-4333-8333-333333333333"
    doc: dict[str, Any] = {
        "_format_version": "3.0",
        "certificates": [{"id": cert_id, "cert": route_cert.decode("ascii"),
                          "key": route_key.decode("ascii")}],
        "ca_certificates": [{"id": ca_id, "cert": ca_cert.decode("ascii")}],
        "plugins": [{"name": "wp5-stock-token-diag", "config": {}}],
        "services": [{
            "name": "stock-par-stage1",
            "url": "http://127.0.0.1:9/not-reached-before-login",
            "routes": [{"name": "stock-par-route-b", "paths": ["/api/fapi/pkj-mtls"],
                        "methods": ["GET"], "strip_path": False}],
            "plugins": [
                {"name": "fapi-client-auth-bridge", "config": {
                    "issuer": issuer,
                    "discovery_endpoint": "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration",
                    "client_id": CLIENT_ID,
                    "private_key_file": "/run/wp5/route-b-jwk.pem",
                    "tls_certificate_file": "/run/wp5/route-b.crt",
                    "key_id": kid,
                    "assertion_delivery": "header",
                    "assertion_ttl": 60,
                }},
                {"name": "openid-connect", "config": {
                    "issuer": issuer,
                    "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
                    "token_endpoint": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token",
                    "mtls_token_endpoint": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token",
                    "jwks_endpoint": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/certs",
                    "pushed_authorization_request_endpoint": PAR_URL,
                    "revocation_endpoint": REVOKE_URL,
                    "mtls_revocation_endpoint": REVOKE_URL,
                    "end_session_endpoint": issuer + "/protocol/openid-connect/logout",
                    "client_id": [CLIENT_ID], "client_auth": ["tls_client_auth"],
                    "client_alg": ["PS256"], "client_jwk": [jwk],
                    "token_endpoint_auth_method": "tls_client_auth",
                    "token_post_args_client": ["client_assertion", "client_assertion_type"],
                    "pushed_authorization_request_endpoint_auth_method": "private_key_jwt",
                    "revocation_endpoint_auth_method": "private_key_jwt",
                    "tls_client_auth_cert_id": cert_id,
                    "tls_client_auth_ssl_verify": True, "ssl_verify": True,
                    "auth_methods": ["authorization_code", "session"],
                    "scopes": ["openid", "profile"],
                    "login_tokens": None,
                    "redirect_uri": ["https://localhost:8443/api/fapi/pkj-mtls"],
                    "require_proof_key_for_code_exchange": True,
                    "require_pushed_authorization_requests": True,
                    "login_action": "redirect",
                    "login_redirect_uri": ["https://localhost:3443/?authenticated=route-b"],
                    "logout_uri_suffix": "/logout", "logout_methods": ["GET", "POST"],
                    "logout_revoke": True,
                    "logout_revoke_access_token": True,
                    "logout_revoke_refresh_token": True,
                    "logout_redirect_uri": ["https://localhost:3443/?logout=route-b"],
                    "session_cookie_name": "wp5_stock_route_b_session",
                    "session_secret": session_secret, "cache_tokens_salt": cache_salt,
                    "upstream_access_token_header": "authorization:bearer",
                }},
            ],
        }],
    }
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _realm(public_key_pem: bytes, kid: str, username: str, password: str) -> bytes:
    doc = {
        "realm": "fapi-demo", "enabled": True, "defaultSignatureAlgorithm": "PS256",
        "components": {
            "org.keycloak.keys.KeyProvider": [{
                "name": "wp5-ps256", "providerId": "rsa-generated",
                "config": {
                    "priority": ["100"], "enabled": ["true"], "active": ["true"],
                    "algorithm": ["PS256"], "keySize": ["3072"],
                },
            }],
        },
        "clients": [{
            "clientId": CLIENT_ID, "name": "WP5 isolated stock PAR Route B",
            "enabled": True, "protocol": "openid-connect", "publicClient": False,
            "clientAuthenticatorType": "client-jwt", "standardFlowEnabled": True,
            "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "redirectUris": ["https://localhost:8443/api/fapi/pkj-mtls"],
            "webOrigins": [],
            "attributes": {
                "jwt.credential.public.key": public_key_pem.decode("ascii"),
                "jwt.credential.kid": kid,
                "token.endpoint.auth.signing.alg": "PS256",
                "token.endpoint.auth.signing.max.exp": "60",
                "pkce.code.challenge.method": "S256",
                "require.pushed.authorization.requests": "true",
                "tls.client.certificate.bound.access.tokens": "true",
                "use.refresh.tokens": "true",
                "id.token.signed.response.alg": "PS256",
                "post.logout.redirect.uris": "https://localhost:3443/?logout=route-b",
            },
        }],
        "users": [{
            "username": username, "firstName": "WP5", "lastName": "Demo",
            "email": username + "@example.invalid", "enabled": True, "emailVerified": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
            "requiredActions": [],
        }],
        "clientPolicies": {
            "policies": [{
                "name": "fapi-2-confidential-clients",
                "description": "Apply the built-in FAPI 2.0 Security Profile to confidential clients.",
                "enabled": True,
                "conditions": [{"condition": "client-access-type", "configuration": {
                    "is-negative-logic": False, "type": ["confidential"],
                }}],
                "profiles": ["fapi-2-security-profile"],
            }],
        },
    }
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _compose_file(root: Path) -> bytes:
    base = str(root)
    text = f'''services:
  keycloak:
    image: "{KEYCLOAK_IMAGE}"
    pull_policy: never
    platform: linux/arm64
    cpus: 2
    mem_limit: 4g
    pids_limit: 256
    stop_grace_period: 20s
    user: "0:0"
    restart: "no"
    command: ["start-dev", "--import-realm", "--https-port=8443"]
    environment:
      KC_HOSTNAME: https://localhost:8444
      KC_HOSTNAME_BACKCHANNEL_DYNAMIC: "true"
      KC_HTTP_ENABLED: "false"
      KC_HTTP_ACCESS_LOG_ENABLED: "false"
      KC_HTTPS_CLIENT_AUTH: request
      KC_HTTPS_CERTIFICATE_FILE: /run/wp5/keycloak.crt
      KC_HTTPS_CERTIFICATE_KEY_FILE: /run/wp5/keycloak.key
      KC_TRUSTSTORE_PATHS: /run/wp5/ca.crt
      FAPI_DEMO_AS_PEER_OBSERVER: "true"
      FAPI_DEMO_AS_PEER_CA_FILE: /run/wp5/ca.crt
      KC_LOG_LEVEL: info
    volumes:
      - {base}/realm/fapi-demo-realm.json:/opt/keycloak/data/import/fapi-demo-realm.json:ro
      - {base}/tls/keycloak.crt:/run/wp5/keycloak.crt:ro
      - {base}/tls/keycloak.key:/run/wp5/keycloak.key:ro
      - {base}/ca/ca.crt:/run/wp5/ca.crt:ro
      - stock-data:/opt/keycloak/data/h2
    ports:
      - "127.0.0.1:8444:8443"
    labels:
      org.picketfence.wp5.owner: {OWNER}
      org.picketfence.wp5.phase: {PHASE}
    networks: [default]

  kong:
    image: "{KONG_IMAGE}"
    pull_policy: never
    platform: linux/arm64
    cpus: 1
    mem_limit: 3g
    pids_limit: 256
    stop_grace_period: 20s
    user: "0:0"
    restart: "no"
    entrypoint: ["/bin/sh", "/run/wp5/stock_kong_entrypoint.sh"]
    environment:
      KONG_DATABASE: "off"
      KONG_LICENSE_PATH: /run/wp5/license.json
      KONG_DECLARATIVE_CONFIG: /run/wp5/kong.json
      KONG_PLUGINS: bundled,fapi-client-auth-bridge,wp5-stock-token-diag
      KONG_PROXY_LISTEN: "0.0.0.0:8443 ssl"
      KONG_PROXY_ACCESS_LOG: "off"
      KONG_PROXY_ERROR_LOG: /dev/stderr
      KONG_ADMIN_LISTEN: "off"
      KONG_ADMIN_ACCESS_LOG: "off"
      KONG_ADMIN_GUI_LISTEN: "off"
      KONG_PORTAL_GUI_LISTEN: "off"
      KONG_PORTAL_API_LISTEN: "off"
      KONG_LOG_LEVEL: error
      KONG_ANONYMOUS_REPORTS: "off"
      KONG_DNS_HOSTSFILE: /tmp/wp5-stock-hosts
      KONG_LUA_SSL_TRUSTED_CERTIFICATE: /run/wp5/ca.crt
      KONG_SSL_CERT: /run/wp5/kong.crt
      KONG_SSL_CERT_KEY: /run/wp5/kong.key
      KONG_PREFIX: /tmp/kong
    volumes:
      - {base}/kong/kong.json:/run/wp5/kong.json:ro
      - {base}/kong/stock_kong_entrypoint.sh:/run/wp5/stock_kong_entrypoint.sh:ro
      - {base}/license/license.json:/run/wp5/license.json:ro
      - {base}/tls/kong.crt:/run/wp5/kong.crt:ro
      - {base}/tls/kong.key:/run/wp5/kong.key:ro
      - {base}/tls/route-b.crt:/run/wp5/route-b.crt:ro
      - {base}/keys/route-b-jwk.pem:/run/wp5/route-b-jwk.pem:ro
      - {base}/ca/ca.crt:/run/wp5/ca.crt:ro
      - {base}/plugins/fapi-client-auth-bridge:/usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge:ro
      - {base}/plugins/wp5-stock-token-diag:/usr/local/share/lua/5.1/kong/plugins/wp5-stock-token-diag:ro
    extra_hosts:
      - "as-host-gateway:host-gateway"
    ports:
      - "127.0.0.1:8443:8443"
    labels:
      org.picketfence.wp5.owner: {OWNER}
      org.picketfence.wp5.phase: {PHASE}
    depends_on: [keycloak, as-spike-harness]
    networks: [default]

  as-spike-harness:
    image: "{RELAY_IMAGE}"
    pull_policy: never
    platform: linux/arm64
    cpus: 0.5
    mem_limit: 1g
    pids_limit: 64
    stop_grace_period: 10s
    user: "0:0"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    restart: "no"
    entrypoint: ["python"]
    command: ["/opt/wp5/stock_relay.py"]
    environment:
      WP5_STOCK_ROOT: /run/wp5
      PYTHONPATH: /opt/python-deps
    volumes:
      - {base}/source/stock_relay.py:/opt/wp5/stock_relay.py:ro
      - {base}/ca/ca.crt:/run/wp5/ca/ca.crt:ro
      - {base}/tls/route-b.crt:/run/wp5/tls/route-b.crt:ro
      - {base}/tls/route-b.key:/run/wp5/tls/route-b.key:ro
      - {base}/tls/harness.crt:/run/wp5/tls/harness.crt:ro
      - {base}/tls/harness.key:/run/wp5/tls/harness.key:ro
      - {base}/keys/route-b-public.pem:/run/wp5/keys/route-b-public.pem:ro
      - {base}/keys/route-b-kid.txt:/run/wp5/keys/route-b-kid.txt:ro
    ports:
      - "127.0.0.1:19445:9443"
    labels:
      org.picketfence.wp5.owner: {OWNER}
      org.picketfence.wp5.phase: {PHASE}
    networks: [default]

volumes:
  stock-data:
    name: {VOLUME}
    labels:
      org.picketfence.wp5.owner: {OWNER}
      org.picketfence.wp5.phase: {PHASE}

networks:
  default:
    name: {NETWORK}
    labels:
      org.picketfence.wp5.owner: {OWNER}
      org.picketfence.wp5.phase: {PHASE}
'''
    return text.encode("utf-8")


def _source_hashes() -> dict[str, str]:
    return {name: _sha256(path.read_bytes()) for name, path in sorted(INPUT_SOURCES.items())}


def _file_manifest(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise StockFixtureError("fixture_symlink_rejected")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            result[relative] = {"sha256": _sha256(path.read_bytes()), "mode": f"{path.stat().st_mode & 0o777:04o}"}
        elif path.is_dir() and path.stat().st_mode & 0o777 != 0o700:
            raise StockFixtureError("fixture_directory_mode_invalid")
    return result


def prepare_stock_fixture(root: Path = FIXTURE_ROOT, receipt_path: Path = PREP_RECEIPT) -> dict[str, Any]:
    root = root.absolute()
    if root.exists() or root.is_symlink():
        raise StockFixtureError("fixture_path_exists")
    if receipt_path.exists() or receipt_path.is_symlink():
        raise StockFixtureError("prep_receipt_exists")
    license_value = os.environ.get("KONG_LICENSE_DATA")
    if not license_value:
        raise StockFixtureError("license_input_missing")
    license_bytes = license_value.encode("utf-8")
    if len(license_bytes) > 64 * 1024:
        raise StockFixtureError("license_input_invalid")
    try:
        license_doc = json.loads(license_bytes)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise StockFixtureError("license_input_invalid") from None
    if not isinstance(license_doc, dict) or not isinstance(license_doc.get("license"), dict):
        raise StockFixtureError("license_input_invalid")
    root.mkdir(mode=0o700, parents=False)
    for directory in ("ca", "tls", "keys", "realm", "kong", "license", "plugins",
                      "plugins/fapi-client-auth-bridge", "plugins/wp5-stock-token-diag", "source"):
        (root / directory).mkdir(mode=0o700, exist_ok=True)

    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    ca_key, ca_cert = _new_ca(now)
    keycloak_key, keycloak_cert = _new_leaf("localhost", ca_key, ca_cert, now,
                                              server_names=("localhost", "keycloak"))
    kong_key, kong_cert = _new_leaf("localhost", ca_key, ca_cert, now, server_names=("localhost",))
    harness_key, harness_cert = _new_leaf("as-spike-harness", ca_key, ca_cert, now,
                                            server_names=("as-spike-harness",))
    route_cert_key, route_cert = _new_leaf(CLIENT_ID, ca_key, ca_cert, now, client=True)
    jwk_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_der = jwk_key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = "wp5-stock-b-" + _sha256(public_der)[:16]
    public_pem = jwk_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    user_password = secrets.token_urlsafe(32)

    files: dict[str, bytes] = {
        "ca/ca.crt": _pem_cert(ca_cert),
        "license/license.json": license_bytes,
        "tls/keycloak.crt": _pem_cert(keycloak_cert), "tls/keycloak.key": _pem_key(keycloak_key),
        "tls/kong.crt": _pem_cert(kong_cert), "tls/kong.key": _pem_key(kong_key),
        "tls/harness.crt": _pem_cert(harness_cert), "tls/harness.key": _pem_key(harness_key),
        "tls/route-b.crt": _pem_cert(route_cert), "tls/route-b.key": _pem_key(route_cert_key),
        "keys/route-b-jwk.pem": _pem_key(jwk_key), "keys/route-b-public.pem": public_pem,
        "keys/route-b-kid.txt": (kid + "\n").encode("ascii"),
        "realm/fapi-demo-realm.json": _realm(public_pem, kid, DEMO_USERNAME, user_password),
        "plugins/fapi-client-auth-bridge/handler.lua": INPUT_SOURCES["bridge_handler.lua"].read_bytes(),
        "plugins/fapi-client-auth-bridge/schema.lua": INPUT_SOURCES["bridge_schema.lua"].read_bytes(),
        "plugins/wp5-stock-token-diag/handler.lua": INPUT_SOURCES["stock_token_diag_handler.lua"].read_bytes(),
        "plugins/wp5-stock-token-diag/schema.lua": INPUT_SOURCES["stock_token_diag_schema.lua"].read_bytes(),
        "source/stock_relay.py": INPUT_SOURCES["stock_relay.py"].read_bytes(),
        "kong/stock_kong_entrypoint.sh": INPUT_SOURCES["stock_kong_entrypoint.sh"].read_bytes(),
    }
    for relative, content in files.items():
        _write_exclusive(root / relative, content)
    (root / "tls/route-b.key").chmod(0o600)
    kong_config = _write_key_config(jwk_key, _pem_cert(route_cert), _pem_cert(ca_cert),
                                    _pem_key(route_cert_key), ISSUER, kid,
                                    _b64url(os.urandom(48)), _b64url(os.urandom(32)))
    _write_exclusive(root / "kong/kong.json", kong_config)
    compose = _compose_file(root)
    _write_exclusive(root / "compose.yml", compose)
    _write_exclusive(root / "compose.env", f"WP5_FIXTURE_ROOT={root}\n".encode("ascii"))

    files_manifest = _file_manifest(root)
    expected_leaf = _b64url(route_cert.fingerprint(hashes.SHA256()))
    sources = _source_hashes()
    receipt = {
        "schema": "wp5-stock-par-prep-v15", "result": "prepared", "stage2": "conditional_after_par_observer_join",
        "fixture_root": str(root), "project": PROJECT, "volume": VOLUME, "network": NETWORK,
        "issuer": ISSUER, "client_id": CLIENT_ID, "route_b_leaf_sha256": expected_leaf,
        "jwk_kid": kid, "fixture_user_imported": True,
        "image_ids": IMAGE_IDS.copy(), "image_refs": IMAGE_REFS.copy(),
        "source_hashes": sources, "files": files_manifest,
        "file_count": len(files_manifest), "directory_mode": "0700", "file_mode": "0600",
    }
    _write_exclusive(receipt_path, (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return receipt


def verify_prepared_fixture(root: Path, receipt_path: Path, *, source_hashes: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        if (root.is_symlink() or not root.is_dir() or receipt_path.is_symlink() or not receipt_path.is_file()
            or receipt_path.stat().st_mode & 0o777 != 0o600):
            raise StockFixtureError("prep_receipt_invalid")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        raise StockFixtureError("prep_receipt_invalid") from None
    if not isinstance(receipt, dict) or receipt.get("schema") != "wp5-stock-par-prep-v15" or receipt.get("result") != "prepared":
        raise StockFixtureError("prep_receipt_schema_invalid")
    if receipt.get("fixture_root") != str(root.absolute()) or receipt.get("project") != PROJECT:
        raise StockFixtureError("prep_fixture_identity_mismatch")
    if receipt.get("source_hashes") != (source_hashes or _source_hashes()):
        raise StockFixtureError("prep_source_changed")
    if receipt.get("files") != _file_manifest(root):
        raise StockFixtureError("prep_file_manifest_mismatch")
    return receipt


def _minimal_env() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "DOCKER_CLI_HINTS": "false"}
    for name in ("HOME", "TMPDIR"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def _rtk_docker() -> list[str]:
    rtk = shutil.which("rtk", path=_minimal_env()["PATH"])
    if not rtk:
        raise StockFixtureError("rtk_unavailable")
    return [rtk, "proxy", "docker"]


def _command(argv: list[str], *, timeout: int = MAX_COMMAND_SECONDS, cap: int = 1024 * 1024) -> bytes:
    try:
        process = subprocess.Popen(argv, cwd=ROOT, env=_minimal_env(), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
    except OSError:
        raise StockFixtureError("command_start_failed") from None
    assert process.stdout is not None
    os.set_blocking(process.stdout.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout
    timed_out = False
    truncated = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(0.2, remaining)):
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
            if process.poll() is not None and not selector.get_map():
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
        code = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        raise StockFixtureError("command_reap_failed") from None
    finally:
        selector.close()
        process.stdout.close()
    if timed_out:
        raise StockFixtureError("command_timeout")
    if truncated:
        raise StockFixtureError("command_output_limit")
    if code != 0:
        raise StockFixtureError("command_failed")
    return bytes(output)


def _compose_prefix(root: Path) -> list[str]:
    docker = _rtk_docker()
    return docker + ["compose", "--project-name", PROJECT, "--file", str(root / "compose.yml"),
                     "--env-file", str(root / "compose.env")]


def _compose(root: Path, *args: str, timeout: int = MAX_COMMAND_SECONDS, cap: int = 1024 * 1024) -> bytes:
    return _command(_compose_prefix(root) + list(args), timeout=timeout, cap=cap)


def _inspect_image(image: str, expected_id: str) -> None:
    docker = _rtk_docker()
    raw = _command(docker + ["image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", image])
    if raw.decode("ascii", errors="strict").strip() != f"{expected_id}|linux|arm64":
        raise StockFixtureError("runtime_image_identity_mismatch")


def _resource_names(kind: str, name: str, *, timeout: int = MAX_COMMAND_SECONDS) -> set[str]:
    raw = _command(_rtk_docker() + [kind, "ls", "--filter", f"name={name}", "--format", "{{.Name}}"], timeout=timeout)
    return {line for line in raw.decode("ascii", errors="strict").splitlines() if line}


def _project_container_ids(*, timeout: int = MAX_COMMAND_SECONDS) -> list[str]:
    raw = _command(_rtk_docker() + ["ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}"], timeout=timeout)
    return [line for line in raw.decode("ascii", errors="strict").splitlines() if line]


def _service_container_id(service: str) -> str:
    raw = _command(_rtk_docker() + ["ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}",
                                    "--filter", f"label=com.docker.compose.service={service}"])
    ids = [line for line in raw.decode("ascii", errors="strict").splitlines() if line]
    if len(ids) != 1:
        raise StockFixtureError("runtime_service_container_missing")
    return ids[0]


def _check_kong_start_state(startup_deadline: float) -> bool:
    remaining = startup_deadline - time.monotonic()
    if remaining <= 0:
        raise StockFixtureError("startup_deadline_exceeded")
    timeout = max(1, min(10, int(remaining)))
    docker = _rtk_docker()
    try:
        raw_ids = _command(docker + ["ps", "-aq", "--no-trunc",
                                     "--filter", f"label=com.docker.compose.project={PROJECT}",
                                     "--filter", "label=com.docker.compose.service=kong"], timeout=timeout)
    except StockFixtureError as error:
        if error.code in {"command_timeout", "command_failed"}:
            return False
        raise
    ids = [line for line in raw_ids.decode("ascii", errors="strict").splitlines() if line]
    if not ids:
        return False
    if len(ids) != 1 or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in ids):
        raise StockFixtureError("kong_container_identity_unavailable")
    fmt = (
        "{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|"
        "{{index .Config.Labels \"com.docker.compose.service\"}}|"
        "{{index .Config.Labels \"org.picketfence.wp5.owner\"}}|"
        "{{index .Config.Labels \"org.picketfence.wp5.phase\"}}|{{.Image}}|"
        "{{.State.Status}}|{{.State.ExitCode}}"
    )
    try:
        raw = _command(docker + ["inspect", "--format", fmt, ids[0]], timeout=timeout)
    except StockFixtureError as error:
        if error.code in {"command_timeout", "command_failed"}:
            return False
        raise
    fields = raw.decode("ascii", errors="strict").strip().split("|")
    if (len(fields) != 8 or fields[0] != ids[0]
        or fields[1:6] != [PROJECT, "kong", OWNER, PHASE, KONG_IMAGE_ID]
        or not fields[7].isdigit()):
        raise StockFixtureError("kong_container_identity_mismatch")
    if fields[6] == "exited":
        raise StockFixtureError("kong_container_exited")
    if fields[6] not in {"created", "running"}:
        raise StockFixtureError("kong_container_not_running")
    return fields[6] == "running"


def _verify_kong_hostgateway_route() -> None:
    container = _service_container_id("kong")
    shell = (
        "ip=\"$(awk 'NR == 1 { print $1 }' /tmp/wp5-stock-hosts)\"; "
        "case \"$ip\" in \"\"|*[!0-9.]*) exit 71;; esac; "
        "exec openssl s_client -connect \"$ip:8444\" -servername localhost "
        "-CAfile /run/wp5/ca.crt -verify_hostname localhost -verify_return_error -brief </dev/null >/dev/null 2>&1"
    )
    _command(_rtk_docker() + ["exec", container, "/bin/sh", "-ec", shell], timeout=10, cap=4096)


def preflight_absent() -> None:
    for service in ("kong", "as-spike-harness", "keycloak"):
        _inspect_image(IMAGE_REFS[service], IMAGE_IDS[service])
    if _project_container_ids():
        raise StockFixtureError("runtime_project_exists")
    if VOLUME in _resource_names("volume", VOLUME):
        raise StockFixtureError("runtime_volume_exists")
    if NETWORK in _resource_names("network", NETWORK):
        raise StockFixtureError("runtime_network_exists")
    for port in HOST_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            raise StockFixtureError("runtime_port_unavailable") from None
        finally:
            sock.close()


def _container_format() -> str:
    return ("{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|"
            "{{index .Config.Labels \"org.picketfence.wp5.owner\"}}|"
            "{{index .Config.Labels \"org.picketfence.wp5.phase\"}}|{{.Image}}|"
            "{{index .Config.Labels \"com.docker.compose.service\"}}")


def verify_owned_resources(*, allow_partial: bool, timeout: int = MAX_COMMAND_SECONDS) -> dict[str, Any]:
    ids = _project_container_ids(timeout=timeout)
    if len(ids) > 3 or (not ids and not allow_partial):
        raise StockFixtureError("runtime_container_set_invalid")
    container_services: set[str] = set()
    for container_id in ids:
        raw = _command(_rtk_docker() + ["inspect", "--format", _container_format(), container_id], timeout=timeout)
        fields = raw.decode("ascii", errors="strict").strip().split("|")
        if len(fields) != 6 or fields[1:4] != [PROJECT, OWNER, PHASE]:
            raise StockFixtureError("runtime_container_ownership_mismatch")
        service = fields[5]
        if service not in IMAGE_IDS or service in container_services or fields[4] != IMAGE_IDS[service]:
            raise StockFixtureError("runtime_container_identity_mismatch")
        container_services.add(service)
    names = {"volume": _resource_names("volume", VOLUME, timeout=timeout),
             "network": _resource_names("network", NETWORK, timeout=timeout)}
    if any(item != VOLUME for item in names["volume"]) or any(item != NETWORK for item in names["network"]):
        raise StockFixtureError("runtime_resource_name_mismatch")
    label_format = '{{index .Labels "org.picketfence.wp5.owner"}}|{{index .Labels "org.picketfence.wp5.phase"}}'
    for kind, name in (("volume", VOLUME), ("network", NETWORK)):
        if name in names[kind]:
            raw = _command(_rtk_docker() + [kind, "inspect", "--format", label_format, name], timeout=timeout)
            if raw.decode("ascii", errors="strict").strip() != f"{OWNER}|{PHASE}":
                raise StockFixtureError(f"runtime_{kind}_ownership_mismatch")
    if ids and (VOLUME not in names["volume"] or NETWORK not in names["network"]):
        raise StockFixtureError("runtime_support_resource_missing")
    return {"containers": len(ids), "volume": VOLUME in names["volume"], "network": NETWORK in names["network"]}


def _wait_tls(host: str, port: int, server_name: str, ca: Path, deadline: float,
              *, exit_watch=None) -> None:
    last = "tls_not_ready"
    next_watch = 0.0
    container_running: bool | None = None
    while time.monotonic() < deadline:
        now = time.monotonic()
        if exit_watch is not None and now >= next_watch:
            container_running = exit_watch(deadline)
            next_watch = time.monotonic() + 1.0
        raw: socket.socket | None = None
        tls: ssl.SSLSocket | None = None
        try:
            remaining = min(3.0, deadline - time.monotonic())
            raw = socket.create_connection((host, port), timeout=remaining)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.keylog_filename = None
            context.load_verify_locations(cafile=str(ca))
            tls = context.wrap_socket(raw, server_hostname=server_name)
            if exit_watch is None or container_running is True:
                return
            last = "kong_container_state_unavailable"
        except (OSError, ssl.SSLError, TimeoutError):
            last = "tls_not_ready"
            time.sleep(0.5)
        finally:
            if tls is not None:
                tls.close()
            elif raw is not None:
                raw.close()
    raise StockFixtureError(last)


def _tls_http(host: str, port: int, server_name: str, ca: Path, request: bytes, deadline: float,
              *, read_status: bool, method: str = "GET") -> tuple[int, bytes, http.client.HTTPMessage]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise StockFixtureError("http_deadline_exceeded")
    raw: socket.socket | None = None
    tls: ssl.SSLSocket | None = None
    timer = None

    def interrupt() -> None:
        if tls is not None:
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    try:
        raw = socket.create_connection((host, port), timeout=remaining)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StockFixtureError("http_deadline_exceeded")
        raw.settimeout(remaining)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.keylog_filename = None
        context.load_verify_locations(cafile=str(ca))
        tls = context.wrap_socket(raw, server_hostname=server_name)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StockFixtureError("http_deadline_exceeded")
        tls.settimeout(remaining)
        timer = threading.Timer(remaining, interrupt)
        timer.daemon = True
        timer.start()
        tls.sendall(request)
        response = http.client.HTTPResponse(tls, method=method)
        response.begin()
        if not read_status:
            return response.status, b"", response.headers
        body = response.read(MAX_HTTP_BODY + 1)
        if len(body) > MAX_HTTP_BODY:
            raise StockFixtureError("http_body_limit")
        return response.status, body, response.headers
    except StockFixtureError:
        raise
    except Exception:
        raise StockFixtureError("https_request_failed") from None
    finally:
        if timer is not None:
            timer.cancel()
        if tls is not None:
            tls.close()
        elif raw is not None:
            raw.close()


def _header_values(headers: http.client.HTTPMessage, name: str, *, limit: int, max_chars: int) -> list[str]:
    values = headers.get_all(name, [])
    if not isinstance(values, list) or len(values) > limit:
        raise StockFixtureError("stock_response_headers_invalid")
    if any(not isinstance(value, str) or not value or len(value) > max_chars
           or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value)
           for value in values):
        raise StockFixtureError("stock_response_headers_invalid")
    return values


def _start_request(root: Path, deadline: float) -> tuple[int, str, list[str], bytes]:
    request = (b"GET /api/fapi/pkj-mtls HTTP/1.1\r\nHost: localhost:8443\r\n"
               b"Accept: text/html\r\nConnection: close\r\n\r\n")
    status, body, headers = _tls_http("127.0.0.1", 8443, "localhost", root / "ca/ca.crt",
                                      request, deadline, read_status=True)
    locations = _header_values(headers, "Location", limit=1, max_chars=16 * 1024)
    cookies = _header_values(headers, "Set-Cookie", limit=16, max_chars=16 * 1024)
    return status, locations[0] if locations else "", cookies, body


def _advance_relay_phase(root: Path, timeout_seconds: float) -> bool:
    if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 10:
        return False
    request = (b"POST /_control/session-ready HTTP/1.1\r\nHost: as-spike-harness:9443\r\n"
               b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    try:
        status, _body, _headers = _tls_http(
            "127.0.0.1", 19445, "as-spike-harness", root / "ca/ca.crt", request,
            time.monotonic() + float(timeout_seconds), read_status=True, method="POST",
        )
    except StockFixtureError:
        return False
    return status == 204


def _status_snapshot(root: Path, deadline: float) -> dict[str, Any]:
    request = b"GET /_status HTTP/1.1\r\nHost: as-spike-harness:9443\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    status, body, _headers = _tls_http("127.0.0.1", 19445, "as-spike-harness", root / "ca/ca.crt",
                                       request, deadline, read_status=True)
    if status != 200:
        raise StockFixtureError("relay_status_http_failure")
    if len(body) > 64 * 1024:
        raise StockFixtureError("relay_status_limit")
    try:
        snapshot = json.loads(body.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise StockFixtureError("relay_status_invalid") from None
    if not isinstance(snapshot, dict) or set(snapshot) != {"stage", "failed", "overflow", "events"}:
        raise StockFixtureError("relay_status_schema_invalid")
    if type(snapshot["failed"]) is not bool or type(snapshot["overflow"]) is not bool or not isinstance(snapshot["events"], list):
        raise StockFixtureError("relay_status_schema_invalid")
    if len(snapshot["events"]) > 32:
        raise StockFixtureError("relay_status_limit")
    return snapshot


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def _validate_par_event(snapshot: dict[str, Any]) -> dict[str, Any]:
    if snapshot["failed"] or snapshot["overflow"] or snapshot["stage"] != "par_complete":
        raise StockFixtureError("relay_par_failed")
    events = snapshot["events"]
    if len(events) != 1:
        raise StockFixtureError("stock_par_event_count")
    event = events[0]
    expected_fields = {
        "operation_id", "operation", "stage", "endpoint", "method", "path", "algorithm",
        "audience_is_issuer", "issuer_subject_match", "ttl_seconds", "remaining_ttl_seconds",
        "jti_distinct", "token_kind", "relay_attempted", "forwarded", "token_distinct", "http_status",
        "oauth_error_enum", "stock_form_client_id_present", "result",
    }
    if not isinstance(event, dict) or set(event) != expected_fields:
        raise StockFixtureError("relay_event_schema_invalid")
    if (not isinstance(event["operation_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", event["operation_id"])
        or event["operation"] != "par" or event["stage"] != "par_claim_gate"
        or event["endpoint"] != "par" or event["method"] != "POST" or event["path"] != PAR_PATH
        or event["algorithm"] != "PS256" or event["audience_is_issuer"] is not True
        or event["issuer_subject_match"] is not True or event["jti_distinct"] is not True
        or type(event["stock_form_client_id_present"]) is not bool
        or event["token_distinct"] is not True or event["token_kind"] != "not_applicable"
        or event["relay_attempted"] is not True or event["forwarded"] is not True or event["http_status"] != 201
        or event["oauth_error_enum"] != "none" or event["result"] != "as_accepted"):
        raise StockFixtureError("stock_par_claim_gate_failed")
    if (type(event["ttl_seconds"]) is not int or not 0 < event["ttl_seconds"] <= 60
        or type(event["remaining_ttl_seconds"]) is not int or event["remaining_ttl_seconds"] < 5):
        raise StockFixtureError("stock_par_ttl_gate_failed")
    return {**{key: event[key] for key in sorted(expected_fields)},
            "rfc9126_client_id_requirement_met": event["stock_form_client_id_present"]}


def _safe_flow_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "ok", "outcome", "http_requests", "redirects", "status_2xx", "status_3xx",
        "status_4xx", "status_5xx", "login_submissions", "consent_submissions",
        "callback_completed", "callback_http_status", "callback_error_enum",
        "session_cookie_changed", "phase_callback_called", "logout_completed",
    }
    if not isinstance(metrics, dict) or set(metrics) != expected:
        raise StockFixtureError("stock_flow_schema_invalid")
    if (type(metrics["ok"]) is not bool or not isinstance(metrics["outcome"], str) or metrics["outcome"] not in {
            "complete", "initial_response_rejected", "input_rejected", "location_rejected", "cookie_rejected",
            "transport_failure", "http_failure", "form_rejected", "callback_rejected", "session_cookie_missing",
            "phase_callback_failed", "secret_collector_failed", "logout_rejected", "budget_exceeded", "internal_failure",
        }
        or any(type(metrics[name]) is not int or metrics[name] < 0 or metrics[name] > 10 for name in (
            "http_requests", "redirects", "status_2xx", "status_3xx", "status_4xx", "status_5xx",
            "login_submissions", "consent_submissions",
        ))
        or type(metrics["callback_http_status"]) is not int or not 0 <= metrics["callback_http_status"] <= 599
        or not isinstance(metrics["callback_error_enum"], str)
        or metrics["callback_error_enum"] not in ({"none", "unknown"} | stock_flow.OAUTH_ERROR_ENUMS)
        or any(type(metrics[name]) is not bool for name in (
            "callback_completed", "session_cookie_changed", "phase_callback_called", "logout_completed",
        ))):
        raise StockFixtureError("stock_flow_schema_invalid")
    return {key: metrics[key] for key in sorted(expected)}


def _validate_stock_flow_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    safe = _safe_flow_metrics(metrics)
    if (safe["ok"] is not True or safe["outcome"] != "complete"
        or safe["http_requests"] > 10 or safe["login_submissions"] != 1
        or safe["consent_submissions"] > 1 or safe["callback_completed"] is not True
        or safe["callback_http_status"] not in stock_flow.REDIRECT_STATUSES or safe["callback_error_enum"] != "none"
        or safe["session_cookie_changed"] is not True or safe["phase_callback_called"] is not True
        or safe["logout_completed"] is not True):
        raise StockFixtureError("stock_flow_not_complete")
    return safe


def _validate_stock_operations(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    if snapshot["failed"] or snapshot["overflow"] or snapshot["stage"] != "session_logout":
        raise StockFixtureError("relay_stock_flow_failed")
    events = snapshot["events"]
    if len(events) != 3:
        raise StockFixtureError("stock_operation_count")
    if len({event["operation_id"] for event in events}) != len(events):
        raise StockFixtureError("stock_operation_id_duplicate")
    if sum(event["operation"] == "par" for event in events) != 1 or sum(
        event["operation"] == "revoke" for event in events
    ) != 2:
        raise StockFixtureError("stock_operation_set_invalid")
    par = next(event for event in events if event["operation"] == "par")
    revokes = [event for event in events if event["operation"] == "revoke"]
    if par["stage"] != "par_claim_gate" or par["http_status"] != 201 or par["result"] != "as_accepted":
        raise StockFixtureError("stock_par_acceptance_lost")
    if sorted(event["token_kind"] for event in revokes) != ["access_token", "refresh_token"]:
        raise StockFixtureError("stock_revoke_token_set_invalid")
    for event in [par, *revokes]:
        if (event["algorithm"] != "PS256" or event["audience_is_issuer"] is not True
            or event["issuer_subject_match"] is not True or event["jti_distinct"] is not True
            or event["token_distinct"] is not True or event["relay_attempted"] is not True
            or event["forwarded"] is not True or event["oauth_error_enum"] != "none"
            or event["result"] != "as_accepted" or type(event["stock_form_client_id_present"]) is not bool
            or type(event["ttl_seconds"]) is not int or not 0 < event["ttl_seconds"] <= 60
            or type(event["remaining_ttl_seconds"]) is not int or event["remaining_ttl_seconds"] < 5):
            raise StockFixtureError("stock_operation_claim_gate_failed")
    for event in revokes:
        if (event["stage"] != "session_logout" or event["http_status"] != 200
            or event["endpoint"] != "revoke" or event["method"] != "POST"
            or event["path"] != "/realms/fapi-demo/protocol/openid-connect/revoke"):
            raise StockFixtureError("stock_revoke_acceptance_failed")
    return [par, *sorted(revokes, key=lambda event: event["token_kind"])]


def _safe_relay_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    stages = {"par_claim_gate", "par_complete", "session_logout"}
    outcomes = {
        "pending", "as_accepted", "as_rejected", "assertion_encoding", "assertion_duplicate_json_key",
        "assertion_json", "public_key_unavailable", "public_key_type", "assertion_size", "assertion_shape",
        "assertion_header", "assertion_signature", "assertion_identity", "assertion_audience",
        "assertion_time_or_id", "assertion_ttl", "assertion_future_iat", "form_contract",
        "duplicate_form_parameter", "assertion_form", "par_form", "par_unknown_field",
        "par_client_id", "par_response_type", "par_response_mode", "revoke_form", "operation",
        "operation_id", "assertion_replay", "par_replay", "revoke_token_replay", "revoke_kind_replay",
        "as_deadline_exceeded", "as_response_too_large", "as_transport_failure", "internal_failure",
    }
    oauth_errors = {
        "none", "invalid_client", "invalid_request", "invalid_grant", "unauthorized_client",
        "unsupported_grant_type", "unsupported_response_type", "invalid_scope", "access_denied",
        "server_error", "temporarily_unavailable", "unknown",
    }
    if (set(snapshot) != {"stage", "failed", "overflow", "events"}
        or snapshot.get("stage") not in stages or type(snapshot.get("failed")) is not bool
        or type(snapshot.get("overflow")) is not bool or not isinstance(snapshot.get("events"), list)
        or len(snapshot["events"]) > 32):
        raise StockFixtureError("relay_snapshot_schema_invalid")
    expected_fields = {
        "operation_id", "operation", "stage", "endpoint", "method", "path", "algorithm",
        "audience_is_issuer", "issuer_subject_match", "ttl_seconds", "remaining_ttl_seconds",
        "jti_distinct", "token_kind", "relay_attempted", "forwarded", "token_distinct", "http_status",
        "oauth_error_enum", "stock_form_client_id_present", "result",
    }
    events = []
    for event in snapshot["events"]:
        if not isinstance(event, dict) or set(event) != expected_fields:
            raise StockFixtureError("relay_snapshot_schema_invalid")
        operation = event["operation"]
        expected = ("par", "POST", PAR_PATH) if operation == "par" else ("revoke", "POST", "/realms/fapi-demo/protocol/openid-connect/revoke")
        if (not isinstance(event["operation_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", event["operation_id"])
            or operation not in {"par", "revoke"} or event["stage"] not in stages
            or (event["endpoint"], event["method"], event["path"]) != expected
            or event["algorithm"] not in {"unknown", "PS256"}
            or any(type(event[name]) is not bool for name in (
                "audience_is_issuer", "issuer_subject_match", "jti_distinct", "relay_attempted",
                "forwarded", "token_distinct", "stock_form_client_id_present",
            ))
            or any(type(event[name]) is not int or not 0 <= event[name] <= 3600 for name in (
                "ttl_seconds", "remaining_ttl_seconds",
            ))
            or event["token_kind"] not in {"not_applicable", "access_token", "refresh_token"}
            or type(event["http_status"]) is not int or not 0 <= event["http_status"] <= 599
            or event["oauth_error_enum"] not in oauth_errors or event["result"] not in outcomes):
            raise StockFixtureError("relay_snapshot_schema_invalid")
        events.append({key: event[key] for key in sorted(expected_fields)})
    return {"stage": snapshot["stage"], "failed": snapshot["failed"],
            "overflow": snapshot["overflow"], "events": events}


def _candidate_secrets(root: Path) -> tuple[bytes, ...]:
    values = []
    for path in sorted(root.rglob("*.key")):
        if path.is_symlink() or not path.is_file():
            raise StockFixtureError("fixture_key_path_invalid")
        values.append(path.read_bytes())
    for path in sorted(root.rglob("*.pem")):
        if "public" not in path.name:
            values.append(path.read_bytes())
    license_path = root / "license/license.json"
    if license_path.is_symlink() or not license_path.is_file():
        raise StockFixtureError("fixture_license_path_invalid")
    values.append(license_path.read_bytes())
    realm_path = root / "realm/fapi-demo-realm.json"
    try:
        realm = json.loads(realm_path.read_bytes())
        users = realm["users"]
        if (not isinstance(users, list) or len(users) != 1 or users[0].get("username") != DEMO_USERNAME
            or not isinstance(users[0].get("credentials"), list) or len(users[0]["credentials"]) != 1):
            raise ValueError("fixture user invalid")
        password = users[0]["credentials"][0].get("value")
        if not isinstance(password, str) or not password or len(password) > 1024:
            raise ValueError("fixture user invalid")
        values.append(password.encode("utf-8"))
    except Exception:
        raise StockFixtureError("fixture_user_config_invalid") from None
    config = (root / "kong/kong.json").read_bytes()
    try:
        parsed = json.loads(config)
        jwk = parsed["services"][0]["plugins"][1]["config"]["client_jwk"][0]
        for field in ("d", "p", "q", "dp", "dq", "qi"):
            values.append(jwk[field].encode("ascii"))
        oidc = parsed["services"][0]["plugins"][1]["config"]
        for field in ("session_secret", "cache_tokens_salt"):
            value = oidc.get(field)
            if not isinstance(value, str) or not value:
                raise ValueError("missing private config value")
            values.append(value.encode("ascii"))
    except Exception:
        raise StockFixtureError("fixture_key_config_invalid") from None
    return tuple(values)


def _demo_credentials(root: Path) -> tuple[str, str]:
    try:
        realm = json.loads((root / "realm/fapi-demo-realm.json").read_bytes())
        users = realm["users"]
        if (realm.get("realm") != "fapi-demo" or not isinstance(users, list) or len(users) != 1
            or users[0].get("username") != DEMO_USERNAME or users[0].get("enabled") is not True
            or users[0].get("firstName") != "WP5" or users[0].get("lastName") != "Demo"
            or users[0].get("email") != DEMO_USERNAME + "@example.invalid"
            or users[0].get("requiredActions") != []):
            raise ValueError("fixture user invalid")
        credentials = users[0].get("credentials")
        if (not isinstance(credentials, list) or len(credentials) != 1
            or credentials[0].get("type") != "password" or credentials[0].get("temporary") is not False):
            raise ValueError("fixture user invalid")
        password = credentials[0].get("value")
        if not isinstance(password, str) or not 32 <= len(password) <= 128:
            raise ValueError("fixture user invalid")
        return DEMO_USERNAME, password
    except Exception:
        raise StockFixtureError("fixture_user_config_invalid") from None


def _leak_scan(raw: bytes, secrets_to_check: tuple[bytes, ...]) -> dict[str, int]:
    patterns = {
        "pem_private_key": re.compile(rb"-----BEGIN (?:EC |RSA |PRIVATE )?PRIVATE KEY-----"),
        "pem_certificate": re.compile(rb"-----BEGIN CERTIFICATE-----"),
        "jwt_value": re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "cookie_value": re.compile(rb"(?i)(?:set-cookie|cookie)\s*[:=]\s*[^\r\n]{8,}"),
        "authorization_value": re.compile(rb"(?i)(?:authorization\s*[:=]\s*bearer|bearer\s+)[A-Za-z0-9._~+/-]{12,}"),
    }
    found = {name: len(pattern.findall(raw)) for name, pattern in patterns.items() if pattern.search(raw)}
    for value in secrets_to_check:
        if value and value in raw:
            found["fixture_private_material"] = found.get("fixture_private_material", 0) + 1
    return found


def _capture_keycloak_logs(root: Path, *, timeout: int = MAX_COMMAND_SECONDS,
                           extra_secrets: tuple[bytes, ...] = ()) -> tuple[bytes, list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    raw = _compose(root, "logs", "--no-color", "--no-log-prefix", timeout=timeout,
                   cap=MAX_OUTPUT)
    if len(extra_secrets) > MAX_RUNTIME_SECRET_VALUES or any(
        not isinstance(value, bytes) or len(value) > MAX_RUNTIME_SECRET_VALUE for value in extra_secrets
    ) or sum(map(len, extra_secrets)) > MAX_RUNTIME_SECRET_BYTES:
        raise StockFixtureError("runtime_secret_scan_input_invalid")
    leaks = _leak_scan(raw, _candidate_secrets(root) + tuple(value for value in extra_secrets if value))
    try:
        from observation_parser import ObservationError, parse_observer_rows
        rows = parse_observer_rows(raw)
    except ImportError:
        raise StockFixtureError("observer_parser_unavailable") from None
    except ObservationError as error:
        raise StockFixtureError("observer_parser_" + error.code) from None
    return raw, rows, leaks, _safe_runtime_log_diagnostics(raw)


def _parse_stock_token_diagnostic(raw: bytes) -> dict[str, Any] | None:
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        raise StockFixtureError("stock_token_diagnostic_input_invalid")
    marker_rows: list[bytes] = []
    for line in raw.splitlines():
        marker_at = line.find(STOCK_TOKEN_MARKER)
        if marker_at >= 0:
            marker_rows.append(line[marker_at + len(STOCK_TOKEN_MARKER):])
            if len(marker_rows) > 1:
                raise StockFixtureError("stock_token_diagnostic_duplicate")
    if not marker_rows:
        return None
    encoded = marker_rows[0]
    if len(encoded) > 8192:
        raise StockFixtureError("stock_token_diagnostic_oversized")

    def no_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        decoder = json.JSONDecoder(object_pairs_hook=no_duplicate_keys)
        row, _end = decoder.raw_decode(encoded.decode("utf-8").lstrip())
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise StockFixtureError("stock_token_diagnostic_invalid") from None
    if not isinstance(row, dict) or set(row) != STOCK_TOKEN_DIAGNOSTIC_KEYS:
        raise StockFixtureError("stock_token_diagnostic_schema_invalid")
    if type(row["v"]) is not int or row["v"] != 1:
        raise StockFixtureError("stock_token_diagnostic_schema_invalid")
    bool_fields = (
        "ssl_client_cert_present", "ssl_client_priv_key_present",
        "client_assertion_present", "client_assertion_type_present",
    )
    if any(type(row[name]) is not bool for name in bool_fields):
        raise StockFixtureError("stock_token_diagnostic_schema_invalid")
    status = row["response_status"]
    if type(status) is not int or (status != 0 and not 100 <= status <= 599):
        raise StockFixtureError("stock_token_diagnostic_schema_invalid")
    if row["oauth_error_enum"] not in STOCK_TOKEN_OAUTH_ERRORS:
        raise StockFixtureError("stock_token_diagnostic_schema_invalid")
    keyword_presence = row["error_description_keyword_presence"]
    if (not isinstance(keyword_presence, dict) or set(keyword_presence) != set(KONG_OIDC_KEYWORDS)
        or any(type(value) is not bool for value in keyword_presence.values())):
        raise StockFixtureError("stock_token_diagnostic_schema_invalid")
    return {
        "v": row["v"],
        **{name: row[name] for name in bool_fields},
        "response_status": status,
        "oauth_error_enum": row["oauth_error_enum"],
        "error_description_keyword_presence": {
            name: keyword_presence[name] for name in KONG_OIDC_KEYWORDS
        },
    }


def _safe_runtime_log_diagnostics(raw: bytes) -> dict[str, Any]:
    """Return fixed error-family counts; never retain log text or arbitrary field values."""
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        raise StockFixtureError("runtime_log_diagnostic_input_invalid")
    keycloak_counts = {name: 0 for name in sorted(KEYCLOAK_ERROR_VALUES)}
    keycloak_counts["unknown"] = 0
    for line in raw.splitlines():
        if b"org.keycloak" not in line.lower():
            continue
        for match in KEYCLOAK_ERROR_FIELD_RE.finditer(line):
            error_name = match.group(1).decode("ascii")
            keycloak_counts[error_name if error_name in KEYCLOAK_ERROR_VALUES else "unknown"] += 1

    kong_counts = {name: 0 for name in KONG_OIDC_ERROR_CATEGORIES}
    keyword_presence = {keyword: False for keyword in KONG_OIDC_KEYWORDS}
    oidc_error_lines = 0
    for line in raw.splitlines():
        lower = line.lower()
        if not (b"openid-connect" in lower or b"openid_connect" in lower or b"openid connect" in lower):
            continue
        # Kong runs at `err`, so only OIDC plugin lines are counted here. Classify with
        # fixed signatures and retain counts only; unknown OIDC errors remain explicit.
        oidc_error_lines += 1
        message = re.split(rb",\s*client:\s*", line, maxsplit=1, flags=re.IGNORECASE)[0]
        for keyword, pattern in KONG_OIDC_KEYWORD_PATTERNS.items():
            if pattern.search(message):
                keyword_presence[keyword] = True
        if any(marker in lower for marker in (b"token endpoint", b"token_endpoint", b"access token", b"token request")):
            category = "token_endpoint_failure"
        elif any(marker in lower for marker in (b"authorization code", b"code exchange", b"code_verifier", b"pkce")):
            category = "authorization_code_failure"
        elif any(marker in lower for marker in (b"client authentication", b"client_assertion", b"invalid_client")):
            category = "client_authentication_failure"
        else:
            category = "other_oidc_error"
        kong_counts[category] += 1
    return {
        "keycloak_error_counts": keycloak_counts,
        "kong_oidc_error_counts": kong_counts,
        "kong_oidc_error_lines": oidc_error_lines,
        "kong_oidc_keyword_presence": keyword_presence,
        "stock_token_diagnostic": _parse_stock_token_diagnostic(raw),
    }


def _safe_observer_diagnostics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep only the strict parser's canonical public fields and bounded counts."""
    if len(rows) > 256:
        raise StockFixtureError("observer_diagnostic_limit")
    allowed_errors = {
        "none", "peer_absent", "correlation_invalid", "peer_validation_failed",
        "no_request_context", "request_context_unavailable", "request_marker_unavailable",
        "request_unavailable", "observer_failure",
    }
    counts = {name: 0 for name in sorted(allowed_errors)}
    safe_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "v", "observed_at", "correlation_id", "endpoint", "method", "path", "peer_present",
            "chain_count", "pkix", "valid_now", "client_auth_eku", "leaf_sha256", "error",
        } or row.get("error") not in allowed_errors:
            raise StockFixtureError("observer_diagnostic_schema_invalid")
        counts[row["error"]] += 1
        safe_rows.append({key: row[key] for key in (
            "v", "observed_at", "correlation_id", "endpoint", "method", "path", "peer_present",
            "chain_count", "pkix", "valid_now", "client_auth_eku", "leaf_sha256", "error",
        )})
    return {"validated_rows": safe_rows, "error_counts": counts}


def _join_par(event: dict[str, Any], rows: list[dict[str, Any]], receipt: dict[str, Any]) -> dict[str, Any]:
    par_rows = [row for row in rows if row["endpoint"] == "par"]
    auxiliary: dict[str, int] = {"discovery": 0, "jwks": 0, "token": 0}
    for row in rows:
        if row["endpoint"] in auxiliary:
            expected_pair = {
                "discovery": ("GET", "realms/fapi-demo/.well-known/openid-configuration"),
                "jwks": ("GET", "realms/fapi-demo/protocol/openid-connect/certs"),
                "token": ("POST", "realms/fapi-demo/protocol/openid-connect/token"),
            }[row["endpoint"]]
            if row["error"] != "correlation_invalid" or (row["method"], row["path"]) != expected_pair:
                raise StockFixtureError("auxiliary_observer_outcome_unexpected")
            auxiliary[row["endpoint"]] += 1
        elif row["endpoint"] != "par":
            raise StockFixtureError("observer_unexpected_endpoint")
    if (auxiliary["discovery"] > MAX_AUX_DISCOVERY or auxiliary["jwks"] > MAX_AUX_JWKS
        or auxiliary["token"] > MAX_AUX_TOKEN):
        raise StockFixtureError("observer_auxiliary_limit")
    if len(par_rows) != 1:
        raise StockFixtureError("par_observer_count")
    row = par_rows[0]
    if (row["correlation_id"] != event["operation_id"] or row["method"] != "POST"
        or row["path"] != PAR_PATH.lstrip("/") or row["peer_present"] is not True
        or row["chain_count"] < 1 or row["pkix"] is not True or row["valid_now"] is not True
        or row["client_auth_eku"] is not True or row["leaf_sha256"] != receipt["route_b_leaf_sha256"]
        or row["error"] != "none"):
        raise StockFixtureError("par_observer_join_failed")
    return {
        "rows_total": len(rows), "par_rows": 1, "par_observer_joined": True,
        "auxiliary_counts": auxiliary,
        "peer": {key: row[key] for key in (
            "peer_present", "chain_count", "pkix", "valid_now", "client_auth_eku", "error",
        )},
        "route_b_leaf_matches": True,
        "correlation_id": row["correlation_id"],
    }


def _join_stock_operations(events: list[dict[str, Any]], rows: list[dict[str, Any]],
                           receipt: dict[str, Any]) -> dict[str, Any]:
    expected_by_endpoint = {"par": [event for event in events if event["operation"] == "par"],
                            "revoke": [event for event in events if event["operation"] == "revoke"]}
    actual_by_endpoint: dict[str, list[dict[str, Any]]] = {"par": [], "revoke": []}
    auxiliary = {"discovery": 0, "jwks": 0, "token": 0}
    auxiliary_paths = {
        "discovery": ("GET", "realms/fapi-demo/.well-known/openid-configuration"),
        "jwks": ("GET", "realms/fapi-demo/protocol/openid-connect/certs"),
        "token": ("POST", "realms/fapi-demo/protocol/openid-connect/token"),
    }
    for row in rows:
        endpoint = row["endpoint"]
        if endpoint in actual_by_endpoint:
            actual_by_endpoint[endpoint].append(row)
        elif endpoint in auxiliary:
            if (row["error"] != "correlation_invalid"
                or (row["method"], row["path"]) != auxiliary_paths[endpoint]):
                raise StockFixtureError("auxiliary_observer_outcome_unexpected")
            auxiliary[endpoint] += 1
        else:
            raise StockFixtureError("observer_unexpected_endpoint")
    if (auxiliary["discovery"] > MAX_AUX_DISCOVERY or auxiliary["jwks"] > MAX_AUX_JWKS
        or auxiliary["token"] > MAX_AUX_TOKEN):
        raise StockFixtureError("observer_auxiliary_limit")
    joined: list[dict[str, Any]] = []
    for endpoint, expected in expected_by_endpoint.items():
        actual = actual_by_endpoint[endpoint]
        if len(actual) != len(expected):
            raise StockFixtureError("stock_observer_operation_count")
        by_id = {row["correlation_id"]: row for row in actual}
        if len(by_id) != len(actual):
            raise StockFixtureError("stock_observer_operation_duplicate")
        for event in expected:
            row = by_id.get(event["operation_id"])
            expected_path = PAR_PATH.lstrip("/") if endpoint == "par" else \
                "/realms/fapi-demo/protocol/openid-connect/revoke".lstrip("/")
            if (row is None or row["method"] != "POST" or row["path"] != expected_path
                or row["peer_present"] is not True or row["chain_count"] < 1 or row["pkix"] is not True
                or row["valid_now"] is not True or row["client_auth_eku"] is not True
                or row["leaf_sha256"] != receipt["route_b_leaf_sha256"] or row["error"] != "none"):
                raise StockFixtureError("stock_observer_operation_join_failed")
            joined.append({
                "operation": endpoint, "operation_id": event["operation_id"],
                "peer_present": row["peer_present"], "chain_count": row["chain_count"],
                "pkix": row["pkix"], "valid_now": row["valid_now"],
                "client_auth_eku": row["client_auth_eku"], "route_b_leaf_matches": True,
                "error": row["error"],
            })
    return {"rows_total": len(rows), "operation_joins": joined,
            "operation_join_count": len(joined), "auxiliary_counts": auxiliary}


def _ports_released(ports: tuple[int, ...], timeout: float = 30.0) -> dict[str, bool]:
    deadline = time.monotonic() + min(timeout, 30.0)
    remaining = set(ports)
    released = {str(port): False for port in ports}
    while remaining and time.monotonic() < deadline:
        for port in tuple(remaining):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("127.0.0.1", port))
                released[str(port)] = True
                remaining.remove(port)
            except OSError:
                pass
            finally:
                probe.close()
        if remaining:
            time.sleep(0.25)
    return released


def _remove_fixture(root: Path) -> bool:
    expected = FIXTURE_ROOT.absolute()
    target = root.absolute()
    if target != expected or target.parent != Path("/private/tmp") or target.is_symlink():
        raise StockFixtureError("fixture_cleanup_path_mismatch")
    if target.exists():
        shutil.rmtree(target)
    return not target.exists()


def _write_receipt_exclusive(path: Path, value: dict[str, Any]) -> None:
    _write_exclusive(path, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())


def run_stock_par(root: Path = FIXTURE_ROOT, prep_path: Path = PREP_RECEIPT,
                  intent_path: Path = RUN_INTENT, receipt_path: Path = RUN_RECEIPT,
                  *, approved_single_attempt: bool = False) -> dict[str, Any]:
    if not approved_single_attempt:
        raise StockFixtureError("single_attempt_flag_required")
    if (root.absolute() != FIXTURE_ROOT.absolute() or prep_path.absolute() != PREP_RECEIPT.absolute()
        or intent_path.absolute() != RUN_INTENT.absolute() or receipt_path.absolute() != RUN_RECEIPT.absolute()):
        raise StockFixtureError("runtime_paths_not_fixed")
    if intent_path.exists() or receipt_path.exists() or intent_path.is_symlink() or receipt_path.is_symlink():
        raise StockFixtureError("run_receipt_path_exists")
    prepared = verify_prepared_fixture(root, prep_path)
    prep_sha = _sha256(prep_path.read_bytes())
    preflight_absent()
    _compose(root, "config", "--quiet", timeout=MAX_COMMAND_SECONDS)
    intent = {
        "schema": "wp5-stock-par-intent-v15", "result": "started",
        "prepared_receipt_sha256": prep_sha, "source_hashes": prepared["source_hashes"],
        "project": PROJECT, "images": IMAGE_IDS.copy(),
        "scope": "one stock Route B auth-start/PAR and conditional browser session plus stock logout revokes",
        "stage2": "conditional_after_par_and_observer_join", "automatic_retry": False,
    }
    _write_receipt_exclusive(intent_path, intent)
    intent_sha = _sha256(intent_path.read_bytes())
    record: dict[str, Any] = {
        "schema": "wp5-stock-par-run-v15", "result": "failed", "phase": "intent_written",
        "failure_category": None, "stage2": "not_run", "prepared_receipt_sha256": prep_sha,
        "intent_sha256": intent_sha, "source_hashes": prepared["source_hashes"],
        "single_attempt": True, "stock_auth_start": {"status": None, "location_present": False, "set_cookie_count": 0},
        "stock_par": None, "rfc9126_client_id_requirement_met": None, "relay_snapshot": None,
        "observer_join": None, "stock_flow": None, "stock_operations": None,
        "stock_operations_join": None, "par_diagnostic": None,
        "hostgateway_tls_preflight": False,
        "diagnostic": {"attempted": False, "complete": False, "rows": 0, "log_sha256": None,
                       "leak_counts": {}, "validated_rows": [], "error_counts": {},
                       "runtime_log_diagnostics": _safe_runtime_log_diagnostics(b"")},
        "cleanup": {"attempted": False, "ownership_verified": False, "down": "not_run",
                    "resources_absent": False, "ports_released": {}, "private_fixture_removed": False},
    }
    may_have_started = False
    total_deadline = time.monotonic() + MAX_TOTAL_SECONDS
    runtime_sensitive_values: list[bytes] = []
    runtime_sensitive_total = 0

    def collect_runtime_secret(value: bytes) -> None:
        nonlocal runtime_sensitive_total
        if (not isinstance(value, bytes) or len(value) > MAX_RUNTIME_SECRET_VALUE
            or len(runtime_sensitive_values) >= MAX_RUNTIME_SECRET_VALUES
            or runtime_sensitive_total + len(value) > MAX_RUNTIME_SECRET_BYTES):
            raise ValueError("secret scan input limit")
        runtime_sensitive_values.append(value)
        runtime_sensitive_total += len(value)

    def remaining_total() -> int:
        remaining = int(total_deadline - time.monotonic())
        if remaining <= 0:
            raise StockFixtureError("runtime_deadline_exceeded")
        return min(MAX_COMMAND_SECONDS, remaining)

    cleanup_deadline = total_deadline

    def remaining_cleanup() -> int:
        remaining = int(min(cleanup_deadline, total_deadline) - time.monotonic())
        if remaining <= 0:
            raise StockFixtureError("cleanup_deadline_exceeded")
        return min(MAX_COMMAND_SECONDS, remaining)

    def fail(code: str, phase: str) -> None:
        if record["failure_category"] is None:
            record["failure_category"] = code
            record["phase"] = phase
            record["result"] = "needs_design" if code.startswith((
                "stock_par_", "stock_authorization_", "stock_flow_", "stock_operation_",
                "par_observer_", "observer_", "hostgateway_",
            )) else "failed"

    try:
        record["phase"] = "compose_up"
        may_have_started = True
        _compose(root, "up", "-d", "--no-build", "--pull", "never", timeout=remaining_total())
        startup_deadline = min(total_deadline, time.monotonic() + MAX_STARTUP_SECONDS)
        for port, host_name in ((8444, "localhost"), (8443, "localhost"), (19445, "as-spike-harness")):
            record["phase"] = "tls_startup"
            _wait_tls("127.0.0.1", port, host_name, root / "ca/ca.crt", startup_deadline,
                      exit_watch=_check_kong_start_state)
        record["phase"] = "hostgateway_tls_preflight"
        _verify_kong_hostgateway_route()
        record["hostgateway_tls_preflight"] = True
        record["phase"] = "stock_authorization_start"
        try:
            status, initial_location, initial_cookies, initial_body = _start_request(
                root, min(total_deadline, time.monotonic() + 10),
            )
        except StockFixtureError as error:
            fail(error.code, "stock_authorization_start")
            # A client-side timeout can follow a completed upstream POST. Capture the
            # relay's fixed snapshot once so the receipt distinguishes that from not_sent.
            record["phase"] = "stock_par_snapshot"
            try:
                record["relay_snapshot"] = _safe_relay_snapshot(
                    _status_snapshot(root, min(total_deadline, time.monotonic() + 10)),
                )
            except Exception as snapshot_error:
                record["relay_snapshot_failure"] = (
                    snapshot_error.code if isinstance(snapshot_error, StockFixtureError)
                    else "relay_snapshot_failed"
                )
            raise
        record["stock_auth_start"]["status"] = status
        record["stock_auth_start"]["location_present"] = bool(initial_location)
        record["stock_auth_start"]["set_cookie_count"] = len(initial_cookies)
        if initial_location:
            collect_runtime_secret(initial_location.encode("utf-8"))
        for cookie in initial_cookies:
            collect_runtime_secret(cookie.encode("utf-8"))
        if initial_body:
            collect_runtime_secret(initial_body)
        if status != 302:
            fail("stock_authorization_not_redirect", "stock_authorization_start")
        record["phase"] = "stock_par_snapshot"
        snapshot = _safe_relay_snapshot(_status_snapshot(root, min(total_deadline, time.monotonic() + 10)))
        record["relay_snapshot"] = snapshot
        if status != 302:
            raise StockFixtureError("stock_authorization_not_redirect")
        event = _validate_par_event(snapshot)
        record["stock_par"] = event
        record["rfc9126_client_id_requirement_met"] = event["rfc9126_client_id_requirement_met"]
        record["phase"] = "par_observer_gate"
        par_raw, par_rows, par_leaks, par_log_diagnostics = _capture_keycloak_logs(
            root, timeout=remaining_total(), extra_secrets=tuple(runtime_sensitive_values),
        )
        par_safe = _safe_observer_diagnostics(par_rows)
        record["par_diagnostic"] = {
            "complete": True, "rows": len(par_rows), "log_bytes": len(par_raw),
            "log_sha256": _sha256(par_raw), "leak_counts": par_leaks,
            "runtime_log_diagnostics": par_log_diagnostics, **par_safe,
        }
        if par_leaks:
            raise StockFixtureError("stock_authorization_log_leak")
        try:
            record["observer_join"] = _join_par(event, par_rows, prepared)
        except StockFixtureError as error:
            raise StockFixtureError("par_observer_" + error.code) from None

        username, password = _demo_credentials(root)
        record["stage2"] = "running"
        record["phase"] = "stock_browser_session_logout"
        metrics = stock_flow.run_stock_flow(
            status, initial_location, initial_cookies, root / "ca/ca.crt", username, password,
            on_session_ready=lambda timeout: _advance_relay_phase(root, timeout),
            on_sensitive_value=collect_runtime_secret,
        )
        record["stock_flow"] = _safe_flow_metrics(metrics)
        record["phase"] = "stock_operations_snapshot"
        final_snapshot = _safe_relay_snapshot(_status_snapshot(root, min(total_deadline, time.monotonic() + 10)))
        record["relay_snapshot"] = final_snapshot
        if record["stock_flow"]["ok"] is not True:
            record["stage2"] = "failed"
            raise StockFixtureError("stock_flow_not_complete")
        record["stock_flow"] = _validate_stock_flow_metrics(record["stock_flow"])
        record["stock_operations"] = _validate_stock_operations(final_snapshot)
        record["stage2"] = "complete"
    except StockFixtureError as error:
        if record["stage2"] == "running":
            record["stage2"] = "failed"
        fail(error.code, record.get("phase", "runtime"))
    except Exception:
        if record["stage2"] == "running":
            record["stage2"] = "failed"
        fail("internal_failure", record.get("phase", "runtime"))
    finally:
        cleanup_deadline = min(total_deadline, time.monotonic() + MAX_CLEANUP_SECONDS)
        record["phase_before_cleanup"] = record["phase"]
        ownership: dict[str, Any] | None = None
        if may_have_started:
            try:
                ownership = verify_owned_resources(allow_partial=True, timeout=remaining_cleanup())
                record["cleanup"]["ownership_verified"] = True
                record["cleanup"]["owned_resources_before_down"] = ownership
            except Exception:
                fail("ownership_check_failed", "ownership_check")
                record["cleanup"]["down"] = "ownership_unverified"
        else:
            record["cleanup"]["ownership_verified"] = True
            ownership = {"containers": 0, "volume": False, "network": False}

        containers_exist = bool(ownership and ownership["containers"] > 0)
        if containers_exist and record["cleanup"]["ownership_verified"]:
            record["cleanup"]["attempted"] = True
            try:
                _compose(root, "stop", "--timeout", "10", timeout=remaining_cleanup())
                record["cleanup"]["stop"] = "complete"
            except Exception:
                record["cleanup"]["stop"] = "stop_failed"
                fail("cleanup_stop_failed", "stop")
            try:
                raw, rows, leaks, log_diagnostics = _capture_keycloak_logs(
                    root, timeout=remaining_cleanup(), extra_secrets=tuple(runtime_sensitive_values),
                )
                safe_rows = _safe_observer_diagnostics(rows)
                record["diagnostic"] = {
                    "attempted": True, "complete": True, "rows": len(rows),
                    "log_bytes": len(raw), "log_sha256": _sha256(raw),
                    "leak_counts": leaks, "runtime_log_diagnostics": log_diagnostics, **safe_rows,
                }
                if leaks:
                    fail("observer_log_leak_detected", "diagnostic_scan")
                if record["stock_operations"] is not None:
                    try:
                        record["stock_operations_join"] = _join_stock_operations(
                            record["stock_operations"], rows, prepared,
                        )
                    except StockFixtureError as error:
                        fail(error.code, "stock_operations_observer_join")
                elif record["stock_par"] is not None and record["observer_join"] is None:
                    try:
                        record["observer_join"] = _join_par(record["stock_par"], rows, prepared)
                    except StockFixtureError as error:
                        fail(error.code, "observer_join")
            except Exception as error:
                code = error.code if isinstance(error, StockFixtureError) else "diagnostic_capture_failed"
                record["diagnostic"] = {
                    "attempted": True, "complete": False, "failure_category": code, "rows": 0,
                    "log_sha256": None, "leak_counts": {}, "validated_rows": [],
                    "error_counts": {}, "runtime_log_diagnostics": _safe_runtime_log_diagnostics(b""),
                }
                fail(code, "diagnostic_scan")
        else:
            record["cleanup"]["stop"] = "no_owned_containers"
            record["diagnostic"] = {
                "attempted": False, "complete": False, "rows": 0, "log_sha256": None,
                "leak_counts": {}, "validated_rows": [], "error_counts": {},
                "runtime_log_diagnostics": _safe_runtime_log_diagnostics(b""),
            }

        cleanup_ownership_verified = record["cleanup"]["ownership_verified"]
        existing = ownership
        if cleanup_ownership_verified and existing is not None:
            has_owned = existing["containers"] > 0 or existing["volume"] or existing["network"]
            if has_owned:
                try:
                    # Revalidate all exact owner/service/image labels before scoped Compose down.
                    verify_owned_resources(allow_partial=True, timeout=remaining_cleanup())
                    record["cleanup"]["down"] = "attempted"
                    _compose(root, "down", "--volumes", "--timeout", "10", timeout=remaining_cleanup())
                    record["cleanup"]["down"] = "complete"
                except Exception:
                    record["cleanup"]["down"] = "down_failed"
                    fail("cleanup_down_failed", "cleanup_down")
            else:
                record["cleanup"]["down"] = "no_owned_resources"
            try:
                after = verify_owned_resources(allow_partial=True, timeout=remaining_cleanup())
                absent = after == {"containers": 0, "volume": False, "network": False}
                record["cleanup"]["resources_absent"] = absent
                if not absent:
                    fail("runtime_resources_remain", "cleanup_verify")
            except Exception:
                absent = False
                record["cleanup"]["resources_absent"] = False
                fail("cleanup_verification_failed", "cleanup_verify")
        else:
            absent = False
            record["cleanup"]["resources_absent"] = False

        try:
            record["cleanup"]["ports_released"] = _ports_released(HOST_PORTS, timeout=min(30.0, max(0.0, cleanup_deadline - time.monotonic())))
            if not all(record["cleanup"]["ports_released"].values()):
                fail("runtime_port_not_released", "port_cleanup")
        except Exception:
            record["cleanup"]["ports_released"] = {str(port): False for port in HOST_PORTS}
            fail("runtime_port_check_failed", "port_cleanup")

        # Once exact Docker objects are independently absent, the private host material is no longer mounted.
        # A transient port-bind failure is recorded but does not skip safe recovery of the fixture tree.
        if record["cleanup"]["resources_absent"]:
            try:
                record["cleanup"]["private_fixture_removed"] = _remove_fixture(root)
                if not record["cleanup"]["private_fixture_removed"]:
                    fail("private_fixture_removal_incomplete", "private_cleanup")
            except Exception:
                fail("private_fixture_removal_failed", "private_cleanup")
        else:
            record["cleanup"]["private_fixture_removed"] = False
        if (record["failure_category"] is None and record["stock_par"] is not None
            and record["stock_flow"] is not None and record["stock_flow"].get("ok") is True
            and record["stock_operations_join"] is not None
            and record["stock_operations_join"].get("operation_join_count") == 3):
            record["result"] = "pass"
            record["phase"] = "complete"
        else:
            record["result"] = record["result"] if record["result"] == "needs_design" else "failed"
        try:
            _write_receipt_exclusive(receipt_path, record)
        except Exception:
            # Never emit receipt contents or underlying OS errors to stdout/stderr.
            print(json.dumps({"result": "failed", "failure_category": "terminal_receipt_write_failed"}, sort_keys=True))
            raise SystemExit(2)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--fixture-root", type=Path, default=FIXTURE_ROOT)
    prepare.add_argument("--receipt", type=Path, default=PREP_RECEIPT)
    run = commands.add_parser("run")
    run.add_argument("--approved-single-attempt", action="store_true")
    run.add_argument("--fixture-root", type=Path, default=FIXTURE_ROOT)
    run.add_argument("--prep-receipt", type=Path, default=PREP_RECEIPT)
    run.add_argument("--intent", type=Path, default=RUN_INTENT)
    run.add_argument("--receipt", type=Path, default=RUN_RECEIPT)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_stock_fixture(args.fixture_root, args.receipt)
            print(json.dumps({"result": result["result"], "fixture_root": result["fixture_root"],
                              "receipt": str(args.receipt), "file_count": result["file_count"]}, sort_keys=True))
            return
        result = run_stock_par(args.fixture_root, args.prep_receipt, args.intent, args.receipt,
                               approved_single_attempt=args.approved_single_attempt)
        print(json.dumps({"result": result["result"], "phase": result["phase"],
                          "failure_category": result["failure_category"], "receipt": str(args.receipt)}, sort_keys=True))
        if result["result"] != "pass":
            raise SystemExit(2)
    except StockFixtureError as error:
        print(json.dumps({"result": "failed", "failure_category": error.code}, sort_keys=True))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
