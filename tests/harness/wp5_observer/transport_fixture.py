#!/usr/bin/env python3
"""Isolated direct AS-peer transport integration fixture for WP5 5c."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Reuse the already-reviewed certificate, exclusive-write, command-bound, and
# in-memory leak-scan helpers from the accepted 5a fixture.
import stock_fixture as _stock  # noqa: E402
from observation_parser import ObservationError, parse_observer_rows  # noqa: E402
import stock_flow  # noqa: E402

FIXTURE_ROOT = Path("/private/tmp/wp5-as-peer-transport-20261004-v6")
PREP_RECEIPT = Path("/private/tmp/wp5-as-peer-transport-prep-receipt-20261004-v6.json")
RUN_INTENT = Path("/private/tmp/wp5-as-peer-transport-run-intent-20261004-v6.json")
RUN_RECEIPT = Path("/private/tmp/wp5-as-peer-transport-run-receipt-20261004-v6.json")

PROJECT = "wp5-as-peer-transport-v6"
VOLUME = "wp5-as-peer-transport-v6-data"
NETWORK = PROJECT + "_default"
OWNER = "wp5-luna"
PHASE = "observer-as-peer-transport-v6"
GENERATION_PATTERN = re.compile(r"[a-f0-9]{32}\Z")
ISSUER = "https://localhost:8444/realms/fapi-demo"
INTERNAL_ORIGIN = "https://keycloak:8443"
KONG_IMAGE_ID = _stock.IMAGE_IDS["kong"]
KEYCLOAK_IMAGE_ID = _stock.IMAGE_IDS["keycloak"]
IMAGE_IDS = {"kong": KONG_IMAGE_ID, "keycloak": KEYCLOAK_IMAGE_ID}
HOST_PORTS = (8443, 8444)
ROUTE_IDS = {
    "A": "754519ff-b0b9-5ed5-94c0-e453d260c6c4",
    "B": "0f45debe-a3a6-5207-aea3-637227fb96f2",
}
CLIENT_IDS = {"A": "third-party-fapi-mtls", "B": "third-party-fapi-pkj-mtls"}
CLIENT_NAMES = {"A": "third-party-fapi-mtls", "B": "third-party-fapi-pkj-mtls"}
CLIENT_CN = {"A": "third-party-fapi-mtls", "B": "third-party-fapi-pkj-mtls"}
CLIENT_AUTH = {"A": "tls_client_auth", "B": "private_key_jwt"}
CALLBACKS = {
    "A": ("/api/fapi/mtls", "https://localhost:8443/api/fapi/mtls"),
    "B": ("/api/fapi/pkj-mtls", "https://localhost:8443/api/fapi/pkj-mtls"),
}
USERNAMES = {"A": "wp5-transport-route-a", "B": "wp5-transport-route-b"}
MAX_COMMAND_SECONDS = 60
MAX_STARTUP_SECONDS = 180
MAX_RUNTIME_SECONDS = 12 * 60
MAX_CLEANUP_SECONDS = 120
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_SECRET_VALUES = 512
MAX_SECRET_BYTES = 16 * 1024 * 1024
MAX_SECRET_VALUE_BYTES = 2 * 1024 * 1024
MAX_WIRE_ROWS = 256
MAX_CONTEXT_ROWS = 256
WIRE_MARKER = b"WP5_TRANSPORT_WIRE="
CONTEXT_MARKER = b"WP5_TRANSPORT_CONTEXT="
ENDPOINTS = {
    "discovery": ("GET", "realms/fapi-demo/.well-known/openid-configuration"),
    "jwks": ("GET", "realms/fapi-demo/protocol/openid-connect/certs"),
    "par": ("POST", "realms/fapi-demo/protocol/openid-connect/ext/par/request"),
    "token": ("POST", "realms/fapi-demo/protocol/openid-connect/token"),
    "revocation": ("POST", "realms/fapi-demo/protocol/openid-connect/revoke"),
}
WIRE_RESULTS = frozenset({"response_received", "network_error"})
GRANT_TYPES = frozenset({"none", "authorization_code", "refresh_token"})
TOKEN_KINDS = frozenset({"none", "unspecified", "access_token", "refresh_token"})
OAUTH_ERRORS = frozenset(stock_flow.OAUTH_ERROR_ENUMS | {"none", "unknown"})
ASSERTION_TYPES = frozenset({"PS256", "unknown"})

INPUT_SOURCES = {
    "transport_fixture.py": HERE / "transport_fixture.py",
    "transport_diag_handler.lua": HERE / "transport_diag_plugin/handler.lua",
    "transport_diag_schema.lua": HERE / "transport_diag_plugin/schema.lua",
    "transport_handler.lua": ROOT / "kong/plugins/fapi-as-mtls-transport/handler.lua",
    "transport_schema.lua": ROOT / "kong/plugins/fapi-as-mtls-transport/schema.lua",
    "bridge_handler.lua": ROOT / "kong/plugins/fapi-client-auth-bridge/handler.lua",
    "bridge_schema.lua": ROOT / "kong/plugins/fapi-client-auth-bridge/schema.lua",
    "observer_parser.py": HERE / "observation_parser.py",
    "observer_java": HERE / "observer/AsPeerObserver.java",
    "stock_flow.py": HERE / "stock_flow.py",
    "wp2_flow.py": ROOT / "tests/harness/wp2_flow.py",
}


class TransportFixtureError(Exception):
    def __init__(self, code: str):
        safe = code if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "internal_failure"
        self.code = safe
        super().__init__(safe)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _source_hashes() -> dict[str, str]:
    return {name: _sha256(path.read_bytes()) for name, path in sorted(INPUT_SOURCES.items())}


def _manifest(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise TransportFixtureError("fixture_symlink_rejected")
        if path.is_dir():
            if path.stat().st_mode & 0o777 != 0o700:
                raise TransportFixtureError("fixture_directory_mode_invalid")
            continue
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            result[relative] = {
                "sha256": _sha256(path.read_bytes()),
                "mode": f"{path.stat().st_mode & 0o777:04o}",
                "size": path.stat().st_size,
            }
    return result


def _key_jwk(key, kid: str) -> dict[str, str]:
    numbers = key.private_numbers()
    public = numbers.public_numbers
    return {
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "PS256",
        "n": _stock._int_b64url(public.n), "e": _stock._int_b64url(public.e),
        "d": _stock._int_b64url(numbers.d), "p": _stock._int_b64url(numbers.p),
        "q": _stock._int_b64url(numbers.q), "dp": _stock._int_b64url(numbers.dmp1),
        "dq": _stock._int_b64url(numbers.dmq1), "qi": _stock._int_b64url(numbers.iqmp),
    }


def _realm(public_pem: bytes, kid: str, passwords: dict[str, str]) -> bytes:
    clients: list[dict[str, Any]] = []
    for route in ("A", "B"):
        callback_path, callback_url = CALLBACKS[route]
        client: dict[str, Any] = {
            "clientId": CLIENT_IDS[route],
            "name": f"WP5 isolated transport Route {route}",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "clientAuthenticatorType": "client-x509" if route == "A" else "client-jwt",
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "redirectUris": [callback_url],
            "webOrigins": [],
            "attributes": {
                "pkce.code.challenge.method": "S256",
                "require.pushed.authorization.requests": "true",
                "tls.client.certificate.bound.access.tokens": "true",
                "use.refresh.tokens": "true",
                "post.logout.redirect.uris": f"https://localhost:3443/?logout=route-{route.lower()}",
                "id.token.signed.response.alg": "PS256",
            },
            "consentRequired": False,
            "fullScopeAllowed": True,
        }
        if route == "A":
            client["attributes"].update({
                "x509.subjectdn": f"CN={CLIENT_CN[route]}",
                "x509.allow.regex.pattern.comparison": "false",
            })
        else:
            client["attributes"].update({
                "jwt.credential.public.key": public_pem.decode("ascii"),
                "jwt.credential.kid": kid,
                "token.endpoint.auth.signing.alg": "PS256",
                "token.endpoint.auth.signing.max.exp": "60",
            })
        clients.append(client)

    users = []
    for route in ("A", "B"):
        username = USERNAMES[route]
        users.append({
            "username": username,
            "firstName": "WP5",
            "lastName": "Demo",
            "email": username + "@example.invalid",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": passwords[route], "temporary": False}],
            "requiredActions": [],
        })

    doc = {
        "realm": "fapi-demo",
        "enabled": True,
        "sslRequired": "all",
        "defaultSignatureAlgorithm": "PS256",
        "accessTokenLifespan": 5,
        "accessCodeLifespan": 60,
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
        "components": {"org.keycloak.keys.KeyProvider": [{
            "name": "wp5-transport-ps256",
            "providerId": "rsa-generated",
            "config": {"priority": ["100"], "enabled": ["true"], "active": ["true"],
                       "algorithm": ["PS256"], "keySize": ["3072"]},
        }]},
        "clients": clients,
        "users": users,
        "clientPolicies": {"policies": [{
            "name": "fapi-2-confidential-clients",
            "description": "Apply the built-in FAPI 2.0 Security Profile to confidential clients.",
            "enabled": True,
            "conditions": [{"condition": "client-access-type", "configuration": {
                "is-negative-logic": False, "type": ["confidential"],
            }}],
            "profiles": ["fapi-2-security-profile"],
        }]},
    }
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _oidc_config(route: str, issuer: str, jwk: dict[str, str] | None,
                 session_secret: str, cache_salt: str) -> dict[str, Any]:
    path, callback_url = CALLBACKS[route]
    client_id = CLIENT_IDS[route]
    logout = f"https://localhost:3443/?logout=route-{route.lower()}"
    result: dict[str, Any] = {
        "issuer": issuer,
        "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
        "token_endpoint": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/token",
        "mtls_token_endpoint": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/token",
        "jwks_endpoint": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/certs",
        "pushed_authorization_request_endpoint": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/ext/par/request",
        "revocation_endpoint": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/revoke",
        "mtls_revocation_endpoint": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/revoke",
        "end_session_endpoint": issuer + "/protocol/openid-connect/logout",
        "client_id": [client_id],
        "client_auth": ["tls_client_auth"],
        "client_alg": ["PS256"] if route == "B" else None,
        "token_endpoint_auth_method": "tls_client_auth",
        "pushed_authorization_request_endpoint_auth_method": "tls_client_auth" if route == "A" else "private_key_jwt",
        "revocation_endpoint_auth_method": "tls_client_auth" if route == "A" else "private_key_jwt",
        "tls_client_auth_cert_id": "11111111-1111-4111-8111-111111111111" if route == "A"
            else "22222222-2222-4222-8222-222222222222",
        "tls_client_auth_ssl_verify": True,
        "ssl_verify": True,
        "auth_methods": ["authorization_code", "session"],
        "login_methods": ["authorization_code"],
        "scopes": ["openid", "profile"],
        "redirect_uri": [callback_url],
        "response_mode": "query",
        "login_tokens": None,
        "require_proof_key_for_code_exchange": True,
        "require_pushed_authorization_requests": True,
        "login_action": "redirect",
        "login_redirect_uri": [f"https://localhost:3443/?authenticated=route-{route.lower()}"],
        "logout_uri_suffix": "/logout",
        "logout_methods": ["GET", "POST"],
        "logout_revoke": True,
        "logout_revoke_access_token": True,
        "logout_revoke_refresh_token": True,
        "logout_redirect_uri": [logout],
        "session_cookie_name": "fapi_route_a_session" if route == "A" else "fapi_route_b_session",
        "session_secret": session_secret,
        "cache_tokens_salt": cache_salt,
        "upstream_access_token_header": "authorization:bearer",
    }
    if jwk is not None:
        result["client_jwk"] = [jwk]
    else:
        result.pop("client_jwk", None)
    if result["client_alg"] is None:
        result.pop("client_alg")
    return result


def _kong_config(route_a_cert: bytes, route_a_key: bytes, route_b_cert: bytes,
                 route_b_key: bytes, ca_cert: bytes, issuer: str, jwk: dict[str, str],
                 jwk_kid: str, secrets_by_route: dict[str, tuple[str, str]],
                 leaf_fingerprints: dict[str, str]) -> bytes:
    cert_ids = {"A": "11111111-1111-4111-8111-111111111111",
                "B": "22222222-2222-4222-8222-222222222222",
                "metadata": "33333333-3333-4333-8333-333333333333"}
    plugin_cfg = {
        "issuer": issuer,
        "internal_origin": INTERNAL_ORIGIN,
        "discovery_url": INTERNAL_ORIGIN + "/realms/fapi-demo/.well-known/openid-configuration",
        "jwks_url": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/certs",
        "par_url": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/ext/par/request",
        "token_url": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/token",
        "revocation_url": INTERNAL_ORIGIN + "/realms/fapi-demo/protocol/openid-connect/revoke",
        "metadata_certificate_file": "/etc/kong/fapi/third-party-metadata.crt",
        "metadata_key_file": "/etc/kong/fapi/third-party-metadata.key",
        "routes": [
            {"route_id": ROUTE_IDS[route], "logical_route": route, "client_id": CLIENT_IDS[route],
             "certificate_file": f"/etc/kong/fapi/route-{route.lower()}.crt",
             "key_file": f"/etc/kong/fapi/route-{route.lower()}.key"}
            for route in ("A", "B")
        ],
        "evidence_correlation_enabled": True,
    }
    certs = [
        {"id": cert_ids["A"], "cert": route_a_cert.decode("ascii"), "key": route_a_key.decode("ascii")},
        {"id": cert_ids["B"], "cert": route_b_cert.decode("ascii"), "key": route_b_key.decode("ascii")},
    ]
    ca_certs = [{"id": cert_ids["metadata"], "cert": ca_cert.decode("ascii")}]
    plugins: list[dict[str, Any]] = [
        {"name": "fapi-as-mtls-transport", "config": plugin_cfg},
        {"name": "wp5-transport-diag", "config": {}},
    ]
    services: list[dict[str, Any]] = []
    for route in ("A", "B"):
        path, _callback = CALLBACKS[route]
        oidc = _oidc_config(route, issuer, jwk if route == "B" else None,
                            *secrets_by_route[route])
        service_plugins: list[dict[str, Any]] = []
        if route == "B":
            service_plugins.append({"name": "fapi-client-auth-bridge", "config": {
                "issuer": issuer,
                "discovery_endpoint": INTERNAL_ORIGIN + "/realms/fapi-demo/.well-known/openid-configuration",
                "client_id": CLIENT_IDS[route],
                "private_key_file": "/etc/kong/fapi/route-b-pkj.key",
                "tls_certificate_file": "/etc/kong/fapi/route-b.crt",
                "key_id": jwk_kid,
                "assertion_delivery": "transport_delegate",
                "assertion_ttl": 60,
            }})
        service_plugins.extend([
            {"name": "openid-connect", "config": oidc},
            {"name": "request-termination", "config": {
                "status_code": 200, "body": "WP5_TRANSPORT_REFRESH_OK", "content_type": "text/plain",
            }},
        ])
        services.append({
            "name": f"wp5-transport-route-{route.lower()}",
            "url": "http://127.0.0.1:9/not-reached-before-login",
            "routes": [{"id": ROUTE_IDS[route], "name": f"wp5-transport-route-{route.lower()}",
                        "paths": [path], "protocols": ["https"], "strip_path": False}],
            "plugins": service_plugins,
        })
    doc = {"_format_version": "3.0", "certificates": certs,
           "ca_certificates": ca_certs, "plugins": plugins, "services": services}
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _compose_file(root: Path) -> bytes:
    base = str(root)
    text = f'''services:
  keycloak:
    image: "{KEYCLOAK_IMAGE_ID}"
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
      - {VOLUME}:/opt/keycloak/data/h2
    ports:
      - "127.0.0.1:8444:8443"
    labels:
      org.picketfence.wp5.owner: {OWNER}
      org.picketfence.wp5.phase: {PHASE}
    networks: [default]

  kong:
    image: "{KONG_IMAGE_ID}"
    pull_policy: never
    platform: linux/arm64
    cpus: 1
    mem_limit: 3g
    pids_limit: 256
    stop_grace_period: 20s
    restart: "no"
    environment:
      KONG_DATABASE: "off"
      KONG_LICENSE_PATH: /etc/kong/fapi/license.json
      KONG_DECLARATIVE_CONFIG: /etc/kong/fapi/kong.json
      KONG_PLUGINS: bundled,fapi-as-mtls-transport,fapi-client-auth-bridge,wp5-transport-diag
      KONG_PROXY_LISTEN: "0.0.0.0:8443 ssl"
      KONG_PROXY_ACCESS_LOG: "off"
      KONG_PROXY_ERROR_LOG: /dev/stderr
      KONG_ADMIN_LISTEN: "off"
      KONG_ADMIN_ACCESS_LOG: "off"
      KONG_ADMIN_GUI_LISTEN: "off"
      KONG_PORTAL_GUI_LISTEN: "off"
      KONG_PORTAL_API_LISTEN: "off"
      KONG_LOG_LEVEL: error
      KONG_NGINX_WORKER_PROCESSES: "2"
      KONG_ANONYMOUS_REPORTS: "off"
      KONG_LUA_SSL_TRUSTED_CERTIFICATE: /etc/kong/fapi/ca.crt
      KONG_SSL_CERT: /etc/kong/fapi/kong.crt
      KONG_SSL_CERT_KEY: /etc/kong/fapi/kong.key
      KONG_NGINX_MAIN_ENV: "FAPI_AS_TRANSPORT_ISSUER; env FAPI_AS_TRANSPORT_INTERNAL_ORIGIN; env FAPI_AS_TRANSPORT_GENERATION; env FAPI_AS_TRANSPORT_STATUS_DIR"
      KONG_PREFIX: /tmp/kong
      FAPI_AS_TRANSPORT_ISSUER: {ISSUER}
      FAPI_AS_TRANSPORT_INTERNAL_ORIGIN: {INTERNAL_ORIGIN}
      FAPI_AS_TRANSPORT_GENERATION: ${{WP5_TRANSPORT_GENERATION:?}}
      FAPI_AS_TRANSPORT_STATUS_DIR: /run/kong/fapi-transport-ready
    tmpfs:
      - /run/kong/fapi-transport-ready:uid=1001,gid=1001,mode=0700,size=1048576
    volumes:
      - {base}/kong/kong.json:/etc/kong/fapi/kong.json:ro
      - {base}/license/license.json:/etc/kong/fapi/license.json:ro
      - {base}/ca/ca.crt:/etc/kong/fapi/ca.crt:ro
      - {base}/tls/kong.crt:/etc/kong/fapi/kong.crt:ro
      - {base}/tls/kong.key:/etc/kong/fapi/kong.key:ro
      - {base}/tls/route-a.crt:/etc/kong/fapi/route-a.crt:ro
      - {base}/tls/route-a.key:/etc/kong/fapi/route-a.key:ro
      - {base}/tls/route-b.crt:/etc/kong/fapi/route-b.crt:ro
      - {base}/tls/route-b.key:/etc/kong/fapi/route-b.key:ro
      - {base}/tls/third-party-metadata.crt:/etc/kong/fapi/third-party-metadata.crt:ro
      - {base}/tls/third-party-metadata.key:/etc/kong/fapi/third-party-metadata.key:ro
      - {base}/keys/route-b-jwk.pem:/etc/kong/fapi/route-b-pkj.key:ro
      - {base}/plugins/fapi-as-mtls-transport:/usr/local/share/lua/5.1/kong/plugins/fapi-as-mtls-transport:ro
      - {base}/plugins/fapi-client-auth-bridge:/usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge:ro
      - {base}/plugins/wp5-transport-diag:/usr/local/share/lua/5.1/kong/plugins/wp5-transport-diag:ro
    ports:
      - "127.0.0.1:8443:8443"
    labels:
      org.picketfence.wp5.owner: {OWNER}
      org.picketfence.wp5.phase: {PHASE}
    depends_on: [keycloak]
    networks: [default]

volumes:
  {VOLUME}:
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


def prepare_fixture(root: Path = FIXTURE_ROOT, receipt_path: Path = PREP_RECEIPT) -> dict[str, Any]:
    root = root.absolute()
    if (root != FIXTURE_ROOT.absolute() or receipt_path.absolute() != PREP_RECEIPT.absolute()
        or root.exists() or root.is_symlink() or receipt_path.exists() or receipt_path.is_symlink()):
        raise TransportFixtureError("fixture_path_exists_or_not_fixed")
    license_value = os.environ.get("KONG_LICENSE_DATA")
    if not license_value or len(license_value) > 64 * 1024:
        raise TransportFixtureError("license_input_missing_or_invalid")
    license_bytes = license_value.encode("utf-8")
    try:
        license_doc = json.loads(license_bytes)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise TransportFixtureError("license_input_invalid") from None
    if not isinstance(license_doc, dict) or not isinstance(license_doc.get("license"), dict):
        raise TransportFixtureError("license_input_invalid")

    root.mkdir(mode=0o700, parents=False)
    directories = (
        "ca", "realm", "tls", "keys", "kong", "license", "status",
        "plugins", "plugins/fapi-as-mtls-transport", "plugins/fapi-client-auth-bridge",
        "plugins/wp5-transport-diag",
    )
    for relative in directories:
        (root / relative).mkdir(mode=0o700, exist_ok=False)
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    ca_key, ca_cert = _stock._new_ca(now)
    kc_key, kc_cert = _stock._new_leaf("localhost", ca_key, ca_cert, now,
                                      server_names=("localhost", "keycloak"))
    kong_key, kong_cert = _stock._new_leaf("localhost", ca_key, ca_cert, now,
                                          server_names=("localhost",))
    route_a_key, route_a_cert = _stock._new_leaf(CLIENT_CN["A"], ca_key, ca_cert, now, client=True)
    route_b_key, route_b_cert = _stock._new_leaf(CLIENT_CN["B"], ca_key, ca_cert, now, client=True)
    meta_key, meta_cert = _stock._new_leaf("third-party-metadata", ca_key, ca_cert, now, client=True)
    jwk_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    jwk_public = jwk_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk_der = jwk_private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = "wp5-transport-b-" + _sha256(jwk_der)[:16]
    jwk = _key_jwk(jwk_private, kid)
    passwords = {route: secrets.token_urlsafe(32) for route in ("A", "B")}
    secrets_by_route = {route: (_stock._b64url(os.urandom(48)), _stock._b64url(os.urandom(32)))
                        for route in ("A", "B")}
    pem = {
        "ca": _stock._pem_cert(ca_cert),
        "keycloak_crt": _stock._pem_cert(kc_cert), "keycloak_key": _stock._pem_key(kc_key),
        "kong_crt": _stock._pem_cert(kong_cert), "kong_key": _stock._pem_key(kong_key),
        "route_a_crt": _stock._pem_cert(route_a_cert), "route_a_key": _stock._pem_key(route_a_key),
        "route_b_crt": _stock._pem_cert(route_b_cert), "route_b_key": _stock._pem_key(route_b_key),
        "metadata_crt": _stock._pem_cert(meta_cert), "metadata_key": _stock._pem_key(meta_key),
        "route_b_jwk": _stock._pem_key(jwk_private),
    }
    leaves = {
        "route_a": _stock._b64url(route_a_cert.fingerprint(hashes.SHA256())),
        "route_b": _stock._b64url(route_b_cert.fingerprint(hashes.SHA256())),
        "metadata": _stock._b64url(meta_cert.fingerprint(hashes.SHA256())),
    }
    for name, data in (
        ("ca/ca.crt", pem["ca"]), ("tls/keycloak.crt", pem["keycloak_crt"]),
        ("tls/keycloak.key", pem["keycloak_key"]), ("tls/kong.crt", pem["kong_crt"]),
        ("tls/kong.key", pem["kong_key"]), ("tls/route-a.crt", pem["route_a_crt"]),
        ("tls/route-a.key", pem["route_a_key"]), ("tls/route-b.crt", pem["route_b_crt"]),
        ("tls/route-b.key", pem["route_b_key"]), ("tls/third-party-metadata.crt", pem["metadata_crt"]),
        ("tls/third-party-metadata.key", pem["metadata_key"]),
        ("keys/route-b-jwk.pem", pem["route_b_jwk"]),
        ("keys/route-b-public.pem", jwk_public), ("realm/fapi-demo-realm.json", _realm(jwk_public, kid, passwords)),
        ("license/license.json", license_bytes),
        ("plugins/fapi-as-mtls-transport/handler.lua", INPUT_SOURCES["transport_handler.lua"].read_bytes()),
        ("plugins/fapi-as-mtls-transport/schema.lua", INPUT_SOURCES["transport_schema.lua"].read_bytes()),
        ("plugins/fapi-client-auth-bridge/handler.lua", INPUT_SOURCES["bridge_handler.lua"].read_bytes()),
        ("plugins/fapi-client-auth-bridge/schema.lua", INPUT_SOURCES["bridge_schema.lua"].read_bytes()),
        ("plugins/wp5-transport-diag/handler.lua", INPUT_SOURCES["transport_diag_handler.lua"].read_bytes()),
        ("plugins/wp5-transport-diag/schema.lua", INPUT_SOURCES["transport_diag_schema.lua"].read_bytes()),
    ):
        _stock._write_exclusive(root / name, data, 0o600)

    kong_config = _kong_config(
        pem["route_a_crt"], pem["route_a_key"], pem["route_b_crt"], pem["route_b_key"],
        pem["ca"], ISSUER, jwk, kid, secrets_by_route, leaves,
    )
    _stock._write_exclusive(root / "kong/kong.json", kong_config, 0o600)
    generation = secrets.token_hex(16)
    _stock._write_exclusive(root / "compose.yml", _compose_file(root), 0o600)
    _stock._write_exclusive(root / "compose.env",
                            f"WP5_FIXTURE_ROOT={root}\nWP5_TRANSPORT_GENERATION={generation}\n".encode(), 0o600)
    secret_candidates = _candidate_secrets(root)
    # Persist only counts, hashes, fixed image identities, and leaf SHA-256 values.
    prep = {
        "schema": "wp5-as-peer-transport-prep-v1",
        "result": "prepared",
        "fixture_root": str(root),
        "project": PROJECT,
        "volume": VOLUME,
        "network": NETWORK,
        "phase": PHASE,
        "generation": generation,
        "issuer": ISSUER,
        "internal_origin": INTERNAL_ORIGIN,
        "image_ids": IMAGE_IDS.copy(),
        "source_hashes": _source_hashes(),
        "files": _manifest(root),
        "file_count": len(_manifest(root)),
        "runtime_usernames": USERNAMES.copy(),
        "expected_leaf_sha256": leaves,
        "license_present": True,
        "secret_candidate_count": len(secret_candidates),
        "secret_candidate_bytes": sum(len(item) for item in secret_candidates),
    }
    _stock._write_exclusive(PREP_RECEIPT, (json.dumps(prep, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return prep


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _load_json(path: Path, *, limit: int = 1024 * 1024) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
            raise ValueError("path")
        raw = path.read_bytes()
        if len(raw) > limit:
            raise ValueError("size")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise TransportFixtureError("receipt_invalid") from None
    if not isinstance(value, dict):
        raise TransportFixtureError("receipt_invalid")
    return value


def _verify_prepared() -> dict[str, Any]:
    prep = _load_json(PREP_RECEIPT)
    if (prep.get("schema") != "wp5-as-peer-transport-prep-v1"
        or prep.get("result") != "prepared" or prep.get("fixture_root") != str(FIXTURE_ROOT)
        or prep.get("project") != PROJECT or prep.get("volume") != VOLUME
        or prep.get("network") != NETWORK or prep.get("phase") != PHASE
        or prep.get("generation") is None or not GENERATION_PATTERN.fullmatch(prep["generation"])
        or prep.get("image_ids") != IMAGE_IDS or prep.get("issuer") != ISSUER
        or prep.get("internal_origin") != INTERNAL_ORIGIN):
        raise TransportFixtureError("prep_receipt_contract_mismatch")
    if prep.get("source_hashes") != _source_hashes():
        raise TransportFixtureError("source_hash_mismatch")
    if prep.get("files") != _manifest(FIXTURE_ROOT):
        raise TransportFixtureError("prep_file_manifest_mismatch")
    leaves = prep.get("expected_leaf_sha256")
    if (not isinstance(leaves, dict) or set(leaves) != {"route_a", "route_b", "metadata"}
        or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
               for value in leaves.values())):
        raise TransportFixtureError("prep_leaf_inventory_invalid")
    return prep


def _call(argv: list[str], *, timeout: int = MAX_COMMAND_SECONDS,
          cap: int = 1024 * 1024) -> bytes:
    try:
        return _stock._command(argv, timeout=timeout, cap=cap)
    except _stock.StockFixtureError as error:
        raise TransportFixtureError(error.code) from None


def _docker() -> list[str]:
    try:
        return _stock._rtk_docker()
    except _stock.StockFixtureError as error:
        raise TransportFixtureError(error.code) from None


def _compose_prefix(root: Path = FIXTURE_ROOT) -> list[str]:
    return _docker() + ["compose", "--project-name", PROJECT, "--file", str(root / "compose.yml"),
                        "--env-file", str(root / "compose.env")]


def _compose(*args: str, timeout: int = MAX_COMMAND_SECONDS,
             cap: int = 1024 * 1024) -> bytes:
    return _call(_compose_prefix() + list(args), timeout=timeout, cap=cap)


def _command_input(argv: list[str], payload: bytes, *, timeout: int = 10) -> None:
    if not isinstance(payload, bytes) or len(payload) > 16 * 1024:
        raise TransportFixtureError("docker_input_invalid")
    try:
        process = subprocess.Popen(
            argv, cwd=ROOT, env=_stock._minimal_env(), stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
    except OSError:
        raise TransportFixtureError("docker_input_start_failed") from None
    try:
        process.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, 15)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
        raise TransportFixtureError("docker_input_timeout") from None
    if process.returncode != 0:
        raise TransportFixtureError("docker_input_failed")


def _inspect_image(image_id: str) -> None:
    raw = _call(_docker() + ["image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", image_id])
    if raw.decode("ascii", "strict").strip() != f"{image_id}|linux|arm64":
        raise TransportFixtureError("runtime_image_identity_mismatch")


def _resource_names(kind: str, name: str, *, timeout: int = MAX_COMMAND_SECONDS) -> set[str]:
    raw = _call(_docker() + [kind, "ls", "--filter", f"name={name}", "--format", "{{.Name}}"], timeout=timeout)
    return {line for line in raw.decode("ascii", "strict").splitlines() if line}


def _container_ids(*, all_states: bool = True, timeout: int = MAX_COMMAND_SECONDS) -> list[str]:
    args = ["ps", "--no-trunc"] + (["-aq"] if all_states else ["-q"])
    raw = _call(_docker() + args + ["--filter", f"label=com.docker.compose.project={PROJECT}"], timeout=timeout)
    return [line for line in raw.decode("ascii", "strict").splitlines() if line]


def preflight_absent() -> None:
    _inspect_image(KONG_IMAGE_ID)
    _inspect_image(KEYCLOAK_IMAGE_ID)
    if _container_ids():
        raise TransportFixtureError("runtime_project_exists")
    if VOLUME in _resource_names("volume", VOLUME) or NETWORK in _resource_names("network", NETWORK):
        raise TransportFixtureError("runtime_resource_exists")
    for port in HOST_PORTS:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            raise TransportFixtureError("runtime_port_unavailable") from None
        finally:
            probe.close()
    _compose("config", "--quiet", timeout=MAX_COMMAND_SECONDS, cap=4096)


def _service_id(service: str, *, timeout: int = MAX_COMMAND_SECONDS) -> str:
    raw = _call(_docker() + ["ps", "--no-trunc", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}",
                              "--filter", f"label=com.docker.compose.service={service}"], timeout=timeout)
    ids = [item for item in raw.decode("ascii", "strict").splitlines() if item]
    if len(ids) != 1:
        raise TransportFixtureError("runtime_service_container_missing")
    return ids[0]


def _verify_owned_resources(*, allow_partial: bool, timeout: int = MAX_COMMAND_SECONDS) -> dict[str, Any]:
    ids = _container_ids(timeout=timeout)
    if len(ids) > 2 or (not ids and not allow_partial):
        raise TransportFixtureError("runtime_container_set_invalid")
    services: set[str] = set()
    for container_id in ids:
        fmt = ("{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|"
               "{{index .Config.Labels \"com.docker.compose.service\"}}|"
               "{{index .Config.Labels \"org.picketfence.wp5.owner\"}}|"
               "{{index .Config.Labels \"org.picketfence.wp5.phase\"}}|{{.Image}}")
        raw = _call(_docker() + ["inspect", "--format", fmt, container_id], timeout=timeout)
        fields = raw.decode("ascii", "strict").strip().split("|")
        if len(fields) != 6 or fields[0] != container_id or fields[1] != PROJECT:
            raise TransportFixtureError("runtime_container_ownership_mismatch")
        service = fields[2]
        if (service not in IMAGE_IDS or service in services
            or fields[3:5] != [OWNER, PHASE] or fields[5] != IMAGE_IDS[service]):
            raise TransportFixtureError("runtime_container_identity_mismatch")
        services.add(service)
    volume_names = _resource_names("volume", VOLUME, timeout=timeout)
    network_names = _resource_names("network", NETWORK, timeout=timeout)
    if any(name != VOLUME for name in volume_names) or any(name != NETWORK for name in network_names):
        raise TransportFixtureError("runtime_resource_name_mismatch")
    label_format = '{{index .Labels "org.picketfence.wp5.owner"}}|{{index .Labels "org.picketfence.wp5.phase"}}'
    for kind, name, names in (("volume", VOLUME, volume_names), ("network", NETWORK, network_names)):
        if name in names:
            raw = _call(_docker() + [kind, "inspect", "--format", label_format, name], timeout=timeout)
            if raw.decode("ascii", "strict").strip() != f"{OWNER}|{PHASE}":
                raise TransportFixtureError(f"runtime_{kind}_ownership_mismatch")
    if ids and (VOLUME not in volume_names or NETWORK not in network_names):
        raise TransportFixtureError("runtime_support_resource_missing")
    return {"containers": len(ids), "services": sorted(services),
            "volume": VOLUME in volume_names, "network": NETWORK in network_names}


def _check_kong_state(deadline: float) -> bool:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportFixtureError("startup_deadline_exceeded")
    timeout = max(1, min(10, int(remaining)))
    try:
        container_id = _service_id("kong", timeout=timeout)
    except TransportFixtureError as error:
        if error.code in {"command_timeout", "command_failed", "runtime_service_container_missing"}:
            return False
        raise
    fmt = ("{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|"
           "{{index .Config.Labels \"org.picketfence.wp5.owner\"}}|"
           "{{index .Config.Labels \"org.picketfence.wp5.phase\"}}|{{.Image}}|{{.State.Status}}")
    raw = _call(_docker() + ["inspect", "--format", fmt, container_id], timeout=timeout)
    fields = raw.decode("ascii", "strict").strip().split("|")
    if (len(fields) != 6 or fields[0] != container_id or fields[1:5] !=
        [PROJECT, OWNER, PHASE, KONG_IMAGE_ID]):
        raise TransportFixtureError("kong_container_identity_mismatch")
    if fields[5] == "exited":
        raise TransportFixtureError("kong_container_exited")
    if fields[5] != "running":
        return False
    return True


def _wait_tls(host: str, port: int, server_name: str, ca_file: Path, deadline: float,
              *, exit_watch=None) -> None:
    last_tls_failure = {}
    while time.monotonic() < deadline:
        if exit_watch is not None and exit_watch(deadline) is False:
            time.sleep(0.25)
            continue
        raw: socket.socket | None = None
        wrapped: ssl.SSLSocket | None = None
        try:
            remaining = max(0.1, min(3.0, deadline - time.monotonic()))
            raw = socket.create_connection((host, port), timeout=remaining)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.keylog_filename = None
            context.load_verify_locations(cafile=str(ca_file))
            wrapped = context.wrap_socket(raw, server_hostname=server_name)
            return
        except (OSError, ssl.SSLError, TimeoutError) as error:
            last_tls_failure = {"exception_class": type(error).__name__,
                                "verify_code": getattr(error, "verify_code", None),
                                "errno": getattr(error, "errno", None)}
            time.sleep(0.25)
        finally:
            if wrapped is not None:
                wrapped.close()
            elif raw is not None:
                raw.close()
    error = TransportFixtureError("tls_startup_timeout")
    error.tls_diagnostic = last_tls_failure
    raise error


def _https_get(path: str, deadline: float, *, spoof: str | None = None) -> tuple[int, bytes]:
    if path not in {CALLBACKS["A"][0], CALLBACKS["B"][0]}:
        raise TransportFixtureError("fixed_path_rejected")
    if spoof not in {None, "header", "query", "body"}:
        raise TransportFixtureError("spoof_probe_invalid")
    method, extra, body = "GET", "", ""
    if spoof == "header":
        extra = "client_assertion: wp5-fixed-noncredential\r\n"
    elif spoof == "query":
        path += "?client_assertion=wp5-fixed-noncredential"
    elif spoof == "body":
        method, body = "POST", "client_assertion=wp5-fixed-noncredential"
        extra = f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
    request = (f"{method} {path} HTTP/1.1\r\nHost: localhost:8443\r\n"
               f"Accept: application/json\r\n{extra}Connection: close\r\n\r\n{body}").encode("ascii")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportFixtureError("http_deadline_exceeded")
    raw: socket.socket | None = None
    wrapped: ssl.SSLSocket | None = None
    try:
        raw = socket.create_connection(("127.0.0.1", 8443), timeout=remaining)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.keylog_filename = None
        context.load_verify_locations(cafile=str(FIXTURE_ROOT / "ca/ca.crt"))
        wrapped = context.wrap_socket(raw, server_hostname="localhost")
        wrapped.settimeout(max(0.1, deadline - time.monotonic()))
        wrapped.sendall(request)
        response = http.client.HTTPResponse(wrapped, method=method)
        response.begin()
        body = response.read(64 * 1024 + 1)
        if len(body) > 64 * 1024:
            raise TransportFixtureError("pre_marker_response_oversized")
        return response.status, body
    except TransportFixtureError:
        raise
    except Exception:
        raise TransportFixtureError("fixed_route_request_failed") from None
    finally:
        if wrapped is not None:
            wrapped.close()
        elif raw is not None:
            raw.close()


def _exec_kong(argv: list[str], *, timeout: int = 10, cap: int = 64 * 1024) -> bytes:
    container = _service_id("kong", timeout=timeout)
    raw = _call(_docker() + ["exec", container, *argv], timeout=timeout, cap=cap)
    return raw


def _require_marker_absent() -> None:
    _exec_kong(["/bin/sh", "-ec", "test ! -e /run/kong/fapi-transport-ready/ready.json"])


def _pre_marker_gate(deadline: float) -> dict[str, Any]:
    _require_marker_absent()
    result = _blocked_route_gate(deadline)
    _require_marker_absent()
    return result


def _blocked_route_gate(deadline: float) -> dict[str, Any]:
    checked = []
    for route in ("A", "B"):
        path = CALLBACKS[route][0]
        status, body = _https_get(path, min(deadline, time.monotonic() + 10))
        if status != 503:
            raise TransportFixtureError("pre_marker_route_not_blocked")
        try:
            payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
            raise TransportFixtureError("pre_marker_response_invalid") from None
        if payload != {"error": "client_authentication_unavailable"}:
            raise TransportFixtureError("pre_marker_response_invalid")
        checked.append(route)
    return {"route_count": len(checked), "routes": checked, "status": 503}


def _read_worker_statuses(prep: dict[str, Any]) -> list[dict[str, Any]]:
    shell = (
        "set -eu; found=0; for f in /run/kong/fapi-transport-ready/worker-*.json; do "
        "[ -f \"$f\" ] || continue; found=1; cat \"$f\"; printf '\\n'; done; "
        "[ \"$found\" = 1 ]"
    )
    raw = _exec_kong(["/bin/sh", "-ec", shell], cap=64 * 1024)
    if len(raw) > 64 * 1024:
        raise TransportFixtureError("worker_status_oversized")
    try:
        lines = [line for line in raw.decode("utf-8", "strict").splitlines() if line]
        statuses = [json.loads(line, object_pairs_hook=_unique_object) for line in lines]
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise TransportFixtureError("worker_status_invalid") from None
    if not 1 <= len(statuses) <= 8:
        raise TransportFixtureError("worker_status_count_invalid")
    keys = {"worker_id", "pid", "generation", "config_hash", "registry_epoch", "wrapper_ready",
            "registry_ready", "bridge_loaded", "delegate_ready", "routes"}
    workers: set[int] = set()
    pids: set[int] = set()
    config_hashes: set[str] = set()
    result = []
    expected_routes = [
        {"route_id": ROUTE_IDS["A"], "logical_route": "A", "client_id": CLIENT_IDS["A"]},
        {"route_id": ROUTE_IDS["B"], "logical_route": "B", "client_id": CLIENT_IDS["B"]},
    ]
    for row in statuses:
        if not isinstance(row, dict) or set(row) != keys:
            raise TransportFixtureError("worker_status_schema_invalid")
        if (type(row["worker_id"]) is not int or row["worker_id"] < 0
            or type(row["pid"]) is not int or row["pid"] <= 0
            or row["generation"] != prep["generation"]
            or not isinstance(row["config_hash"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["config_hash"])
            or not isinstance(row["registry_epoch"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["registry_epoch"])
            or any(row[name] is not True for name in ("wrapper_ready", "registry_ready", "bridge_loaded", "delegate_ready"))
            or row["routes"] != expected_routes or row["worker_id"] in workers or row["pid"] in pids):
            raise TransportFixtureError("worker_status_not_ready")
        workers.add(row["worker_id"])
        pids.add(row["pid"])
        config_hashes.add(row["config_hash"])
        result.append({key: row[key] for key in (
            "worker_id", "pid", "generation", "config_hash", "registry_epoch",
            "wrapper_ready", "registry_ready", "bridge_loaded", "delegate_ready", "routes",
        )})
    if len(config_hashes) != 1:
        raise TransportFixtureError("worker_config_hash_mismatch")
    return result


def _write_ready_marker(prep: dict[str, Any], workers: list[dict[str, Any]]) -> None:
    marker = {
        "generation": prep["generation"],
        "config_hash": workers[0]["config_hash"],
        "workers": [{"worker_id": row["worker_id"], "pid": row["pid"],
                     "registry_epoch": row["registry_epoch"]} for row in workers],
    }
    payload = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    container = _service_id("kong")
    _command_input(
        _docker() + ["exec", "-i", container, "/bin/sh", "-ec",
                     "umask 077; cat > /run/kong/fapi-transport-ready/ready.json; "
                     "chown 1001:1001 /run/kong/fapi-transport-ready/ready.json; "
                     "chmod 0600 /run/kong/fapi-transport-ready/ready.json"],
        payload,
    )


def _runtime_guards(prep: dict[str, Any], workers: list[dict[str, Any]],
                    deadline: float) -> list[dict[str, Any]]:
    if len(workers) != 2:
        raise TransportFixtureError("guard_two_workers_required")
    checks: list[dict[str, Any]] = []
    for source in ("header", "query", "body"):
        status, body = _https_get(CALLBACKS["B"][0], deadline, spoof=source)
        try:
            error = json.loads(body).get("error")
        except (ValueError, AttributeError):
            error = None
        if status != 400 or error != "invalid_request":
            raise TransportFixtureError("caller_assertion_not_rejected")
        checks.append({"case": "caller_assertion_" + source, "status": 400})

    _exec_kong(["/bin/sh", "-ec", "rm -f /run/kong/fapi-transport-ready/ready.json"])
    checks.append({"case": "marker_missing", **_pre_marker_gate(deadline)})
    stale = [{**row, "config_hash": "0" * 64} for row in workers]
    _write_ready_marker(prep, stale)
    checks.append({"case": "marker_config_mismatch", **_blocked_route_gate(deadline)})
    _write_ready_marker(prep, workers)

    old_pids = {row["pid"] for row in workers}
    old_epochs = {row["registry_epoch"] for row in workers}
    _exec_kong(["kong", "reload"], timeout=20)
    replacement = None
    while time.monotonic() < deadline:
        try:
            current = _read_worker_statuses(prep)
            if (len(current) == 2 and old_pids.isdisjoint(row["pid"] for row in current)
                and old_epochs.isdisjoint(row["registry_epoch"] for row in current)):
                replacement = current
                break
        except TransportFixtureError:
            pass
        time.sleep(0.2)
    if replacement is None:
        raise TransportFixtureError("reload_worker_change_not_confirmed")
    checks.append({"case": "reload_marker_removed", **_pre_marker_gate(deadline),
                   "worker_count": len(replacement), "pids_changed": True, "epochs_changed": True})
    # A syntactically valid pre-reload marker must still close the entrance.
    _write_ready_marker(prep, workers)
    checks.append({"case": "marker_epoch_stale", **_blocked_route_gate(deadline)})
    _write_ready_marker(prep, replacement)
    status, body = _https_get(CALLBACKS["B"][0], deadline, spoof="header")
    if status != 400:
        raise TransportFixtureError("reload_delegate_guard_not_ready")
    checks.append({"case": "reload_caller_assertion", "status": status})
    return checks


def _validate_guard_logs(logs: dict[str, Any]) -> dict[str, Any]:
    if (logs["observer_rows"] or logs["wire_rows"] or logs["context_rows"]
        or logs["context_markers"] or logs["leak_counts"]):
        raise TransportFixtureError("guard_as_operation_or_secret_detected")
    return {"complete": True, "observer_row_count": 0, "operation_join_count": 0,
            "as_not_sent": True, "leak_counts": {}}


def _demo_credentials(root: Path, route: str) -> tuple[str, str]:
    try:
        realm = json.loads((root / "realm/fapi-demo-realm.json").read_bytes())
        matches = [user for user in realm["users"] if user.get("username") == USERNAMES[route]]
        if len(matches) != 1:
            raise ValueError("user")
        user = matches[0]
        credentials = user.get("credentials")
        if (user.get("enabled") is not True or user.get("firstName") != "WP5"
            or user.get("lastName") != "Demo" or user.get("requiredActions") != []
            or not isinstance(credentials, list) or len(credentials) != 1
            or credentials[0].get("type") != "password" or credentials[0].get("temporary") is not False):
            raise ValueError("user")
        password = credentials[0].get("value")
        if not isinstance(password, str) or not 32 <= len(password) <= 128:
            raise ValueError("password")
        return USERNAMES[route], password
    except Exception:
        raise TransportFixtureError("demo_user_config_invalid") from None


def _candidate_secrets(root: Path) -> tuple[bytes, ...]:
    values: list[bytes] = []
    for path in sorted(root.rglob("*.key")):
        if path.is_symlink() or not path.is_file():
            raise TransportFixtureError("fixture_key_path_invalid")
        values.append(path.read_bytes())
    for path in sorted(root.rglob("*.pem")):
        if path.is_symlink() or not path.is_file():
            raise TransportFixtureError("fixture_key_path_invalid")
        if "public" not in path.name:
            values.append(path.read_bytes())
    values.append((root / "license/license.json").read_bytes())
    realm = json.loads((root / "realm/fapi-demo-realm.json").read_bytes())
    users = realm.get("users")
    if not isinstance(users, list) or len(users) != 2:
        raise TransportFixtureError("fixture_user_config_invalid")
    for user in users:
        creds = user.get("credentials")
        if not isinstance(creds, list) or len(creds) != 1 or not isinstance(creds[0].get("value"), str):
            raise TransportFixtureError("fixture_user_config_invalid")
        values.append(creds[0]["value"].encode("utf-8"))
    config = json.loads((root / "kong/kong.json").read_bytes())
    for service in config.get("services", []):
        for plugin in service.get("plugins", []):
            cfg = plugin.get("config", {})
            for field in ("session_secret", "cache_tokens_salt"):
                value = cfg.get(field)
                if value is not None:
                    if not isinstance(value, str) or not value:
                        raise TransportFixtureError("fixture_secret_config_invalid")
                    values.append(value.encode("ascii"))
            jwks = cfg.get("client_jwk", [])
            for jwk in jwks:
                for field in ("d", "p", "q", "dp", "dq", "qi"):
                    if isinstance(jwk.get(field), str):
                        values.append(jwk[field].encode("ascii"))
    if len(values) > MAX_SECRET_VALUES or sum(map(len, values)) > MAX_SECRET_BYTES:
        raise TransportFixtureError("fixture_secret_scan_limit")
    return tuple(value for value in values if value)


def _compose_logs(service: str, *, timeout: int, cap: int = MAX_LOG_BYTES) -> bytes:
    return _compose("logs", "--no-color", "--no-log-prefix", service, timeout=timeout, cap=cap)


def _marker_rows(raw: bytes, marker: bytes, *, max_rows: int, max_row_bytes: int) -> list[dict[str, Any]]:
    if not isinstance(raw, bytes) or len(raw) > MAX_LOG_BYTES:
        raise TransportFixtureError("diagnostic_log_input_invalid")
    rows = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    for line in raw.splitlines():
        at = line.find(marker)
        if at < 0:
            continue
        if line.find(marker, at + len(marker)) >= 0:
            raise TransportFixtureError("diagnostic_marker_duplicate_line")
        suffix = line[at + len(marker):]
        if not suffix or len(suffix) > max_row_bytes:
            raise TransportFixtureError("diagnostic_row_invalid")
        try:
            row, _end = decoder.raw_decode(suffix.decode("utf-8", "strict").lstrip())
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
            raise TransportFixtureError("diagnostic_row_invalid") from None
        if not isinstance(row, dict):
            raise TransportFixtureError("diagnostic_row_invalid")
        rows.append(row)
        if len(rows) > max_rows:
            raise TransportFixtureError("diagnostic_row_limit")
    return rows


def _validate_wire_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = {
        "v", "request_id", "endpoint_kind", "method", "logical_route", "identity_kind", "status",
        "client_cert_present", "client_key_present", "client_assertion_present",
        "client_assertion_type_present", "grant_type", "token_kind", "assertion", "token_present",
        "refresh_token_present", "cnf_matches", "revoke_token_present", "oauth_error_enum",
    }
    extended_fields = {"par_evidence", "refresh_evidence"}
    assertion_fields = {"alg", "aud_is_issuer", "iss_sub_match", "ttl_seconds", "jti_present", "jti_distinct"}
    canonical = []
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or frozenset(row) not in {frozenset(fields), frozenset(fields | extended_fields)} \
            or row.get("v") != 1:
            raise TransportFixtureError("wire_row_schema_invalid")
        request_id = row["request_id"]
        if (not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id)
            or request_id in seen_ids):
            raise TransportFixtureError("wire_row_id_invalid")
        seen_ids.add(request_id)
        endpoint = row["endpoint_kind"]
        if endpoint not in ENDPOINTS or row["method"] != ENDPOINTS[endpoint][0]:
            raise TransportFixtureError("wire_row_endpoint_invalid")
        if (type(row["status"]) is not int or not 100 <= row["status"] <= 599
            or row["logical_route"] not in {"A", "B", "none"}
            or row["identity_kind"] not in {"route_A", "route_B", "metadata"}
            or row["grant_type"] not in GRANT_TYPES or row["token_kind"] not in TOKEN_KINDS
            or row["oauth_error_enum"] not in OAUTH_ERRORS
            or any(type(row[name]) is not bool for name in (
                "client_cert_present", "client_key_present", "client_assertion_present",
                "client_assertion_type_present", "token_present", "refresh_token_present",
                "cnf_matches", "revoke_token_present",
            ))):
            raise TransportFixtureError("wire_row_value_invalid")
        claim = row["assertion"]
        if not isinstance(claim, dict) or set(claim) != assertion_fields:
            raise TransportFixtureError("wire_row_assertion_invalid")
        if (claim["alg"] not in ASSERTION_TYPES
            or any(type(claim[name]) is not bool for name in (
                "aud_is_issuer", "iss_sub_match", "jti_present", "jti_distinct",
            )) or type(claim["ttl_seconds"]) is not int or not 0 <= claim["ttl_seconds"] <= 60):
            raise TransportFixtureError("wire_row_assertion_invalid")
        expected_identity = {"A": "route_A", "B": "route_B", "none": "metadata"}[row["logical_route"]]
        if row["identity_kind"] != expected_identity:
            raise TransportFixtureError("wire_row_identity_invalid")
        if extended_fields.issubset(row):
            par = row["par_evidence"]
            rotation = row["refresh_evidence"]
            if (not isinstance(par, dict) or set(par) != {
                    "pkce_s256", "code_challenge_present", "nonce_present", "nonce_at_most_64",
                    "callback_uri_fixed",
                }
                or any(type(value) is not bool for value in par.values())
                or not isinstance(rotation, dict) or set(rotation) != {
                    "input_matches_previous", "output_differs_from_input", "second_uses_rotated",
                }
                or any(type(value) is not bool for value in rotation.values())):
                raise TransportFixtureError("wire_row_extended_evidence_invalid")
            if endpoint != "par" and any(par.values()):
                raise TransportFixtureError("wire_row_extended_par_evidence_unexpected")
            if (endpoint != "token" or row["grant_type"] != "refresh_token") and any(rotation.values()):
                raise TransportFixtureError("wire_row_extended_refresh_evidence_unexpected")
        canonical_row = {key: row[key] for key in sorted(fields)}
        if extended_fields.issubset(row):
            canonical_row.update({key: row[key] for key in sorted(extended_fields)})
        canonical.append(canonical_row)
    return canonical


def _validate_context_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = {"v", "observations", "truncated"}
    event_fields = {
        "request_id", "logical_route", "endpoint_kind", "method", "identity_kind", "oauth_auth_method",
        "result", "not_sent", "http_status", "rejection_layer", "reason_code", "grant_type",
        "token_kind", "claim_summary",
    }
    cleaned = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields or row.get("v") != 1:
            raise TransportFixtureError("context_marker_schema_invalid")
        if type(row["truncated"]) is not bool or row["truncated"] is not False:
            raise TransportFixtureError("context_rows_truncated")
        observations = row["observations"]
        if not isinstance(observations, list) or len(observations) > MAX_CONTEXT_ROWS:
            raise TransportFixtureError("context_marker_schema_invalid")
        for item in observations:
            if not isinstance(item, dict) or not set(item).issubset(event_fields) or not {
                "request_id", "logical_route", "endpoint_kind", "method", "identity_kind",
                "oauth_auth_method", "result", "not_sent",
            }.issubset(item):
                raise TransportFixtureError("context_observation_schema_invalid")
            rid = item["request_id"]
            if (not isinstance(rid, str) or not re.fullmatch(r"[a-f0-9]{32}", rid)
                or item["logical_route"] not in {"A", "B", "none"}
                or item["endpoint_kind"] not in set(ENDPOINTS) | {"unknown"}
                or item["method"] not in {"GET", "POST"}
                or item["identity_kind"] not in {"route_A", "route_B", "metadata"}
                or item["oauth_auth_method"] not in {"tls_client_auth", "private_key_jwt", "none"}
                or item["result"] not in {"not_sent", "network_error", "redirect_rejected", "response_received"}
                or type(item["not_sent"]) is not bool):
                raise TransportFixtureError("context_observation_value_invalid")
            if "http_status" in item and (type(item["http_status"]) is not int or not 100 <= item["http_status"] <= 599):
                raise TransportFixtureError("context_observation_value_invalid")
            if "claim_summary" in item:
                claim = item["claim_summary"]
                if (not isinstance(claim, dict) or set(claim) != {
                    "alg", "aud_is_issuer", "iss_sub_match", "ttl_seconds", "jti_present",
                } or claim["alg"] not in ASSERTION_TYPES
                    or any(type(claim[key]) is not bool for key in ("aud_is_issuer", "iss_sub_match", "jti_present"))
                    or type(claim["ttl_seconds"]) is not int or not 0 <= claim["ttl_seconds"] <= 60):
                    raise TransportFixtureError("context_claim_summary_invalid")
            cleaned.append({key: item[key] for key in sorted(item)})
    return cleaned


def _validate_operation_joins(wire_rows: list[dict[str, Any]], context_rows: list[dict[str, Any]],
                              observer_rows: list[dict[str, Any]], prep: dict[str, Any], *,
                              extended_flow: bool = False) -> dict[str, Any]:
    wire = _validate_wire_rows(wire_rows)
    if type(extended_flow) is not bool:
        raise TransportFixtureError("extended_flow_flag_invalid")
    if extended_flow and any("par_evidence" not in row or "refresh_evidence" not in row for row in wire):
        raise TransportFixtureError("extended_wire_evidence_missing")
    contexts = _validate_context_rows(context_rows)
    if len(observer_rows) > MAX_WIRE_ROWS:
        raise TransportFixtureError("observer_row_limit")
    wire_by_id = {row["request_id"]: row for row in wire}
    observer_by_id: dict[str, dict[str, Any]] = {}
    for row in observer_rows:
        if not isinstance(row, dict) or set(row) != {
            "v", "observed_at", "correlation_id", "endpoint", "method", "path", "peer_present",
            "chain_count", "pkix", "valid_now", "client_auth_eku", "leaf_sha256", "error",
        }:
            raise TransportFixtureError("observer_row_schema_invalid")
        rid = row["correlation_id"]
        if rid in observer_by_id or rid not in wire_by_id:
            raise TransportFixtureError("observer_operation_id_unmatched")
        observer_by_id[rid] = row
    context_by_id: dict[str, dict[str, Any]] = {}
    for item in contexts:
        rid = item["request_id"]
        if rid in context_by_id:
            raise TransportFixtureError("context_operation_id_duplicate")
        context_by_id[rid] = item
    if not set(context_by_id).issubset(wire_by_id):
        raise TransportFixtureError("context_operation_unmatched")
    if set(wire_by_id) != set(observer_by_id):
        raise TransportFixtureError("observer_wire_join_incomplete")

    ledger: list[dict[str, Any]] = []
    operation_counts = {"route_a": {"par": 0, "code": 0, "refresh": 0,
                                    "revoke_access": 0, "revoke_refresh": 0},
                        "route_b": {"par": 0, "code": 0, "refresh": 0,
                                    "revoke_access": 0, "revoke_refresh": 0}}
    metadata_counts = {"discovery": 0, "jwks": 0}
    second_rotation_flags = {"route_a": 0, "route_b": 0}
    joined_ids: set[str] = set()
    for row in wire:
        rid = row["request_id"]
        obs = observer_by_id[rid]
        endpoint = row["endpoint_kind"]
        method, observer_endpoint, path = {
            "discovery": ("GET", "discovery", "realms/fapi-demo/.well-known/openid-configuration"),
            "jwks": ("GET", "jwks", "realms/fapi-demo/protocol/openid-connect/certs"),
            "par": ("POST", "par", "realms/fapi-demo/protocol/openid-connect/ext/par/request"),
            "token": ("POST", "token", "realms/fapi-demo/protocol/openid-connect/token"),
            "revocation": ("POST", "revoke", "realms/fapi-demo/protocol/openid-connect/revoke"),
        }[endpoint]
        identity = row["identity_kind"]
        expected_leaf = prep["expected_leaf_sha256"][
            {"route_A": "route_a", "route_B": "route_b", "metadata": "metadata"}[identity]
        ]
        if (row["method"] != method or obs["method"] != method or obs["endpoint"] != observer_endpoint
            or obs["path"] != path or obs["error"] != "none" or obs["peer_present"] is not True
            or obs["chain_count"] < 1 or obs["pkix"] is not True or obs["valid_now"] is not True
            or obs["client_auth_eku"] is not True or obs["leaf_sha256"] != expected_leaf
            or row["status"] not in (200, 201)):
            raise TransportFixtureError("operation_peer_gate_failed")
        context = context_by_id.get(rid)
        if context is not None and (
            context["endpoint_kind"] != endpoint or context["method"] != method
            or context["identity_kind"] != identity
            or context["result"] != "response_received" or context["not_sent"] is not False
            or context.get("http_status") != row["status"]
        ):
            raise TransportFixtureError("context_wire_join_failed")
        if identity == "metadata":
            if endpoint not in metadata_counts or row["status"] != 200:
                raise TransportFixtureError("metadata_operation_unexpected")
            metadata_counts[endpoint] += 1
            if row["client_cert_present"] is not True or row["client_key_present"] is not True:
                raise TransportFixtureError("metadata_identity_missing")
        else:
            route_name = "route_a" if identity == "route_A" else "route_b"
            if row["client_cert_present"] is not True or row["client_key_present"] is not True:
                raise TransportFixtureError("route_identity_missing")
            if (context is None or context["identity_kind"] != identity
                or context["logical_route"] != ("A" if identity == "route_A" else "B")
                or context["result"] != "response_received" or context["not_sent"] is not False
                or context.get("http_status") != row["status"]):
                raise TransportFixtureError("context_wire_join_failed")
            if endpoint == "par":
                if row["status"] != 201:
                    raise TransportFixtureError("par_http_status_invalid")
                operation_counts[route_name]["par"] += 1
                if row["token_present"] or row["refresh_token_present"]:
                    raise TransportFixtureError("par_response_shape_invalid")
                if extended_flow:
                    par = row["par_evidence"]
                    if not all(par.values()):
                        raise TransportFixtureError("par_request_profile_gate_failed")
            elif endpoint == "token":
                if row["oauth_error_enum"] != "none" or not row["token_present"] or not row["refresh_token_present"] or not row["cnf_matches"]:
                    raise TransportFixtureError("token_response_gate_failed")
                grant = row["grant_type"]
                if grant == "authorization_code":
                    operation_counts[route_name]["code"] += 1
                elif grant == "refresh_token":
                    operation_counts[route_name]["refresh"] += 1
                    if extended_flow:
                        rotation = row["refresh_evidence"]
                        if (rotation["input_matches_previous"] is not True
                            or rotation["output_differs_from_input"] is not True):
                            raise TransportFixtureError("refresh_token_rotation_gate_failed")
                        if rotation["second_uses_rotated"]:
                            second_rotation_flags[route_name] += 1
                else:
                    raise TransportFixtureError("token_grant_invalid")
            elif endpoint == "revocation":
                if row["status"] != 200 or not row["revoke_token_present"]:
                    raise TransportFixtureError("revoke_response_gate_failed")
                if row["token_kind"] == "access_token":
                    operation_counts[route_name]["revoke_access"] += 1
                elif row["token_kind"] == "refresh_token":
                    operation_counts[route_name]["revoke_refresh"] += 1
                else:
                    raise TransportFixtureError("revoke_token_kind_invalid")
            else:
                raise TransportFixtureError("route_metadata_operation_invalid")
        if identity == "route_B" and endpoint in {"par", "token", "revocation"}:
            claim = row["assertion"]
            if (claim["alg"] != "PS256" or claim["aud_is_issuer"] is not True
                or claim["iss_sub_match"] is not True or not 0 < claim["ttl_seconds"] <= 60
                or claim["jti_present"] is not True or claim["jti_distinct"] is not True):
                raise TransportFixtureError("route_b_assertion_gate_failed")
        elif identity == "route_A" and (row["client_assertion_present"] or row["client_assertion_type_present"]):
            raise TransportFixtureError("route_a_assertion_unexpected")
        joined_ids.add(rid)
        ledger_entry = {
            "request_id": rid, "endpoint": endpoint, "identity_kind": identity,
            "method": method, "status": row["status"], "observer_error": obs["error"],
            "peer_present": obs["peer_present"], "chain_count": obs["chain_count"],
            "pkix": obs["pkix"], "valid_now": obs["valid_now"],
            "client_auth_eku": obs["client_auth_eku"], "leaf_sha256": obs["leaf_sha256"],
            "cnf_matches": row["cnf_matches"], "grant_type": row["grant_type"],
            "token_kind": row["token_kind"], "assertion": row["assertion"],
        }
        if extended_flow:
            ledger_entry["par_evidence"] = row["par_evidence"]
            ledger_entry["refresh_evidence"] = row["refresh_evidence"]
        ledger.append(ledger_entry)
    expected_counts = {"par": 1, "code": 1, "refresh": 2 if extended_flow else 1,
                       "revoke_access": 1, "revoke_refresh": 1}
    if operation_counts != {"route_a": expected_counts.copy(), "route_b": expected_counts.copy()}:
        raise TransportFixtureError("route_operation_set_incomplete")
    if extended_flow and second_rotation_flags != {"route_a": 1, "route_b": 1}:
        raise TransportFixtureError("second_refresh_did_not_use_rotated_token")
    if any(count < 1 for count in metadata_counts.values()) or any(count > 8 for count in metadata_counts.values()):
        raise TransportFixtureError("metadata_operation_set_invalid")
    return {"wire_rows": len(wire), "observer_rows": len(observer_rows), "context_rows": len(contexts),
            "operation_joins": ledger, "operation_join_count": len(ledger),
            "route_operation_counts": operation_counts, "metadata_operation_counts": metadata_counts}


def _safe_flow_metrics(metrics: dict[str, Any], *, extended_flow: bool = False) -> dict[str, Any]:
    expected = {
        "ok", "outcome", "http_requests", "redirects", "status_2xx", "status_3xx", "status_4xx",
        "status_5xx", "login_submissions", "consent_submissions", "callback_completed",
        "callback_http_status", "callback_error_enum", "session_cookie_changed",
        "phase_callback_called", "logout_completed", "protected_refresh",
    }
    if type(extended_flow) is not bool:
        raise TransportFixtureError("flow_metrics_mode_invalid")
    if extended_flow:
        expected.add("extended_evidence")
    if not isinstance(metrics, dict) or set(metrics) != expected:
        raise TransportFixtureError("flow_metrics_schema_invalid")
    if (type(metrics["ok"]) is not bool or metrics["outcome"] not in stock_flow.OUTCOMES
        or any(type(metrics[name]) is not int or not 0 <= metrics[name] <= stock_flow.MAX_HTTP_REQUESTS
               for name in ("http_requests", "redirects", "status_2xx", "status_3xx", "status_4xx",
                            "status_5xx", "login_submissions", "consent_submissions"))
        or type(metrics["callback_http_status"]) is not int or not 0 <= metrics["callback_http_status"] <= 599
        or metrics["callback_error_enum"] not in stock_flow.OAUTH_ERROR_ENUMS | {"none", "unknown"}
        or any(type(metrics[name]) is not bool for name in (
            "callback_completed", "session_cookie_changed", "phase_callback_called", "logout_completed",
        ))):
        raise TransportFixtureError("flow_metrics_value_invalid")
    refresh = metrics["protected_refresh"]
    if not isinstance(refresh, dict) or set(refresh) != {"attempted", "http_status", "completed"}:
        raise TransportFixtureError("flow_refresh_metrics_invalid")
    if (type(refresh["attempted"]) is not bool or type(refresh["http_status"]) is not int
        or not 0 <= refresh["http_status"] <= 599 or type(refresh["completed"]) is not bool):
        raise TransportFixtureError("flow_refresh_metrics_invalid")
    if extended_flow:
        extended = metrics["extended_evidence"]
        if not isinstance(extended, dict) or set(extended) != {
            "initial_redirect_query", "callback_iss_mismatch", "protected_refresh_gets", "refresh_waits",
        }:
            raise TransportFixtureError("flow_extended_metrics_invalid")
        initial = extended["initial_redirect_query"]
        if not isinstance(initial, dict) or set(initial) != {
            "query_names", "only_expected_names", "client_id_matches", "request_uri_present",
        }:
            raise TransportFixtureError("flow_initial_redirect_metrics_invalid")
        if (initial["query_names"] != ["client_id", "request_uri"]
            or any(type(initial[name]) is not bool for name in (
                "only_expected_names", "client_id_matches", "request_uri_present",
            ))):
            raise TransportFixtureError("flow_initial_redirect_metrics_invalid")
        mismatch = extended["callback_iss_mismatch"]
        if not isinstance(mismatch, dict) or set(mismatch) != {"attempted", "http_status", "rejected"} \
            or type(mismatch["attempted"]) is not bool or type(mismatch["http_status"]) is not int \
            or not 0 <= mismatch["http_status"] <= 599 or type(mismatch["rejected"]) is not bool:
            raise TransportFixtureError("flow_callback_iss_metrics_invalid")
        for name in ("protected_refresh_gets", "refresh_waits"):
            if type(extended[name]) is not int or not 0 <= extended[name] <= 2:
                raise TransportFixtureError("flow_refresh_rotation_metrics_invalid")
        if (initial["only_expected_names"] is not True or initial["client_id_matches"] is not True
            or initial["request_uri_present"] is not True
            or mismatch["attempted"] is not True or mismatch["rejected"] is not True
            or mismatch["http_status"] not in {400, 401}
            or extended["protected_refresh_gets"] != 2 or extended["refresh_waits"] != 2):
            raise TransportFixtureError("flow_extended_evidence_gate_failed")
    return {key: metrics[key] for key in sorted(expected)}


def _capture_runtime_logs(extra_secrets: tuple[bytes, ...], *, timeout: int,
                          deadline: float | None = None) -> dict[str, Any]:
    def remaining() -> int:
        if deadline is None:
            return max(1, timeout)
        seconds = min(timeout, int(deadline - time.monotonic()))
        if seconds <= 0:
            raise TransportFixtureError("runtime_log_deadline_exceeded")
        return seconds

    keycloak_raw = _compose_logs("keycloak", timeout=remaining(), cap=MAX_LOG_BYTES // 2)
    kong_raw = _compose_logs("kong", timeout=remaining(), cap=MAX_LOG_BYTES // 2)
    if len(keycloak_raw) + len(kong_raw) > MAX_LOG_BYTES:
        raise TransportFixtureError("runtime_log_limit")
    secret_values = _candidate_secrets(FIXTURE_ROOT) + extra_secrets
    if len(secret_values) > MAX_SECRET_VALUES or sum(map(len, secret_values)) > MAX_SECRET_BYTES:
        raise TransportFixtureError("runtime_secret_scan_limit")
    leaks = _stock._leak_scan(keycloak_raw + b"\n" + kong_raw, secret_values)
    try:
        observer_rows = parse_observer_rows(keycloak_raw)
    except ObservationError as error:
        raise TransportFixtureError("observer_parser_" + error.code) from None
    wire_rows = _marker_rows(kong_raw, WIRE_MARKER, max_rows=MAX_WIRE_ROWS, max_row_bytes=16 * 1024)
    context_markers = _marker_rows(kong_raw, CONTEXT_MARKER, max_rows=MAX_CONTEXT_ROWS, max_row_bytes=16 * 1024)
    wire_rows = _validate_wire_rows(wire_rows)
    contexts = _validate_context_rows(context_markers)
    return {
        "complete": True,
        "keycloak_log_bytes": len(keycloak_raw), "keycloak_log_sha256": _sha256(keycloak_raw),
        "kong_log_bytes": len(kong_raw), "kong_log_sha256": _sha256(kong_raw),
        "leak_counts": leaks,
        "observer_rows": observer_rows,
        "wire_rows": wire_rows,
        "context_rows": contexts,
        "context_markers": context_markers,
        "observer_error_counts": {name: sum(row["error"] == name for row in observer_rows)
                                  for name in sorted({"none", "peer_absent", "correlation_invalid",
                                                      "peer_validation_failed", "no_request_context",
                                                      "request_context_unavailable", "request_marker_unavailable",
                                                      "request_unavailable", "observer_failure"})},
    }


def _write_intent(prep: dict[str, Any], *, guards_only: bool = False) -> dict[str, Any]:
    intent = {
        "schema": "wp5-as-peer-transport-intent-v1", "result": "authorized_attempt",
        "fixture_root": str(FIXTURE_ROOT), "project": PROJECT, "volume": VOLUME,
        "network": NETWORK, "phase": PHASE, "generation": prep["generation"],
        "image_ids": IMAGE_IDS.copy(), "source_hashes": prep["source_hashes"],
        "prep_receipt_sha256": _sha256(PREP_RECEIPT.read_bytes()),
        "ports": list(HOST_PORTS), "deadline_seconds": MAX_RUNTIME_SECONDS,
        "guards_only": guards_only,
        "commands": ["compose config --quiet", "compose up -d --no-build --pull never",
                     "two-worker caller assertion / marker / reload guards" if guards_only else
                     "extended A/B callback iss and two-refresh-rotation flow",
                     "compose stop/down exact owned project"],
    }
    _stock._write_exclusive(RUN_INTENT, (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return intent


def _remove_fixture_if_exact(prep: dict[str, Any]) -> bool:
    if not FIXTURE_ROOT.exists():
        return True
    if FIXTURE_ROOT.is_symlink() or _manifest(FIXTURE_ROOT) != prep.get("files"):
        return False
    shutil.rmtree(FIXTURE_ROOT)
    return not FIXTURE_ROOT.exists()


def _run_input(route: str) -> dict[str, Any]:
    if route not in {"A", "B"}:
        raise TransportFixtureError("route_invalid")
    return {"profile": "route_a" if route == "A" else "transport_route_b", "route": route}


def run_fixture(*, approved_single_attempt: bool = False, guards_only: bool = False) -> dict[str, Any]:
    if approved_single_attempt is not True:
        raise TransportFixtureError("single_attempt_flag_required")
    if RUN_INTENT.exists() or RUN_INTENT.is_symlink() or RUN_RECEIPT.exists() or RUN_RECEIPT.is_symlink():
        raise TransportFixtureError("run_receipt_path_exists")
    prep = _verify_prepared()
    preflight_absent()
    intent = _write_intent(prep, guards_only=guards_only)
    started = time.monotonic()
    total_deadline = started + MAX_RUNTIME_SECONDS
    record: dict[str, Any] = {
        "schema": "wp5-as-peer-transport-terminal-v1", "result": "failed", "phase": "intent_written",
        "failure_category": "none", "failure_phase": "none", "fixture_root": str(FIXTURE_ROOT),
        "project": PROJECT, "volume": VOLUME, "network": NETWORK, "phase_label": PHASE,
        "generation": prep["generation"], "image_ids": IMAGE_IDS.copy(),
        "source_hashes": prep["source_hashes"], "prep_receipt_sha256": intent["prep_receipt_sha256"],
        "intent_sha256": _sha256(RUN_INTENT.read_bytes()), "started_unix": int(time.time()),
        "pre_marker_gate": {"attempted": False, "status": 0, "observer_rows": 0},
        "workers": [], "flows": [], "guards_only": guards_only, "guards": [], "evidence": {"complete": False},
        "cleanup": {"attempted": False, "ownership_verified": False, "down": "not_started",
                    "resources_absent": False, "ports_released": {}, "fixture_removed": False},
    }
    may_have_started = False
    primary_failure: tuple[str, str] | None = None
    runtime_secrets = list(_candidate_secrets(FIXTURE_ROOT))

    def fail(code: str, phase: str) -> None:
        nonlocal primary_failure
        if primary_failure is None:
            primary_failure = (code, phase)
            record["failure_category"], record["failure_phase"] = primary_failure

    try:
        record["phase"] = "compose_up"
        may_have_started = True
        _compose("up", "-d", "--no-build", "--pull", "never",
                 timeout=min(MAX_COMMAND_SECONDS, max(1, int(total_deadline - time.monotonic()))))
        startup_deadline = min(total_deadline, time.monotonic() + MAX_STARTUP_SECONDS)
        _wait_tls("127.0.0.1", 8444, "localhost", FIXTURE_ROOT / "ca/ca.crt", startup_deadline,
                  exit_watch=_check_kong_state)
        _wait_tls("127.0.0.1", 8443, "localhost", FIXTURE_ROOT / "ca/ca.crt", startup_deadline,
                  exit_watch=_check_kong_state)
        owned = _verify_owned_resources(allow_partial=False, timeout=10)
        if owned["services"] != ["keycloak", "kong"] or not owned["volume"] or not owned["network"]:
            raise TransportFixtureError("runtime_resource_set_invalid")
        record["resources_verified"] = owned

        record["phase"] = "pre_marker_gate"
        record["pre_marker_gate"]["attempted"] = True
        gate = _pre_marker_gate(min(total_deadline, time.monotonic() + 30))
        record["pre_marker_gate"].update(gate)
        pre_marker_logs = _compose_logs("keycloak", timeout=20, cap=MAX_LOG_BYTES // 2)
        try:
            pre_marker_rows = parse_observer_rows(pre_marker_logs)
        except ObservationError as error:
            raise TransportFixtureError("pre_marker_observer_parser_" + error.code) from None
        record["pre_marker_gate"]["observer_rows"] = len(pre_marker_rows)
        record["pre_marker_gate"]["log_sha256"] = _sha256(pre_marker_logs)
        if pre_marker_rows:
            raise TransportFixtureError("pre_marker_as_observer_not_empty")
        pre_kong_logs = _compose_logs("kong", timeout=20, cap=MAX_LOG_BYTES // 2)
        pre_wire_rows = _marker_rows(pre_kong_logs, WIRE_MARKER, max_rows=MAX_WIRE_ROWS, max_row_bytes=16 * 1024)
        pre_context_rows = _marker_rows(pre_kong_logs, CONTEXT_MARKER, max_rows=MAX_CONTEXT_ROWS, max_row_bytes=16 * 1024)
        pre_leaks = _stock._leak_scan(
            pre_marker_logs + b"\n" + pre_kong_logs, _candidate_secrets(FIXTURE_ROOT),
        )
        if pre_wire_rows or pre_context_rows or pre_leaks:
            raise TransportFixtureError("pre_marker_unexpected_observation")
        record["pre_marker_gate"]["kong_log_sha256"] = _sha256(pre_kong_logs)
        record["pre_marker_gate"]["leak_counts"] = pre_leaks
        del pre_marker_logs
        del pre_kong_logs

        record["phase"] = "worker_status_gate"
        workers = _read_worker_statuses(prep)
        record["workers"] = workers
        _write_ready_marker(prep, workers)
        record["ready_marker_written"] = True

        if guards_only:
            record["phase"] = "runtime_guards"
            record["guards"] = _runtime_guards(prep, workers, min(total_deadline, time.monotonic() + 60))

        for route in (() if guards_only else ("A", "B")):
            profile = _run_input(route)
            username, password = _demo_credentials(FIXTURE_ROOT, route)
            runtime_secrets.append(password.encode("utf-8"))
            record["phase"] = "route_" + route.lower() + "_stock_flow"
            if total_deadline - time.monotonic() < stock_flow.TOTAL_TIMEOUT_SECONDS + 5:
                raise TransportFixtureError("runtime_deadline_insufficient")
            status, initial_body, location, cookies = _initial_request(route, min(total_deadline, time.monotonic() + 15))
            runtime_secrets.extend([location.encode("utf-8"), initial_body, *(cookie.encode("utf-8") for cookie in cookies)])
            if status != 302:
                raise TransportFixtureError("authorization_start_not_redirect")
            metrics = stock_flow.run_stock_flow(
                status, location, cookies, FIXTURE_ROOT / "ca/ca.crt", username, password,
                on_session_ready=lambda _timeout: True,
                on_sensitive_value=lambda value: _collect_runtime_secret(runtime_secrets, value),
                profile=profile["profile"], trigger_refresh=True, extended_flow=True,
            )
            if metrics.get("ok") is not True:
                extended = metrics.get("extended_evidence", {})
                mismatch = extended.get("callback_iss_mismatch", {})
                record["flow_failure_diagnostic"] = {
                    "route": route,
                    "outcome": metrics["outcome"] if metrics.get("outcome") in stock_flow.OUTCOMES else "internal_failure",
                    "http_requests": metrics.get("http_requests", 0),
                    "callback_status": metrics.get("callback_http_status", 0),
                    "issuer_probe_status": mismatch.get("http_status", 0),
                    "issuer_probe_attempted": mismatch.get("attempted", False),
                    "refresh_gets": extended.get("protected_refresh_gets", 0),
                }
                raise TransportFixtureError("stock_flow_not_complete")
            safe_metrics = _safe_flow_metrics(metrics, extended_flow=True)
            record["flows"].append({"route": route, "metrics": safe_metrics})
            if safe_metrics["ok"] is not True or safe_metrics["outcome"] != "complete":
                raise TransportFixtureError("stock_flow_not_complete")
            if (safe_metrics["callback_completed"] is not True or safe_metrics["session_cookie_changed"] is not True
                or safe_metrics["protected_refresh"]["attempted"] is not True
                or safe_metrics["protected_refresh"]["completed"] is not True
                or safe_metrics["logout_completed"] is not True):
                raise TransportFixtureError("stock_flow_gate_failed")

        record["phase"] = "observer_wire_join"
        logs = _capture_runtime_logs(tuple(runtime_secrets), timeout=40, deadline=total_deadline)
        record["evidence"] = {
            key: value for key, value in logs.items()
            if key not in {"observer_rows", "wire_rows", "context_rows", "context_markers"}
        }
        if logs["leak_counts"]:
            raise TransportFixtureError("runtime_log_secret_leak")
        joined = _validate_guard_logs(logs) if guards_only else _validate_operation_joins(
            logs["wire_rows"], logs["context_markers"], logs["observer_rows"], prep,
            extended_flow=True,
        )
        record["evidence"].update(joined)
        record["evidence"]["observer_diagnostics"] = _stock._safe_observer_diagnostics(logs["observer_rows"])
        record["evidence"]["wire_rows"] = logs["wire_rows"]
        record["evidence"]["context_rows"] = logs["context_rows"]
        record["result"] = "accepted"
        record["phase"] = "complete"
    except TransportFixtureError as error:
        if hasattr(error, "tls_diagnostic"):
            record["startup_tls_diagnostic"] = error.tls_diagnostic
        fail(error.code, record.get("phase", "runtime"))
    except Exception:
        fail("internal_failure", record.get("phase", "runtime"))
    finally:
        record["phase_before_cleanup"] = record["phase"]
        cleanup_deadline = time.monotonic() + MAX_CLEANUP_SECONDS
        if may_have_started:
            try:
                ownership = _verify_owned_resources(allow_partial=True, timeout=10)
                record["cleanup"]["ownership_verified"] = True
                record["cleanup"]["resources_before_down"] = ownership
            except Exception:
                record["cleanup"]["down"] = "ownership_unverified"
                fail("cleanup_ownership_check_failed", "cleanup_ownership")
                ownership = None
            if ownership is not None and ownership["containers"]:
                record["cleanup"]["attempted"] = True
                try:
                    _compose("stop", "--timeout", "15", timeout=max(1, min(20, int(cleanup_deadline - time.monotonic()))))
                    record["cleanup"]["stop"] = "complete"
                except Exception:
                    record["cleanup"]["stop"] = "failed"
                    fail("cleanup_stop_failed", "cleanup_stop")
            if ownership is not None:
                record["phase"] = "cleanup_logs"
                try:
                    logs = _capture_runtime_logs(tuple(runtime_secrets), timeout=30, deadline=cleanup_deadline)
                    record["cleanup"]["log_scan_complete"] = True
                    record["cleanup"]["observer_rows"] = len(logs["observer_rows"])
                    record["cleanup"]["wire_rows"] = len(logs["wire_rows"])
                    record["cleanup"]["context_rows"] = len(logs["context_rows"])
                    record["cleanup"]["log_sha256"] = {
                        "keycloak": logs["keycloak_log_sha256"], "kong": logs["kong_log_sha256"],
                    }
                    record["cleanup"]["leak_counts"] = logs["leak_counts"]
                    record["evidence"]["observer_diagnostics"] = _stock._safe_observer_diagnostics(logs["observer_rows"])
                    record["evidence"]["wire_rows"] = logs["wire_rows"]
                    record["evidence"]["context_rows"] = logs["context_rows"]
                    record["evidence"]["observer_row_count"] = len(logs["observer_rows"])
                    if logs["leak_counts"]:
                        fail("cleanup_log_secret_leak", "cleanup_log_scan")
                    if record["result"] == "accepted":
                        joined = _validate_guard_logs(logs) if guards_only else _validate_operation_joins(
                            logs["wire_rows"], logs["context_markers"], logs["observer_rows"], prep,
                            extended_flow=True)
                        record["evidence"].update(joined)
                        record["evidence"]["observer_diagnostics"] = _stock._safe_observer_diagnostics(logs["observer_rows"])
                        record["evidence"]["wire_rows"] = logs["wire_rows"]
                        record["evidence"]["context_rows"] = logs["context_rows"]
                except Exception as error:
                    record["cleanup"]["log_scan_complete"] = False
                    record["cleanup"]["log_scan_failure"] = (
                        error.code if isinstance(error, TransportFixtureError) else "log_scan_failed"
                    )
                    if record["result"] == "accepted":
                        record["result"] = "failed"
                        fail("runtime_log_scan_incomplete", "cleanup_log_scan")
                record["phase"] = "cleanup_down"
                try:
                    _compose("down", "--volumes", timeout=max(1, min(30, int(cleanup_deadline - time.monotonic()))))
                    record["cleanup"]["down"] = "complete"
                except Exception:
                    record["cleanup"]["down"] = "failed"
                    fail("cleanup_down_failed", "cleanup_down")
            try:
                after = _verify_owned_resources(allow_partial=True, timeout=max(1, min(15, int(cleanup_deadline - time.monotonic()))))
                absent = after == {"containers": 0, "services": [], "volume": False, "network": False}
                record["cleanup"]["resources_absent"] = absent
                if not absent:
                    fail("cleanup_resources_remain", "cleanup_verify")
            except Exception:
                record["cleanup"]["resources_absent"] = False
                fail("cleanup_verify_failed", "cleanup_verify")
        else:
            record["cleanup"].update({"ownership_verified": True, "resources_absent": True,
                                      "down": "not_needed"})
        record["cleanup"]["ports_released"] = _wait_ports(HOST_PORTS, min(30, max(0, cleanup_deadline - time.monotonic())))
        if not all(record["cleanup"]["ports_released"].values()):
            fail("cleanup_ports_not_released", "cleanup_ports")
        if record["cleanup"].get("resources_absent") is True:
            try:
                record["cleanup"]["fixture_removed"] = _remove_fixture_if_exact(prep)
                if not record["cleanup"]["fixture_removed"]:
                    fail("cleanup_fixture_tree_mismatch", "cleanup_fixture")
            except Exception:
                record["cleanup"]["fixture_removed"] = False
                fail("cleanup_fixture_removal_failed", "cleanup_fixture")
        else:
            record["cleanup"]["fixture_removed"] = False
        runtime_secrets.clear()
        record["duration_seconds"] = round(time.monotonic() - started, 3)
        if primary_failure:
            record["result"] = "failed"
            record["failure_category"], record["failure_phase"] = primary_failure
        elif record["result"] == "accepted" and not (
            record["cleanup"].get("resources_absent") is True
            and all(record["cleanup"].get("ports_released", {}).values())
            and record["cleanup"].get("fixture_removed") is True
        ):
            record["result"] = "failed"
            record["failure_category"] = "cleanup_incomplete"
            record["failure_phase"] = "cleanup"
        record["phase"] = "terminal"
        _stock._write_exclusive(RUN_RECEIPT, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return record


def _collect_runtime_secret(collection: list[bytes], value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) > MAX_SECRET_VALUE_BYTES:
        raise TransportFixtureError("runtime_secret_input_invalid")
    if value:
        if len(collection) >= MAX_SECRET_VALUES or sum(map(len, collection)) + len(value) > MAX_SECRET_BYTES:
            raise TransportFixtureError("runtime_secret_scan_limit")
        collection.append(value)


def _initial_request(route: str, deadline: float) -> tuple[int, bytes, str, list[str]]:
    path = CALLBACKS[route][0]
    request = (f"GET {path} HTTP/1.1\r\nHost: localhost:8443\r\n"
               "Accept: text/html\r\nConnection: close\r\n\r\n").encode("ascii")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportFixtureError("authorization_start_deadline")
    raw: socket.socket | None = None
    wrapped: ssl.SSLSocket | None = None
    try:
        raw = socket.create_connection(("127.0.0.1", 8443), timeout=remaining)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.keylog_filename = None
        context.load_verify_locations(cafile=str(FIXTURE_ROOT / "ca/ca.crt"))
        wrapped = context.wrap_socket(raw, server_hostname="localhost")
        wrapped.settimeout(max(0.1, deadline - time.monotonic()))
        wrapped.sendall(request)
        response = http.client.HTTPResponse(wrapped, method="GET")
        response.begin()
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise TransportFixtureError("authorization_body_limit")
        locations = response.headers.get_all("Location", [])
        cookies = response.headers.get_all("Set-Cookie", [])
        if (len(locations) != 1 or len(cookies) > 16
            or any(not isinstance(value, str) or not value or len(value) > 16 * 1024
                   or any(ord(char) < 32 or ord(char) == 127 for char in value)
                   for value in [*locations, *cookies])):
            raise TransportFixtureError("authorization_headers_invalid")
        return response.status, body, locations[0], cookies
    except TransportFixtureError:
        raise
    except Exception:
        raise TransportFixtureError("authorization_request_failed") from None
    finally:
        if wrapped is not None:
            wrapped.close()
        elif raw is not None:
            raw.close()


def _wait_ports(ports: tuple[int, ...], timeout: float) -> dict[str, bool]:
    deadline = time.monotonic() + min(max(timeout, 0.0), 30.0)
    remaining = set(ports)
    result = {str(port): False for port in ports}
    while remaining and time.monotonic() < deadline:
        for port in tuple(remaining):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("127.0.0.1", port))
                result[str(port)] = True
                remaining.remove(port)
            except OSError:
                pass
            finally:
                probe.close()
        if remaining:
            time.sleep(0.25)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    sub.add_parser("preflight")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--approved-single-attempt", action="store_true")
    run_parser.add_argument("--guards-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            record = prepare_fixture()
            print(json.dumps({"result": "prepared", "fixture_root": str(FIXTURE_ROOT),
                              "prep_receipt": str(PREP_RECEIPT), "file_count": record["file_count"]},
                             sort_keys=True))
        elif args.command == "preflight":
            _verify_prepared()
            preflight_absent()
            print(json.dumps({"result": "preflight_pass", "project": PROJECT,
                              "image_ids": IMAGE_IDS, "ports": list(HOST_PORTS)}, sort_keys=True))
        else:
            record = run_fixture(approved_single_attempt=args.approved_single_attempt, guards_only=args.guards_only)
            print(json.dumps({"result": record["result"], "failure_category": record["failure_category"],
                              "failure_phase": record["failure_phase"],
                              "run_receipt": str(RUN_RECEIPT)}, sort_keys=True))
            return 0 if record["result"] == "accepted" else 1
    except TransportFixtureError as error:
        print(json.dumps({"result": "failed", "failure_category": error.code}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
