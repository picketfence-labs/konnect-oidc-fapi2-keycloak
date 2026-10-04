#!/usr/bin/env python3
"""Fail-closed local and read-only Konnect target checks for WP1 commands."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
from subprocess import TimeoutExpired, run as subprocess_run

import yaml
from yaml.constructor import ConstructorError
from wp3_runtime import validate_api_runtime_state

from wp1 import ROUTES, compare_schema_hashes, endpoint_host, validate_selector, validate_targets


PLUGIN_FILES = {
    "fapi-as-mtls-transport": Path("kong/plugins/fapi-as-mtls-transport/schema.lua"),
    "fapi-client-auth-bridge": Path("kong/plugins/fapi-client-auth-bridge/schema.lua"),
}
FOUNDATION_FILES = {
    "api": Path("kong/foundation/api.yaml"),
    "third-party": Path("kong/foundation/third-party.yaml"),
}
RUNTIME_FILES = {
    "api": Path("kong/api-gateway.yaml"),
    "third-party": Path("kong/third-party-gateway.yaml"),
}
THIRD_PARTY_RUNTIME_SERVICE_IDS = {
    "A": "0e48dd20-46a0-5b94-832b-014b857c58b5",
    "B": "b52f6f69-8c94-5148-a6a2-dbc5b6e2c15e",
}
THIRD_PARTY_RUNTIME_PLUGIN_IDS = {
    "A": {
        "cors": "66d86cb7-9d75-5b1b-855d-63b1a9a957f9",
        "openid-connect": "96d4d14a-4b66-5751-b8b0-d000c6c84409",
        "request-transformer": "1f1902cb-dfa2-5003-a3ae-9968b2c126b2",
    },
    "B": {
        "cors": "be2f0305-7644-5e24-9c0d-c5c16e726492",
        "fapi-client-auth-bridge": "564675c7-1913-5d2c-8e2f-af7709855db5",
        "openid-connect": "fa9b36b8-2ae3-5240-ac4e-c1303c33bb9c",
        "request-transformer": "2678d008-77b3-5ec1-bc5d-8e2a5f8633a5",
    },
}


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def read_config(path: Path) -> dict[str, str]:
    allowed = {"TF_VAR_control_plane_name", "TF_VAR_third_party_control_plane_name", "KONNECT_SERVER_URL"}
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in allowed:
            values[key] = value.strip().strip("\"'")
    return values


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            values[key] = value.strip().strip("\"'")
    return values


def expected_names(env: dict[str, str]) -> dict[str, str]:
    return {
        "api": env.get("TF_VAR_control_plane_name", "keycloak-fapi2-demo"),
        "third-party": env.get(
            "TF_VAR_third_party_control_plane_name", "keycloak-fapi2-third-party-demo"
        ),
    }


def local_manifest(root: Path, gateway: str, stage: str | None, operation: str) -> dict:
    selector_operation = "schema" if operation.startswith("schema-") else operation
    validate_selector(gateway, stage, selector_operation)
    validate_foundation_state(root, gateway)
    if stage == "runtime" and gateway not in RUNTIME_FILES:
        raise ValueError("runtime state is unavailable for the selected gateway")
    state = (
        FOUNDATION_FILES[gateway]
        if stage == "foundation"
        else RUNTIME_FILES.get(gateway)
        if stage == "runtime"
        else None
    )
    if operation == "validate" and gateway == "api":
        runtime_state = root / "kong/api-gateway.yaml"
        if runtime_state.exists():
            validate_api_runtime_state(root)
    if operation == "validate" and gateway == "third-party" and stage == "runtime":
        validate_third_party_runtime_state(root)
    if operation in {"diff", "sync"}:
        if stage == "runtime":
            if gateway == "api":
                validate_api_runtime_state(root)
            else:
                validate_third_party_runtime_state(root)
        if not (root / state).is_file():
            raise ValueError(f"{stage} state is missing: {state}")
    manifest_path = root / ".generated/gateway_targets.json"
    if operation == "validate":
        return {}
    if operation in {"diff", "sync", "schema-check", "schema-sync"}:
        if not manifest_path.is_file():
            raise ValueError("generated gateway target manifest is missing; render it after provisioning")
        manifest = json.loads(manifest_path.read_text())
        if set(manifest) != {"konnect_server_url", "targets"}:
            raise ValueError("gateway target manifest fields are malformed")
        config = read_config(root / ".env")
        targets = validate_targets(manifest["targets"], expected_names(config))
        region_url = manifest["konnect_server_url"]
        region_host = endpoint_host(region_url)
        env_region = config.get("KONNECT_SERVER_URL", "https://us.api.konghq.com").rstrip("/")
        if region_host != endpoint_host(env_region):
            raise ValueError("Konnect region URL does not match the rendered target manifest")
        return {"manifest": manifest, "targets": targets, "target": targets[gateway]}
    return {}


class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise ConstructorError("while constructing a mapping", node.start_mark,
                                       "found an unhashable key", key_node.start_mark) from exc
            if duplicate:
                raise ConstructorError("while constructing a mapping", node.start_mark,
                                       "found a duplicate key", key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _parse_foundation(path: Path) -> dict:
    source = path.read_text()
    rendered = re.sub(
        r'\$\{\{\s*env\s+"([A-Z0-9_]+)"\s*\}\}',
        lambda match: f"foundation-template:{match.group(1)}",
        source,
    )
    if "${{" in rendered:
        raise ValueError("foundation state contains an unsupported template expression")
    try:
        parsed = yaml.load(rendered, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ValueError("foundation state is not valid duplicate-free YAML") from exc
    if not isinstance(parsed, dict):
        raise ValueError("foundation state must be a YAML mapping")
    return parsed


def _require_tags(entity: dict) -> None:
    if not isinstance(entity, dict) or entity.get("tags") != ["fapi2-demo", "fapi2-foundation"]:
        raise ValueError("foundation entity ownership tags were changed")


def validate_foundation_state(root: Path, gateway: str) -> None:
    path = root / FOUNDATION_FILES[gateway]
    if not path.is_file():
        raise ValueError(f"foundation state is missing: {FOUNDATION_FILES[gateway]}")
    parsed = _parse_foundation(path)
    if set(parsed) - {"_format_version", "_info", "certificates", "ca_certificates", "plugins"}:
        raise ValueError("foundation state contains an unexpected top-level entity or key")
    if parsed.get("_format_version") != "3.0" or parsed.get("_info") != {
        "select_tags": ["fapi2-demo", "fapi2-foundation"]
    }:
        raise ValueError("foundation state select_tags were changed")
    certificates = parsed.get("certificates")
    if gateway == "api" and "ca_certificates" in parsed:
        raise ValueError("API foundation must not manage the shared API CA")
    ca_certificates = parsed.get("ca_certificates", []) if gateway == "api" else parsed.get("ca_certificates")
    expected_ids = {
        "api": {
            "certificates": {"44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"},
            "ca_certificates": set(),
        },
        "third-party": {
            "certificates": {"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"},
            "ca_certificates": {"33333333-3333-4333-8333-333333333333"},
        },
    }[gateway]
    expected_cert_refs = {
        "api": {
            "44444444-4444-4444-8444-444444444444": ("DECK_API_INTROSPECTION_CERT_YAML", "{vault://env/API_INTROSPECTION_KEY}"),
            "55555555-5555-4555-8555-555555555555": ("DECK_API_UPSTREAM_CERT_YAML", "{vault://env/API_UPSTREAM_KEY}"),
        },
        "third-party": {
            "11111111-1111-4111-8111-111111111111": ("DECK_ROUTE_A_TLS_CERT_YAML", "{vault://env/ROUTE_A_TLS_KEY}"),
            "22222222-2222-4222-8222-222222222222": ("DECK_ROUTE_B_TLS_CERT_YAML", "{vault://env/ROUTE_B_TLS_KEY}"),
        },
    }[gateway]
    expected_ca_ref = {
        "api": None,
        "third-party": ("33333333-3333-4333-8333-333333333333", "DECK_FAPI_CA_CERT_YAML"),
    }[gateway]
    for collection_name, collection in (("certificates", certificates), ("ca_certificates", ca_certificates)):
        if not isinstance(collection, list):
            raise ValueError("foundation certificate entity set or fixed IDs were changed")
        actual_ids = []
        for row in collection:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise ValueError("foundation certificate entity set or fixed IDs were changed")
            actual_ids.append(row["id"])
        if set(actual_ids) != expected_ids[collection_name] or len(actual_ids) != len(expected_ids[collection_name]):
            raise ValueError("foundation certificate entity set or fixed IDs were changed")
        expected_fields = {"id", "cert", "key", "tags"} if collection_name == "certificates" else {"id", "cert", "tags"}
        for entity in collection:
            if not isinstance(entity, dict) or set(entity) != expected_fields:
                raise ValueError("foundation certificate entity fields were changed")
            _require_tags(entity)
            if collection_name == "certificates":
                cert_env, key_ref = expected_cert_refs[entity["id"]]
                if entity["cert"] != f"foundation-template:{cert_env}" or entity.get("key") != key_ref:
                    raise ValueError("foundation certificate identity or secret reference was changed")
            elif expected_ca_ref is None or (entity["id"], entity["cert"]) != (
                expected_ca_ref[0], f"foundation-template:{expected_ca_ref[1]}"
            ):
                raise ValueError("foundation CA certificate identity or reference was changed")
    if parsed.get("services") is not None or parsed.get("routes") is not None:
        raise ValueError("foundation state must not contain services or routes")
    if gateway == "api":
        if "plugins" in parsed:
            raise ValueError("API foundation must not contain any plugin entities")
    else:
        plugins = parsed.get("plugins")
        if not isinstance(plugins, list) or len(plugins) != 1:
            raise ValueError("third-party foundation must contain exactly one global transport entity")
        plugin = plugins[0]
        expected_config = {
            "issuer": "https://localhost:8444/realms/fapi-demo",
            "internal_origin": "https://keycloak:8443",
            "discovery_url": "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration",
            "jwks_url": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/certs",
            "par_url": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/ext/par/request",
            "token_url": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token",
            "revocation_url": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/revoke",
            "metadata_certificate_file": "/etc/kong/fapi/third-party-metadata.crt",
            "metadata_key_file": "/etc/kong/fapi/third-party-metadata.key",
            "routes": list(ROUTES),
            "evidence_correlation_enabled": False,
        }
        if (
            set(plugin) != {"id", "name", "enabled", "protocols", "tags", "config"}
            or plugin.get("id") != "88888888-8888-4888-8888-888888888888"
            or plugin.get("name") != "fapi-as-mtls-transport"
            or plugin.get("enabled") is not True
            or plugin.get("protocols") != ["http", "https"]
            or plugin.get("config") != expected_config
        ):
            raise ValueError("third-party global transport entity identity or config was changed")
        _require_tags(plugin)


def validate_third_party_runtime_state(root: Path) -> dict:
    """Validate the WP5 third-party state while pinning its foundation entities."""
    state_path = root / RUNTIME_FILES["third-party"]
    if not state_path.is_file() or state_path.is_symlink():
        raise ValueError("third-party runtime state is missing or unsafe")
    validate_foundation_state(root, "third-party")
    state = _parse_foundation(state_path)
    foundation = _parse_foundation(root / FOUNDATION_FILES["third-party"])
    if set(state) != {
        "_format_version", "_info", "certificates", "ca_certificates", "plugins", "services"
    }:
        raise ValueError("third-party runtime state contains unexpected entities or fields")
    if state.get("_format_version") != "3.0" or state.get("_info") != {
        "select_tags": ["fapi2-demo"]
    }:
        raise ValueError("third-party runtime select_tags must remain fapi2-demo")
    for entity_set in ("certificates", "ca_certificates", "plugins"):
        if state.get(entity_set) != foundation.get(entity_set):
            raise ValueError(f"third-party runtime must preserve the foundation {entity_set} exactly")

    ca_id = "33333333-3333-4333-8333-333333333333"
    certificate_ids = {
        "A": "11111111-1111-4111-8111-111111111111",
        "B": "22222222-2222-4222-8222-222222222222",
    }
    route_ids = {
        "A": "754519ff-b0b9-5ed5-94c0-e453d260c6c4",
        "B": "0f45debe-a3a6-5207-aea3-637227fb96f2",
    }
    clients = {"A": "third-party-fapi-mtls", "B": "third-party-fapi-pkj-mtls"}
    paths = {"A": "/api/fapi/mtls", "B": "/api/fapi/pkj-mtls"}
    services = state.get("services")
    if not isinstance(services, list) or len(services) != 2:
        raise ValueError("third-party runtime must contain exactly fixed Route A and B services")

    by_route: dict[str, dict] = {}
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("third-party runtime service is malformed")
        route = next((name for name, route_id in route_ids.items()
                      if isinstance(service.get("routes"), list)
                      and len(service["routes"]) == 1
                      and isinstance(service["routes"][0], dict)
                      and service["routes"][0].get("id") == route_id), None)
        if route is None or route in by_route:
            raise ValueError("third-party runtime Route A/B IDs are missing or duplicated")
        expected_service = {
            "id": THIRD_PARTY_RUNTIME_SERVICE_IDS[route],
            "name": f"third-party-route-{route.lower()}-api",
            "protocol": "https",
            "host": "kong-api",
            "port": 8443,
            "path": "/fapi-api/evidence",
            "tls_verify": True,
            "ca_certificates": [ca_id],
            "client_certificate": certificate_ids[route],
            "tags": ["fapi2-demo", f"route-{route.lower()}"],
        }
        if set(service) != {
            "id", "name", "protocol", "host", "port", "path", "tls_verify", "ca_certificates",
            "client_certificate", "tags", "routes", "plugins",
        } or any(service.get(name) != value for name, value in expected_service.items()):
            raise ValueError(f"third-party Route {route} must use verified internal HTTPS and its fixed TLS identity")
        route_entity = service["routes"][0]
        if set(route_entity) != {"id", "name", "paths", "protocols", "strip_path", "tags"} or route_entity != {
            "id": route_ids[route],
            "name": f"third-party-route-{route.lower()}",
            "paths": [paths[route]],
            "protocols": ["https"],
            "strip_path": True,
            "tags": ["fapi2-demo", f"route-{route.lower()}"],
        }:
            raise ValueError(f"third-party Route {route} identity or HTTPS scope changed")
        by_route[route] = service

    if set(by_route) != {"A", "B"}:
        raise ValueError("third-party runtime Route A/B services are incomplete")

    issuer = "https://localhost:8444/realms/fapi-demo"
    internal = "https://keycloak:8443/realms/fapi-demo"
    token_url = internal + "/protocol/openid-connect/token"
    jwks_url = internal + "/protocol/openid-connect/certs"
    par_url = internal + "/protocol/openid-connect/ext/par/request"
    revoke_url = internal + "/protocol/openid-connect/revoke"
    common_oidc = {
        "issuer": issuer,
        "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
        "token_endpoint": token_url,
        "mtls_token_endpoint": token_url,
        "jwks_endpoint": jwks_url,
        "pushed_authorization_request_endpoint": par_url,
        "revocation_endpoint": revoke_url,
        "mtls_revocation_endpoint": revoke_url,
        "end_session_endpoint": issuer + "/protocol/openid-connect/logout",
        "client_auth": ["tls_client_auth"],
        "token_endpoint_auth_method": "tls_client_auth",
        "tls_client_auth_ssl_verify": True,
        "ssl_verify": True,
        "auth_methods": ["authorization_code", "session"],
        "scopes": ["openid", "profile"],
        "response_mode": "query",
        "login_tokens": ["id_token"],
        "require_proof_key_for_code_exchange": True,
        "require_pushed_authorization_requests": True,
        "login_action": "redirect",
        "logout_uri_suffix": "/logout",
        "logout_methods": ["GET", "POST"],
        "logout_revoke": True,
        "logout_revoke_access_token": True,
        "logout_revoke_refresh_token": True,
    }

    for route in ("A", "B"):
        plugins = by_route[route].get("plugins")
        expected_names = ["cors", "openid-connect", "request-transformer"]
        if route == "B":
            expected_names = ["cors", "fapi-client-auth-bridge", "openid-connect", "request-transformer"]
        if not isinstance(plugins, list) or [plugin.get("name") for plugin in plugins
                                              if isinstance(plugin, dict)] != expected_names:
            raise ValueError(f"third-party Route {route} plugin set changed")
        for plugin in plugins:
            if not isinstance(plugin, dict) \
                or plugin.get("id") != THIRD_PARTY_RUNTIME_PLUGIN_IDS[route].get(plugin.get("name")) \
                or plugin.get("tags") != ["fapi2-demo", f"route-{route.lower()}"]:
                raise ValueError(f"third-party Route {route} plugin scope changed")
        plugins_by_name = {plugin["name"]: plugin for plugin in plugins}
        oidc = plugins_by_name["openid-connect"].get("config")
        if not isinstance(oidc, dict) or any(oidc.get(name) != value for name, value in common_oidc.items()):
            raise ValueError(f"third-party Route {route} OIDC HTTPS, TLS, or session policy changed")
        if oidc.get("client_id") != [clients[route]] or oidc.get("tls_client_auth_cert_id") != certificate_ids[route]:
            raise ValueError(f"third-party Route {route} TLS client identity changed")
        if oidc.get("redirect_uri") != ["https://localhost:8443" + paths[route]]:
            raise ValueError(f"third-party Route {route} callback URI changed")
        if oidc.get("upstream_access_token_header") != "authorization:bearer":
            raise ValueError(f"third-party Route {route} upstream token behavior changed")

        if route == "A":
            if oidc.get("client_auth") != ["tls_client_auth"] \
                or oidc.get("pushed_authorization_request_endpoint_auth_method") != "tls_client_auth" \
                or oidc.get("revocation_endpoint_auth_method") != "tls_client_auth":
                raise ValueError("third-party Route A must use TLS client authentication for PAR and revocation")
        else:
            if oidc.get("client_alg") != ["PS256"] \
                or oidc.get("pushed_authorization_request_endpoint_auth_method") != "private_key_jwt" \
                or oidc.get("revocation_endpoint_auth_method") != "private_key_jwt":
                raise ValueError("third-party Route B must retain stock PS256 PAR/revocation and TLS token auth")
            expected_jwk = {
                "kty": "RSA",
                "kid": "foundation-template:DECK_ROUTE_B_JWK_KID",
                "use": "sig",
                "alg": "PS256",
                "n": "foundation-template:DECK_ROUTE_B_JWK_N",
                "e": "foundation-template:DECK_ROUTE_B_JWK_E",
                "d": "{vault://env/route-b-jwk/d}",
                "p": "{vault://env/route-b-jwk/p}",
                "q": "{vault://env/route-b-jwk/q}",
                "dp": "{vault://env/route-b-jwk/dp}",
                "dq": "{vault://env/route-b-jwk/dq}",
                "qi": "{vault://env/route-b-jwk/qi}",
            }
            if oidc.get("client_jwk") != [expected_jwk]:
                raise ValueError("third-party Route B stock PS256 signing JWK references changed")
            bridge = plugins_by_name["fapi-client-auth-bridge"]
            bridge_config = bridge.get("config")
            expected_bridge = {
                "issuer": issuer,
                "discovery_endpoint": "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration",
                "client_id": clients["B"],
                "private_key_file": "/etc/kong/fapi/route-b-pkj.key",
                "tls_certificate_file": "/etc/kong/fapi/route-b.crt",
                "key_id": "foundation-template:DECK_ROUTE_B_JWK_KID",
                "assertion_delivery": "transport_delegate",
                "assertion_ttl": 60,
            }
            if bridge.get("protocols") != ["grpc", "grpcs", "http", "https"] \
                or bridge_config != expected_bridge:
                raise ValueError("third-party Route B bridge must use the fixed transport delegate")
    return state


def request_json(url: str, token: str, *, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    request = Request(
        url,
        method=method,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        opener = build_opener(RejectRedirects())
        with opener.open(request, timeout=20) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as exc:
        exc.close()
        raise ValueError(f"Konnect request failed with HTTP {exc.code}") from None
    except (URLError, TimeoutError, json.JSONDecodeError):
        raise ValueError("Konnect request failed or returned invalid JSON") from None


def verify_remote_target(base: str, target: dict, token: str) -> None:
    status, response = request_json(
        f"{base}/v2/control-planes/{target['control_plane_id']}", token
    )
    remote = response.get("data", response)
    config = remote.get("config") if isinstance(remote, dict) else None
    if (
        status != 200
        or not isinstance(remote, dict)
        or remote.get("id") != target["control_plane_id"]
        or remote.get("name") != target["control_plane_name"]
        or not isinstance(config, dict)
        or config.get("control_plane_endpoint") != target["control_plane_endpoint"]
        or config.get("telemetry_endpoint") != target["telemetry_endpoint"]
    ):
        raise ValueError("read-only control plane metadata does not match local target ID, name, or endpoints")


SHARED_API_CA_ID = "33333333-3333-4333-8333-333333333333"
SINGLE_CERTIFICATE_PEM = re.compile(
    r"\s*-----BEGIN CERTIFICATE-----\r?\n"
    r"[A-Za-z0-9+/=]+(?:\r?\n[A-Za-z0-9+/=]+)*\r?\n"
    r"-----END CERTIFICATE-----\s*",
    re.ASCII,
)
ROLE_INPUT_FIELDS = {
    "api": {
        "certificates": {
            "DECK_FAPI_CA_CERT_YAML",
            "DECK_API_INTROSPECTION_CERT_YAML",
            "DECK_API_UPSTREAM_CERT_YAML",
        },
        "keys": {"API_INTROSPECTION_KEY", "API_UPSTREAM_KEY"},
    },
    "third-party": {
        "certificates": {
            "DECK_FAPI_CA_CERT_YAML",
            "DECK_ROUTE_A_TLS_CERT_YAML",
            "DECK_ROUTE_B_TLS_CERT_YAML",
        },
        "keys": {"ROUTE_A_TLS_KEY", "ROUTE_B_TLS_KEY"},
    },
}


def certificate_der(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("role-scoped certificate input is missing or malformed")
    pem = value.replace("\\n", "\n")
    if SINGLE_CERTIFICATE_PEM.fullmatch(pem) is None:
        raise ValueError("role-scoped certificate input is missing or malformed")
    try:
        result = subprocess_run(
            ["openssl", "x509", "-inform", "PEM", "-outform", "DER"],
            input=pem.encode("ascii"),
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, UnicodeEncodeError, TimeoutExpired):
        raise ValueError("role-scoped certificate input is missing or malformed") from None
    if result.returncode != 0 or not result.stdout:
        raise ValueError("role-scoped certificate input is missing or malformed")
    return result.stdout


def validate_role_values(gateway: str, role_values: object) -> dict[str, str]:
    if not isinstance(role_values, dict):
        raise ValueError("role-scoped decK input is malformed")
    fields = ROLE_INPUT_FIELDS[gateway]
    expected = fields["certificates"] | fields["keys"]
    if set(role_values) != expected:
        raise ValueError("role-scoped decK input fields are malformed")
    for name in fields["certificates"]:
        certificate_der(role_values[name])
    for name in fields["keys"]:
        value = role_values[name]
        if not isinstance(value, str) or not value.startswith("-----BEGIN ") or "PRIVATE KEY-----" not in value:
            raise ValueError("role-scoped decK input fields are malformed")
    return role_values


def verify_shared_api_ca(base: str, target: dict, token: str, role_certificate: str) -> None:
    url = (
        f"{base}/v2/control-planes/{target['control_plane_id']}"
        f"/core-entities/ca_certificates/{SHARED_API_CA_ID}"
    )
    status, response = request_json(url, token)
    if status != 200 or not isinstance(response, dict):
        raise ValueError("required shared API CA could not be verified")
    remote = response.get("data", response)
    if (
        not isinstance(remote, dict)
        or remote.get("id") != SHARED_API_CA_ID
        or not isinstance(remote.get("tags"), list)
        or len(remote["tags"]) != 1
        or not all(isinstance(tag, str) for tag in remote["tags"])
        or set(remote["tags"]) != {"fapi2-demo"}
    ):
        raise ValueError("required shared API CA metadata does not match")
    try:
        remote_der = certificate_der(remote.get("cert"))
        expected_der = certificate_der(role_certificate)
    except ValueError:
        raise ValueError("required shared API CA certificate is malformed") from None
    if remote_der != expected_der:
        raise ValueError("required shared API CA certificate does not match runtime input")


def request_schema_pages(collection_url: str, token: str) -> list[dict]:
    cursor: str | None = None
    pages: list[dict] = []
    seen_cursors: set[str] = set()
    count: int | None = None
    observed = 0
    for _ in range(1000):
        params = {"page[size]": "100"}
        if cursor:
            params["page[after]"] = cursor
        status, page = request_json(f"{collection_url}?{urlencode(params)}", token)
        if status != 200:
            raise ValueError(f"schema list request failed with HTTP {status}")
        # Konnect may omit both optional `items` and `page` for a brand-new CP
        # with no schemas. Accept only the literal, initial empty object; all
        # later or partially populated responses still require full pagination.
        if not pages and cursor is None and page == {}:
            return [{
                "items": [],
                "page": {"total_count": 0, "has_next_page": False, "next_cursor": None},
                "request_cursor": None,
            }]
        if not isinstance(page, dict):
            raise ValueError("schema list response is malformed")
        items = page.get("items")
        page_info = page.get("page")
        if not isinstance(items, list) or not isinstance(page_info, dict):
            raise ValueError("schema list response is missing items or pagination metadata")
        total = page_info.get("total_count")
        if type(total) is not int or total < 0 or (count is not None and total != count):
            raise ValueError("schema list total_count is missing or changed during pagination")
        has_next = page_info.get("has_next_page")
        next_cursor = page_info.get("next_cursor")
        if not isinstance(has_next, bool):
            raise ValueError("schema list has_next_page is malformed")
        if has_next and (not isinstance(next_cursor, str) or not next_cursor.strip()):
            raise ValueError("schema list next_cursor is missing or malformed")
        count = total
        pages.append({"items": items, "page": page_info, "request_cursor": cursor})
        observed += len(items)
        if observed > total:
            raise ValueError("schema list returned more items than page.total_count")
        if not has_next:
            if observed != total:
                raise ValueError("schema pagination ended before page.total_count")
            return pages
        if observed >= total or not items:
            raise ValueError("schema pagination made no progress")
        if next_cursor in seen_cursors or next_cursor == cursor:
            raise ValueError("schema page cursor did not advance")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise ValueError("schema pagination exceeded its safety limit")


def check_schemas(root: Path, gateway: str, base: str, target: dict, token: str) -> None:
    if gateway == "api":
        print("api foundation has no custom plugin entities; schema inventory check skipped")
        return
    expected = {name: (root / path).read_text() for name, path in PLUGIN_FILES.items()}
    url = f"{base}/v2/control-planes/{target['control_plane_id']}/core-entities/plugin-schemas"
    pages = request_schema_pages(url, token)
    from wp1 import collect_schema_pages

    observed = collect_schema_pages(pages, set(expected))
    hashes = compare_schema_hashes(expected, observed)
    for name, result in hashes.items():
        print(f"{name}: CP {target['control_plane_id']} schema hash matches {result['expected_sha256']}")


def sync_schemas(root: Path, base: str, target: dict, token: str) -> None:
    expected = {name: (root / path).read_text() for name, path in PLUGIN_FILES.items()}
    url = f"{base}/v2/control-planes/{target['control_plane_id']}/core-entities/plugin-schemas"
    pages = request_schema_pages(url, token)
    from wp1 import collect_schema_pages, schema_hash

    all_items = [item for page in pages for item in page["items"]]
    present: dict[str, str] = {}
    for item in all_items:
        if not isinstance(item, dict):
            raise ValueError("schema inventory contains a malformed item")
        name, source = item.get("name"), item.get("lua_schema")
        if not isinstance(name, str) or not name or not isinstance(source, str) or not source:
            raise ValueError("schema inventory item is missing a valid name or lua_schema")
        if name in present:
            raise ValueError("duplicate schema name in CP inventory")
        present[name] = source
    # Validate a complete inventory before any write; missing desired schemas are expected here.
    if any(not name or not source for name, source in present.items()):
        raise ValueError("schema inventory contains malformed source")
    payload = {name: source for name, source in expected.items()}
    changed = [name for name, source in payload.items() if name not in present or schema_hash(source) != schema_hash(present[name])]
    for name in changed:
        if name in present:
            request_json(f"{url}/{name}", token, method="PUT", body={"lua_schema": payload[name]})
        else:
            request_json(url, token, method="POST", body={"lua_schema": payload[name]})
    print("Synchronized custom schema names: " + (", ".join(changed) if changed else "already current"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["validate", "preflight", "deck-validate", "deck-diff", "deck-sync", "schema-check", "schema-sync"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--stage")
    args = parser.parse_args()
    root = args.root.resolve()
    operation = args.operation.removeprefix("deck-")
    manifest_info = local_manifest(root, args.gateway, args.stage, operation)
    if operation in {"preflight", "validate"}:
        return 0
    if args.gateway == "api" and operation == "schema-sync":
        raise ValueError("API foundation must not register custom schemas")
    env = read_env(root / ".env")
    token = env.get("KONNECT_TOKEN", "")
    if not token:
        raise ValueError("KONNECT_TOKEN is required after local target validation")
    base = manifest_info["manifest"]["konnect_server_url"].rstrip("/")
    target = manifest_info["target"]
    verify_remote_target(base, target, token)
    if operation == "diff":
        return 0
    if operation == "schema-check":
        check_schemas(root, args.gateway, base, target, token)
        return 0
    if operation == "schema-sync":
        if os.environ.get("SCHEMA_SYNC_APPROVED") != "YES":
            raise ValueError("schema sync is a separate Konnect write; set SCHEMA_SYNC_APPROVED=YES only after explicit approval")
        sync_schemas(root, base, target, token)
        return 0
    if operation == "sync":
        return 0
    raise ValueError("unsupported WP1 operation")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"WP1 target check failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
