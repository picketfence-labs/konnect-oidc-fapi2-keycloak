#!/usr/bin/env python3
"""Exercise fresh Keycloak-issued tokens against the isolated WP3 API Route."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import selectors
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import yaml

from prepare_wp3_preview import (
    COMPOSE_FILE,
    IMAGES,
    PREVIEW,
    PROJECT,
    PreviewError,
    WP3_CASE_PHASES,
    WP3_EXECUTION_PHASES,
    inspect_images,
    load_runtime_role_values,
    require_loopback_port_free,
    validate_runtime_receipt,
    verify_preparation_receipt,
)
from wp3_tls_metadata import MAX_NGINX_CONFIG_BYTES as TLS_METADATA_MAX_CONFIG_BYTES
from wp3_tls_metadata import derive_effective_inbound_tls_policy


ROOT = Path(__file__).resolve().parents[2]
PUBLIC_ISSUER = "https://localhost:8444/realms/fapi-demo"
PUBLIC_ORIGIN = "https://localhost:8444"
FIXTURE_ORIGIN = "https://localhost:18444"
API_PORT = 18443
API_PATH = "/fapi-api/evidence"
EXPECTED_DEPARTMENT = "engineering"
EXPECTED_ROUTE = "engineering-route"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_TARGET_BYTES = 7680
MAX_ADMIN_RESPONSE_BYTES = 1024 * 1024
MAX_NGINX_CONFIG_BYTES = TLS_METADATA_MAX_CONFIG_BYTES
RESTY_EXECUTABLE = "/usr/local/openresty/bin/resty"
ADMIN_PROBE_STAGES = frozenset({
    "not_started", "admin_isolation", "resty_client_preflight", "root_get",
    "gateway_version", "plugin_inventory", "plugin_metadata", "plugin_schema", "complete",
})
ADMIN_PROBE_REASONS = frozenset({
    "not_started", "pending", "none", "admin_isolation_failed", "resty_binary_missing",
    "resty_http_module_missing", "resty_client_failed", "resty_client_timeout",
    "resty_connect_failed", "resty_request_failed", "admin_redirect_rejected",
    "admin_status_rejected", "admin_body_read_failed", "admin_body_too_large",
    "admin_response_malformed", "gateway_version_mismatch", "plugin_inventory_missing",
    "plugin_metadata_incomplete", "plugin_version_malformed", "plugin_priority_mismatch",
    "plugin_schema_fields_incomplete", "tls_request_enum_mismatch",
})
RESTY_HTTP_PREFLIGHT_LUA = (
    'local ok, http = pcall(require, "resty.http"); '
    'if not ok or type(http) ~= "table" or type(http.new) ~= "function" then os.exit(78) end; '
    'io.write("WP3_RESTY_HTTP_READY")'
)
ADMIN_PLUGIN_NAMES = {
    "pre-function": 1000000,
    "openid-connect": 1050,
    "tls-handshake-modifier": 997,
    "tls-metadata-headers": 996,
}
ADMIN_PROBE_PLUGINS = frozenset({"none", *ADMIN_PLUGIN_NAMES})
ADMIN_FIELD_ALLOWLIST = {
    "openid-connect": frozenset({
        "cache_introspection", "cache_tokens", "introspection_check_active",
        "upstream_headers", "audience_required", "scopes_required",
        "bearer_token_param_type", "proof_of_possession_mtls",
        "proof_of_possession_auth_methods_validation", "tls_client_auth_cert_id",
        "upstream_access_token_header", "issuer", "introspection_endpoint",
        "mtls_introspection_endpoint", "client_auth", "auth_methods",
    }),
    "tls-handshake-modifier": frozenset({"tls_client_certificate"}),
    "tls-metadata-headers": frozenset({"client_cert_header_name", "inject_client_cert_details"}),
}
ADMIN_ENUM_VALUES = frozenset({"REQUEST", "ON", "OFF", "header", "cookie", "query", "form", "introspection", "tls_client_auth", "strict", "true", "false"})
CLIENT_CERT_SPOOF_HEADERS = {
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


class FlowError(RuntimeError):
    pass


class RuntimeReceiptFailure(FlowError):
    REASONS = {"evidence_directory_unsafe", "schema_rejected", "destination_exists", "write_failed"}

    def __init__(self, reason: str, message: str):
        if reason not in self.REASONS:
            reason = "write_failed"
        self.reason = reason
        super().__init__(message)


class AdminProbeError(FlowError):
    def __init__(self, category: str):
        allowed = {
            "resty_binary_missing", "resty_http_module_missing", "resty_client_failed",
            "resty_client_timeout", "resty_connect_failed", "resty_request_failed",
            "admin_redirect_rejected", "admin_status_rejected", "admin_body_read_failed",
            "admin_body_too_large", "admin_response_malformed",
        }
        self.category = category if category in allowed else "resty_client_failed"
        super().__init__(self.category)


class LogScanError(FlowError):
    def __init__(self, category: str):
        allowed = {
            "container_inventory_unavailable",
            "log_stream_unavailable",
            "log_read_failed",
            "time_limit_exceeded",
            "byte_limit_exceeded",
        }
        self.category = category if category in allowed else "log_read_failed"
        super().__init__(self.category)


ROUTE_EXECUTION_PHASES = frozenset({
    "authorization",
    "token_exchange",
    "token_signature_and_claim_validation",
    "dedicated_mtls_introspection",
    "api_tls_and_authorization",
    "upstream_mtls_and_header_evidence",
})


def record_route_execution_phase(execution: dict, route_label: str, phase: str) -> None:
    if route_label not in {"A", "B"} or phase not in ROUTE_EXECUTION_PHASES:
        raise FlowError("route execution phase recorder rejected an unknown fixed phase")
    execution["phase"] = f"route_{route_label}_{phase}"


def host_crypto_diagnostics() -> dict:
    record = {
        "interpreter": sys.executable,
        "python_version": platform.python_version(),
        "pyjwt_version": "not_installed",
        "pyjwt_importable": False,
        "cryptography_version": "not_installed",
        "cryptography_importable": False,
    }
    try:
        record["pyjwt_version"] = importlib.metadata.version("PyJWT")
    except importlib.metadata.PackageNotFoundError:
        pass
    try:
        import jwt  # noqa: F401 - dependency preflight before any OAuth request

        record["pyjwt_importable"] = True
    except Exception:
        pass
    try:
        record["cryptography_version"] = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        pass
    try:
        import cryptography  # noqa: F401 - dependency preflight before any OAuth request

        record["cryptography_importable"] = True
    except Exception:
        pass
    return record


PUBLIC_FIXTURE_USERNAMES = frozenset({
    "wp2-preview-admin",
    "engineering.user@fapi-demo.invalid",
    "sales.user@fapi-demo.invalid",
})
PUBLIC_FIXTURE_IDENTIFIERS = PUBLIC_FIXTURE_USERNAMES | frozenset({
    "route-a.crt",
    "route-b.crt",
    "route-a.key",
    "route-b.key",
    "route-b-pkj.key",
    "api-introspection.crt",
    "api-upstream.crt",
    "api-introspection.key",
    "api-upstream.key",
    "third-party-fapi-mtls",
    "third-party-fapi-pkj-mtls",
})


def load_wp2_flow():
    source = ROOT / "tests/harness/wp2_flow.py"
    spec = importlib.util.spec_from_file_location("wp3_wp2_flow_support", source)
    if spec is None or spec.loader is None:
        raise FlowError("WP2 protocol support could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def map_loopback_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or parsed.hostname != "localhost":
        raise FlowError("fixture endpoint left the approved HTTPS loopback host")
    if parsed.port == 8444:
        return urllib.parse.urlunsplit((parsed.scheme, "localhost:18444", parsed.path, parsed.query, parsed.fragment))
    if parsed.port == 18444:
        return value
    if parsed.port == 8443:
        return value
    raise FlowError("fixture endpoint used an unapproved loopback port")


def install_fixture_transport(wp2):
    original_request_json = wp2.request_json
    original_submit_form = wp2.submit_local_form
    original_redirect_handler = wp2.LocalAuthRedirectHandler

    def fixture_request_json(base_url, path_or_url, *args, **kwargs):
        mapped_base = map_loopback_url(base_url.rstrip("/"))
        mapped_target = path_or_url
        if isinstance(path_or_url, str) and path_or_url.startswith("https://"):
            mapped_target = map_loopback_url(path_or_url)
        form = kwargs.get("form")
        if isinstance(form, dict):
            for key, value in form.items():
                category = category_for_sensitive_key(key) if isinstance(key, str) else None
                if category is not None:
                    remember_sensitive(
                        value,
                        category,
                        source="oauth_form_submission",
                        field=_candidate_field_label((key,)),
                    )
        bearer = kwargs.get("bearer")
        if isinstance(bearer, str):
            remember_sensitive(bearer, "oauth_token", source="oauth_admin_bearer", field="admin_bearer")
        return original_request_json(mapped_base, mapped_target, *args, **kwargs)

    def fixture_submit_form(opener, current_url, form, *args, **kwargs):
        copied = {"attrs": dict(form.get("attrs", {})), "fields": form.get("fields", []), "buttons": form.get("buttons", [])}
        remember_sensitive(copied["fields"], source="oauth_form_submission")
        action = copied["attrs"].get("action")
        if isinstance(action, str) and action.startswith("https://"):
            copied["attrs"]["action"] = map_loopback_url(action)
        return original_submit_form(opener, current_url, copied, *args, **kwargs)

    class FixtureRedirectHandler(original_redirect_handler):
        def redirect_request(self, request, file_pointer, code, message, headers, new_url):
            mapped = map_loopback_url(new_url)
            return super().redirect_request(request, file_pointer, code, message, headers, mapped)

    wp2.request_json = fixture_request_json
    wp2.submit_local_form = fixture_submit_form
    wp2.LocalAuthRedirectHandler = FixtureRedirectHandler


LOG_VALUE_CATEGORIES = (
    "certificate",
    "privatekey",
    "license",
    "password",
    "oauth_token",
    "code",
    "assertion",
    "cookie",
    "verifier",
    "spoof_sentinel",
    "public_fixed_protocol_constant",
    "public_fixture_identifier",
    "noncredential_protocol_identifier",
    "unknown",
)
LOG_CANDIDATE_SOURCES = frozenset({
    "unclassified_callsite",
    "fixture_pki_inventory",
    "fixture_account_inventory",
    "runtime_role_inventory",
    "oauth_form_submission",
    "oauth_route_grant",
    "oauth_authorization_state",
    "oauth_par_response",
    "oauth_token_response",
    "oauth_verified_access_token",
    "oauth_introspection_response",
    "oauth_admin_bearer",
    "oauth_browser_cookie_jar",
    "api_request_target",
    "api_request_body",
    "api_request_header",
    "api_caller_spoof_header",
    "api_invalid_bearer_fixture",
    "api_audience_fixture",
    "api_scope_fixture",
    "api_active_transition",
    "api_header_fixture",
    "public_protocol_inventory",
    "public_fixture_inventory",
    "explicit_candidate_input",
})
LOG_CANDIDATE_FIELDS = frozenset({
    "unkeyed_value",
    "other",
    "access_token",
    "id_token",
    "refresh_token",
    "authorization_code",
    "session_code",
    "state",
    "nonce",
    "pkce_verifier",
    "pkce_challenge",
    "par_request_uri",
    "cookie_value",
    "admin_bearer",
    "client_assertion",
    "client_assertion_type",
    "session_state",
    "session_id",
    "sid",
    "subject",
    "sub",
    "object_id",
    "id",
    "client_id",
    "redirect_uri",
    "azp",
    "preferred_username",
    "name",
    "email",
    "auth_time",
    "jti",
    "form_field_name",
    "api_query",
    "api_body",
    "authorization_header",
    "spoof_header",
    "username",
    "password",
    "issuer",
    "audience",
    "scope",
    "department",
    "route",
    "certificate_thumbprint",
    "certificate_file",
    "private_key_file",
    "license_material",
    "token_field_other",
})
LOG_MATCH_CONTEXTS = frozenset({
    "oauth_token_endpoint_request",
    "oauth_par_endpoint_request",
    "oauth_authorization_endpoint_request",
    "keycloak_introspection_token_error",
    "api_query_access_token_request",
    "api_resource_request",
    "other_service_log_context",
    "unclassified_log_context",
})
PUBLIC_LOG_CATEGORIES = frozenset({
    "public_fixed_protocol_constant",
    "public_fixture_identifier",
})
NONCREDENTIAL_LOG_CATEGORIES = frozenset({"noncredential_protocol_identifier"})
LOG_CREDENTIAL_FAILURE_CATEGORIES = frozenset(LOG_VALUE_CATEGORIES) - PUBLIC_LOG_CATEGORIES - NONCREDENTIAL_LOG_CATEGORIES
LOG_NONCREDENTIAL_CONTEXTS = frozenset({"keycloak_introspection_token_error"})
PUBLIC_FIXED_PROTOCOL_CONSTANTS = frozenset({
    PUBLIC_ISSUER,
    PUBLIC_ORIGIN,
    FIXTURE_ORIGIN,
    API_PATH,
    "https://localhost:8443/api/fapi/mtls",
    "https://localhost:8443/api/fapi/pkj-mtls",
    EXPECTED_DEPARTMENT,
    EXPECTED_ROUTE,
    "fapi-demo-api",
    "api-gateway-introspection",
    "openid profile",
})
HARMLESS_API_QUERY_TARGETS = frozenset({
    f"{API_PATH}?probe=small",
    f"{API_PATH}?" + "&".join(["x=1"] * 1000),
})
PUBLIC_FIELD_OBSERVATIONS = {
    "username": ("public_fixture_identifier", PUBLIC_FIXTURE_USERNAMES),
    "issuer": ("public_fixed_protocol_constant", frozenset({PUBLIC_ISSUER})),
    "iss": ("public_fixed_protocol_constant", frozenset({PUBLIC_ISSUER})),
    "aud": (
        "public_fixed_protocol_constant",
        frozenset({"fapi-demo-api", "api-gateway-introspection"}),
    ),
    "audience": (
        "public_fixed_protocol_constant",
        frozenset({"fapi-demo-api", "api-gateway-introspection"}),
    ),
    "scope": ("public_fixed_protocol_constant", frozenset({"openid", "profile", "openid profile"})),
    "department": ("public_fixed_protocol_constant", frozenset({EXPECTED_DEPARTMENT})),
    "route": ("public_fixed_protocol_constant", frozenset({EXPECTED_ROUTE})),
    "client_id": (
        "public_fixture_identifier",
        frozenset({"third-party-fapi-mtls", "third-party-fapi-pkj-mtls"}),
    ),
    "redirect_uri": (
        "public_fixed_protocol_constant",
        frozenset({
            "https://localhost:8443/api/fapi/mtls",
            "https://localhost:8443/api/fapi/pkj-mtls",
        }),
    ),
    "certificate": ("public_fixture_identifier", frozenset({
        "route-a.crt", "route-b.crt", "api-introspection.crt", "api-upstream.crt",
    })),
    "key": ("public_fixture_identifier", frozenset({
        "route-a.key", "route-b.key", "route-b-pkj.key",
        "api-introspection.key", "api-upstream.key",
    })),
    "signing_key": ("public_fixture_identifier", frozenset({"route-b-pkj.key"})),
}
SENSITIVE_VALUE_PROVENANCE: dict[tuple[str, str], set[tuple[str, str]]] = {}
PENDING_PROTOCOL_IDENTIFIERS: dict[int, list[dict]] = {}
RESPONSE_COLLECTION_SEQUENCE = 0
MAX_PENDING_PROTOCOL_IDENTIFIERS = 64
MAX_PENDING_PROTOCOL_COLLECTIONS = 64
MAX_PROTOCOL_IDENTIFIER_CHARS = 512
MAX_BOUND_RESPONSE_TOKEN_CHARS = 16384
RESPONSE_COLLECTION_TOKEN_BINDINGS: dict[int, str] = {}


class SensitiveValueList(list):
    """Keep the diagnostic provenance lifecycle aligned with the candidate list."""

    def clear(self):
        super().clear()
        SENSITIVE_VALUE_PROVENANCE.clear()
        PENDING_PROTOCOL_IDENTIFIERS.clear()
        RESPONSE_COLLECTION_TOKEN_BINDINGS.clear()
        global RESPONSE_COLLECTION_SEQUENCE
        RESPONSE_COLLECTION_SEQUENCE = 0


SENSITIVE_VALUES: list[tuple[str, str]] = SensitiveValueList()
# These two public certificate digests are registered from the hash-bound,
# freshly generated Route A/B fixture certificates before AS evidence is
# remembered. They are observations only at the exact cnf.x5t#S256 field.
PUBLIC_ROUTE_CERT_THUMBPRINTS: set[str] = set()


def category_for_sensitive_key(key: str) -> str | None:
    lowered = key.lower().replace("-", "_")
    if "license" in lowered:
        return "license"
    if "password" in lowered or "secret" in lowered:
        return "password"
    if "private_key" in lowered or lowered.endswith("_key"):
        return "privatekey"
    if "certificate" in lowered or "_cert" in lowered or lowered.endswith("_crt"):
        return "certificate"
    if "assertion" in lowered:
        return "assertion"
    if "cookie" in lowered or "session" in lowered:
        return "cookie"
    if "verifier" in lowered:
        return "verifier"
    if "code_challenge" in lowered:
        return "verifier"
    if lowered in {"nonce", "state", "jti", "request_uri"}:
        return "unknown"
    if "code" in lowered:
        return "code"
    if "token" in lowered or lowered == "authorization":
        return "oauth_token"
    return None


def _candidate_field_label(path, explicit_field=None):
    if explicit_field in LOG_CANDIDATE_FIELDS:
        return explicit_field
    normalized = tuple(
        item.lower().replace("-", "_") if isinstance(item, str) else ""
        for item in path
    )
    if len(normalized) >= 2 and normalized[-2:] == ("cnf", "x5t#s256"):
        return "certificate_thumbprint"
    key = normalized[-1] if normalized else ""
    if key in {"access_token", "token"}:
        return "access_token"
    if key == "id_token":
        return "id_token"
    if key == "refresh_token":
        return "refresh_token"
    if key == "code":
        return "authorization_code"
    if key == "session_code":
        return "session_code"
    if key == "state":
        return "state"
    if key == "nonce":
        return "nonce"
    if key in {"verifier", "code_verifier"}:
        return "pkce_verifier"
    if key == "code_challenge":
        return "pkce_challenge"
    if key == "request_uri":
        return "par_request_uri"
    if key in {"cookie", "cookie_value", "set_cookie"}:
        return "cookie_value"
    if key in {"client_assertion", "client_assertion_type"}:
        return key
    if key in {"session_state", "session_id", "sid", "subject", "sub", "id", "client_id", "redirect_uri"}:
        return key
    if key in {"azp", "preferred_username", "name", "email", "auth_time", "jti"}:
        return key
    if key in {"user_id", "object_id"}:
        return "object_id"
    if key in {"authorization", "bearer_token"}:
        return "authorization_header"
    if key == "password" or "password" in key:
        return "password"
    if key == "username" or "username" in key:
        return "username"
    if key in {"certificate", "cert", "crt"}:
        return "certificate_file"
    if key in {"private_key", "key"}:
        return "private_key_file"
    if key in {"iss", "issuer"}:
        return "issuer"
    if "license" in key:
        return "license_material"
    if key in {"aud", "audience"}:
        return "audience"
    if key == "scope":
        return "scope"
    if key == "department":
        return "department"
    if key == "route":
        return "route"
    if key in {"query", "request_target"}:
        return "api_query"
    if key in {"body", "request_body"}:
        return "api_body"
    if key in {"spoof_header", "header_value"}:
        return "spoof_header"
    if key in {"client_assertion"}:
        return "client_assertion"
    if key:
        return "token_field_other" if "token" in key else "other"
    return "unkeyed_value"


def remember_candidate_provenance(category, value, source, field):
    if not isinstance(value, str) or len(value) < 8:
        return
    if category not in LOG_VALUE_CATEGORIES:
        category = "unknown"
    if source not in LOG_CANDIDATE_SOURCES:
        source = "unclassified_callsite"
    if field not in LOG_CANDIDATE_FIELDS:
        field = "other"
    SENSITIVE_VALUE_PROVENANCE.setdefault((category, value), set()).add((source, field))


def remember_sensitive(
    value, category: str = "unknown", *,
    source: str = "unclassified_callsite", field: str | None = None,
    token_binding: str | None = None,
) -> int | None:
    if category not in LOG_VALUE_CATEGORIES:
        category = "unknown"
    if isinstance(value, str) and len(value) >= 8:
        SENSITIVE_VALUES.append((category, value))
        remember_candidate_provenance(category, value, source, field or "unkeyed_value")
        return None
    elif isinstance(value, dict):
        collection_id = None
        if (
            category == "unknown"
            and source in {"oauth_token_response", "oauth_introspection_response"}
            and len(PENDING_PROTOCOL_IDENTIFIERS) < MAX_PENDING_PROTOCOL_COLLECTIONS
        ):
            global RESPONSE_COLLECTION_SEQUENCE
            RESPONSE_COLLECTION_SEQUENCE += 1
            collection_id = RESPONSE_COLLECTION_SEQUENCE
            PENDING_PROTOCOL_IDENTIFIERS[collection_id] = []
            bound_token = value.get("access_token") if source == "oauth_token_response" else token_binding
            if (
                isinstance(bound_token, str)
                and 8 <= len(bound_token) <= MAX_BOUND_RESPONSE_TOKEN_CHARS
                and bound_token.isascii()
            ):
                RESPONSE_COLLECTION_TOKEN_BINDINGS[collection_id] = bound_token
        for key, nested in value.items():
            remember_sensitive_field(
                key, nested, category, source=source, path=(key,),
                collection_id=collection_id,
            )
        return collection_id
    elif isinstance(value, list):
        form_fields = (
            source == "oauth_form_submission"
            and all(isinstance(nested, dict) and "name" in nested and "value" in nested for nested in value)
        )
        if form_fields:
            for form_field in value:
                input_name = form_field.get("name")
                value_label = (
                    _candidate_field_label((input_name,))
                    if isinstance(input_name, str)
                    else "other"
                )
                for key, nested in form_field.items():
                    if key == "value":
                        # Preserve the previous candidate/category decision;
                        # the trusted control name adds only a finite label.
                        remember_sensitive(nested, category, source=source, field=value_label)
                    elif key == "name":
                        if nested == "username" and category == "unknown":
                            remember_sensitive(
                                nested, "public_fixed_protocol_constant", source=source,
                                field="form_field_name",
                            )
                        else:
                            remember_sensitive(nested, category, source=source, field="form_field_name")
                    else:
                        remember_sensitive_field(key, nested, category, source=source, path=(key,))
        else:
            for nested in value:
                remember_sensitive(nested, category, source=source, field=field)
        return None
    return None


def remember_sensitive_field(
    key, value, inherited_category: str, *,
    source: str = "unclassified_callsite", path: tuple = (), collection_id: int | None = None,
) -> None:
    normalized_key = key.lower().replace("-", "_") if isinstance(key, str) else ""
    field_category = category_for_sensitive_key(normalized_key) if normalized_key else None
    public_observation = PUBLIC_FIELD_OBSERVATIONS.get(normalized_key)
    inherited_is_sensitive = inherited_category not in {"unknown", *PUBLIC_LOG_CATEGORIES}
    current_path = (*path[:-1], normalized_key) if path else (normalized_key,)
    if normalized_key == "cnf" and isinstance(value, dict):
        # A certificate thumbprint is public only when it is the exact FAPI
        # cnf field and one of the two fresh Route leaf digests. An enclosing
        # password/token category always wins, and arbitrary cnf values stay
        # tracked as unknown sensitive values.
        for cnf_key, nested in value.items():
            if (
                cnf_key == "x5t#S256"
                and isinstance(nested, str)
                and nested in PUBLIC_ROUTE_CERT_THUMBPRINTS
                and inherited_category == "unknown"
            ):
                remember_sensitive(
                    nested, "public_fixture_identifier", source=source,
                    field="certificate_thumbprint",
                )
            else:
                child_category = (
                    "unknown" if inherited_category in PUBLIC_LOG_CATEGORIES else inherited_category
                )
                remember_sensitive_field(
                    cnf_key, nested, child_category, source=source,
                    path=(*current_path, cnf_key), collection_id=collection_id,
                )
        return
    if isinstance(value, str):
        deferred_category = field_category or inherited_category
        exact_top_level_key = (
            isinstance(key, str)
            and key == normalized_key
            and path == (key,)
        )
        eligible_pending_field = (
            collection_id is not None
            and inherited_category == "unknown"
            and source == "oauth_token_response"
            and exact_top_level_key
            and current_path == ("session_state",)
            and deferred_category == "cookie"
        ) or (
            collection_id is not None
            and inherited_category == "unknown"
            and source == "oauth_introspection_response"
            and exact_top_level_key
            and current_path in {("azp",), ("jti",), ("sid",), ("sub",)}
            and deferred_category == "unknown"
        )
        pending_total = sum(len(items) for items in PENDING_PROTOCOL_IDENTIFIERS.values())
        if (
            eligible_pending_field
            and 8 <= len(value) <= MAX_PROTOCOL_IDENTIFIER_CHARS
            and value.isascii()
            and pending_total < MAX_PENDING_PROTOCOL_IDENTIFIERS
        ):
            PENDING_PROTOCOL_IDENTIFIERS[collection_id].append({
                "value": value,
                "category": deferred_category,
                "source": source,
                "field": _candidate_field_label(current_path),
                "key": normalized_key,
            })
            return
        if (
            public_observation is not None
            and value in public_observation[1]
            and not inherited_is_sensitive
            and (normalized_key != "username" or source in {"oauth_form_submission", "fixture_account_inventory"})
            and (
                field_category is None
                or normalized_key in {"certificate", "key", "signing_key"}
            )
        ):
            remember_sensitive(
                value, public_observation[0], source=source,
                field=_candidate_field_label(current_path),
            )
        else:
            candidate_category = field_category or inherited_category
            SENSITIVE_VALUES.append((candidate_category, value))
            remember_candidate_provenance(
                candidate_category, value, source, _candidate_field_label(current_path),
            )
    elif isinstance(value, list):
        for item in value:
            remember_sensitive_field(
                normalized_key, item, field_category or inherited_category,
                source=source, path=current_path, collection_id=None,
            )
    elif isinstance(value, dict):
        for child_key, child_value in value.items():
            remember_sensitive_field(
                child_key, child_value, field_category or inherited_category,
                source=source, path=(*current_path, child_key), collection_id=collection_id,
            )


def _retain_protocol_identifier(record, category):
    remember_sensitive(
        record["value"], category, source=record["source"], field=record["field"],
    )


def _flush_protocol_identifier_collection(collection_id):
    RESPONSE_COLLECTION_TOKEN_BINDINGS.pop(collection_id, None)
    for record in PENDING_PROTOCOL_IDENTIFIERS.pop(collection_id, []):
        _retain_protocol_identifier(record, record["category"])


def _resolve_protocol_identifier_collection(collection_id, claims, grant, verified_token, *, response_kind, active=True):
    """Resolve fixed top-level identifiers after this response's token passed validation."""
    if type(collection_id) is not int:
        return
    records = PENDING_PROTOCOL_IDENTIFIERS.pop(collection_id, [])
    bound_token = RESPONSE_COLLECTION_TOKEN_BINDINGS.pop(collection_id, None)
    client = grant.get("client") if isinstance(grant, dict) else None
    client_id = client.get("client_id") if isinstance(client, dict) else None
    context_valid = (
        isinstance(claims, dict)
        and isinstance(verified_token, str)
        and isinstance(bound_token, str)
        and hmac.compare_digest(bound_token, verified_token)
        and isinstance(client_id, str)
        and isinstance(claims.get("azp"), str)
        and claims.get("azp") == client_id
        and active is True
    )
    for record in records:
        key = record["key"]
        field = record["field"]
        expected = None
        expected_source = "oauth_token_response" if response_kind == "token" else "oauth_introspection_response"
        if context_valid and record["source"] == expected_source and response_kind == "token" and key == "session_state" and field == "session_state":
            expected = claims.get("sid")
        elif context_valid and record["source"] == expected_source and response_kind == "introspection" and key in {"azp", "jti", "sid", "sub"} and field == key:
            expected = claims.get(key)
        category = (
            "noncredential_protocol_identifier"
            if isinstance(expected, str) and record["value"] == expected
            else record["category"]
        )
        _retain_protocol_identifier(record, category)


def resolve_verified_token_response_identifiers(collection_id, claims, grant, verified_token):
    _resolve_protocol_identifier_collection(
        collection_id, claims, grant, verified_token, response_kind="token", active=True,
    )


def resolve_verified_introspection_identifiers(collection_id, claims, grant, verified_token, *, active):
    _resolve_protocol_identifier_collection(
        collection_id, claims, grant, verified_token, response_kind="introspection", active=active,
    )


def flush_pending_protocol_identifiers():
    for collection_id in tuple(PENDING_PROTOCOL_IDENTIFIERS):
        _flush_protocol_identifier_collection(collection_id)


def register_public_route_certificate_thumbprints(wp2, pki: Path) -> None:
    """Bind public cnf observations to the two fresh Route certificates in memory."""
    PUBLIC_ROUTE_CERT_THUMBPRINTS.clear()
    try:
        thumbprints = {
            wp2.certificate_thumbprint(pki / "route-a.crt"),
            wp2.certificate_thumbprint(pki / "route-b.crt"),
        }
    except Exception:
        raise FlowError("fresh Route certificate thumbprints could not be derived") from None
    if len(thumbprints) != 2 or any(
        not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
        for value in thumbprints
    ):
        raise FlowError("fresh Route certificate thumbprints did not meet the bounded digest contract")
    PUBLIC_ROUTE_CERT_THUMBPRINTS.update(thumbprints)


def load_fixture_metadata(wp2, pki):
    discovery = wp2.request_json(
        FIXTURE_ORIGIN,
        PUBLIC_ISSUER + "/.well-known/openid-configuration",
        pki / "ca.crt",
    )
    if discovery.get("issuer") != PUBLIC_ISSUER:
        raise FlowError("Keycloak discovery did not retain the public token issuer")
    endpoint_names = {
        "authorization_endpoint": {8444},
        "token_endpoint": {8444, 18444},
        "pushed_authorization_request_endpoint": {8444, 18444},
        "introspection_endpoint": {8444, 18444},
        "jwks_uri": {8444, 18444},
    }
    metadata = dict(discovery)
    for name, approved_ports in endpoint_names.items():
        value = discovery.get(name)
        parsed = urllib.parse.urlsplit(value or "")
        if (
            parsed.scheme != "https"
            or parsed.hostname != "localhost"
            or parsed.port not in approved_ports
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise FlowError("Keycloak metadata endpoint did not use an approved TLS loopback origin")
        metadata[name] = map_loopback_url(value)
    jwks = wp2.request_json(FIXTURE_ORIGIN, metadata["jwks_uri"], pki / "ca.crt")
    document = wp2.JwksDocument(
        jwks,
        refresh=lambda: wp2.request_json(FIXTURE_ORIGIN, metadata["jwks_uri"], pki / "ca.crt"),
    )
    return PUBLIC_ISSUER, metadata, document


def require_callback_port_free() -> None:
    # Keycloak's isolated client registrations use the fixed callback port 8443.
    # Check immediately before binding; the listener is closed by its context manager.
    try:
        require_loopback_port_free(8443)
    except PreviewError:
        raise FlowError("fixed loopback OAuth callback port is unavailable") from None


def wait_for_runtime_ready(wp2, pki, containers, timeout_seconds=180):
    deadline = time.monotonic() + timeout_seconds
    last_probe = "not_ready"
    while time.monotonic() < deadline:
        try:
            health = subprocess.run(
                ["docker", "exec", containers["kong-api"], "kong-health"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                timeout=8,
            )
            discovery = wp2.request_json(
                FIXTURE_ORIGIN,
                PUBLIC_ISSUER + "/.well-known/openid-configuration",
                pki / "ca.crt",
            )
            if health.returncode == 0 and discovery.get("issuer") == PUBLIC_ISSUER:
                config = subprocess.run(
                    [
                        "docker", "exec", containers["kong-api"],
                        "nginx", "-p", "/usr/local/kong", "-c", "nginx.conf", "-T",
                    ],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                nginx_config = config.stdout + config.stderr
                if len(nginx_config) > MAX_NGINX_CONFIG_BYTES:
                    raise FlowError("active Nginx config exceeded the bounded metadata inspection size")
                alias_directives = re.findall(rb"(?m)^\s*underscores_in_headers\s+on\s*;", nginx_config)
                if config.returncode == 0 and len(alias_directives) == 1:
                    version_result = subprocess.run(
                        ["docker", "exec", containers["kong-api"], "nginx", "-v"],
                        cwd=ROOT,
                        check=False,
                        capture_output=True,
                        timeout=8,
                    )
                    version_text = version_result.stdout + version_result.stderr
                    if len(version_text) > 512:
                        version_text = b""
                    version_matches = re.findall(rb"(?m)^nginx version: (openresty/[0-9.]+)\s*$", version_text)
                    nginx_version = "openresty/1.29.2.5" if (
                        version_result.returncode == 0 and version_matches == [b"openresty/1.29.2.5"]
                    ) else "not_proven"
                    active_max_headers = re.findall(
                        rb"(?m)^\s*max_headers\s+([^;\r\n]+)\s*;",
                        b"\n".join(line for line in nginx_config.splitlines() if not line.lstrip().startswith(b"#")),
                    )
                    override_absent = len(active_max_headers) == 0
                    parser_limit = 1000 if nginx_version == "openresty/1.29.2.5" and override_absent else None
                    parser_source = "pinned_image_default_1000" if parser_limit == 1000 else "not_proven"
                    return {
                        "fixture_underscores_in_headers_on": True,
                        # Keep the bounded config dump in process memory only;
                        # it is parsed by the pinned-shape TLS helper after
                        # Admin's requested settings have been captured.
                        "nginx_config_dump": nginx_config,
                        "nginx_version": nginx_version,
                        "header_parser_metadata": {
                            "nginx_version": nginx_version,
                            "max_headers_override_absent": override_absent,
                            "default_header_limit": parser_limit,
                            "source": parser_source,
                        },
                    }
                raise FlowError("fixture underscore header mode could not be confirmed in active Nginx config")
            last_probe = "health_or_public_issuer_not_ready"
        except FlowError:
            raise
        except Exception:
            # Preserve only a fixed category; transport details can contain endpoint data.
            last_probe = "tls_metadata_or_health_unavailable"
        time.sleep(1)
    raise FlowError(f"bounded runtime readiness check timed out ({last_probe})")


def assert_fixture_admin_isolation(container_id: str) -> None:
    configured = subprocess.run(
        [
            "docker", "exec", container_id, "/bin/sh", "-c",
            'test "$KONG_ADMIN_LISTEN" = "127.0.0.1:8001" && test "$KONG_ADMIN_GUI_LISTEN" = "off"',
        ],
        cwd=ROOT, check=False, capture_output=True, timeout=8,
    )
    bindings = subprocess.run(
        ["docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", container_id],
        cwd=ROOT, check=False, capture_output=True, timeout=8,
    )
    if configured.returncode != 0 or bindings.returncode != 0 or len(bindings.stdout) > 16_384:
        raise FlowError("fixture Kong Admin listener isolation could not be verified")
    try:
        port_bindings = json.loads(bindings.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise FlowError("fixture Kong Admin port binding metadata is malformed") from None
    if not isinstance(port_bindings, dict) or port_bindings.get("8001/tcp") not in (None, []):
        raise FlowError("fixture Kong Admin listener is unexpectedly published to the host")


def _schema_field_observations(value, wanted: set[str], found=None):
    if found is None:
        found = {name: [] for name in wanted}
    if not isinstance(value, dict) or not isinstance(value.get("fields"), list):
        return found

    # Kong plugin schemas place the configuration record under the top-level
    # `fields` list. Count only direct children of its `config.fields` list;
    # recursive matching mistakes nested, unrelated records named `issuer`
    # for config.issuer and can turn a valid schema into a false duplicate.
    config_nodes = [
        field.get("config")
        for field in value["fields"]
        if isinstance(field, dict) and "config" in field
    ]
    if len(config_nodes) != 1:
        return found
    config = config_nodes[0]
    if not isinstance(config, dict) or config.get("type") != "record" or not isinstance(config.get("fields"), list):
        return found

    for field in config["fields"]:
        if not isinstance(field, dict):
            continue
        for name in wanted.intersection(field):
            node = field[name]
            if len(field) != 1 or not isinstance(node, dict):
                found[name].append({"type": "invalid", "enum": []})
                continue
            kind = node.get("type")
            if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", kind):
                found[name].append({"type": "invalid", "enum": []})
                continue
            enums = node.get("enum", node.get("one_of", []))
            safe_enums = []
            if isinstance(enums, list):
                safe_enums = sorted({item for item in enums if isinstance(item, str) and item in ADMIN_ENUM_VALUES})
            found[name].append({"type": kind, "enum": safe_enums})
    return found


def _resty_get_script(path: str) -> str:
    return f'''local ok, http = pcall(require, "resty.http")
if not ok or type(http) ~= "table" or type(http.new) ~= "function" then os.exit(78) end
local client = http.new()
client:set_timeouts(2000, 2000, 3000)
local connected, connect_err = client:connect("127.0.0.1", 8001)
if not connected then client:close(); os.exit(71) end
local response, request_err = client:request({{
  method = "GET",
  path = {json.dumps(path)},
  headers = {{["Host"] = "127.0.0.1", ["Connection"] = "close"}},
}})
if not response then client:close(); os.exit(72) end
if response.status ~= 200 then
  local status = response.status
  client:close()
  if type(status) == "number" and status >= 300 and status < 400 then os.exit(73) end
  os.exit(74)
end
if type(response.body_reader) ~= "function" then client:close(); os.exit(75) end
local chunks, total = {{}}, 0
while true do
  local chunk, read_err = response.body_reader(8192)
  if read_err then client:close(); os.exit(75) end
  if not chunk then break end
  total = total + #chunk
  if total > {MAX_ADMIN_RESPONSE_BYTES} then client:close(); os.exit(76) end
  chunks[#chunks + 1] = chunk
end
client:close()
io.write(table.concat(chunks))
'''


def _run_resty(container_id: str, script: str):
    try:
        return subprocess.run(
            ["docker", "exec", container_id, RESTY_EXECUTABLE, "-e", script],
            cwd=ROOT, check=False, capture_output=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        raise AdminProbeError("resty_client_timeout") from None
    except OSError:
        raise AdminProbeError("resty_client_failed") from None


def _admin_client_preflight(container_id: str) -> None:
    result = _run_resty(container_id, RESTY_HTTP_PREFLIGHT_LUA)
    if result.returncode in {126, 127}:
        raise AdminProbeError("resty_binary_missing")
    if result.returncode == 78:
        raise AdminProbeError("resty_http_module_missing")
    if result.returncode != 0 or result.stdout.strip() != b"WP3_RESTY_HTTP_READY":
        raise AdminProbeError("resty_client_failed")


def _admin_json(container_id: str, path: str):
    allowed_paths = {"/"} | {
        "/schemas/plugins/" + urllib.parse.quote(name, safe="-") for name in ADMIN_FIELD_ALLOWLIST
    }
    if path not in allowed_paths:
        raise AdminProbeError("resty_request_failed")
    result = _run_resty(container_id, _resty_get_script(path))
    if result.returncode == 126 or result.returncode == 127:
        raise AdminProbeError("resty_binary_missing")
    if result.returncode == 78:
        raise AdminProbeError("resty_http_module_missing")
    return_code_categories = {
        71: "resty_connect_failed",
        72: "resty_request_failed",
        73: "admin_redirect_rejected",
        74: "admin_status_rejected",
        75: "admin_body_read_failed",
        76: "admin_body_too_large",
    }
    if result.returncode != 0:
        raise AdminProbeError(return_code_categories.get(result.returncode, "resty_client_failed"))
    if len(result.stdout) > MAX_ADMIN_RESPONSE_BYTES:
        raise AdminProbeError("admin_body_too_large")
    try:
        parsed = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise AdminProbeError("admin_response_malformed") from None
    if not isinstance(parsed, dict):
        raise AdminProbeError("admin_response_malformed")
    return parsed


def _set_admin_probe_diagnostic(diagnostic: dict, stage: str, reason: str, plugin: str = "none") -> None:
    if stage not in ADMIN_PROBE_STAGES or reason not in ADMIN_PROBE_REASONS or plugin not in ADMIN_PROBE_PLUGINS:
        diagnostic.update({"stage": "plugin_metadata", "reason": "plugin_metadata_incomplete", "plugin": "none"})
        return
    diagnostic.update({"stage": stage, "reason": reason, "plugin": plugin})


def probe_loaded_schema_priorities(container_id: str, diagnostic: dict | None = None) -> dict:
    """Read exact runtime plugin metadata without retaining Admin config values."""
    diagnostic = diagnostic if diagnostic is not None else {}
    _set_admin_probe_diagnostic(diagnostic, "admin_isolation", "pending")
    try:
        assert_fixture_admin_isolation(container_id)
    except Exception:
        _set_admin_probe_diagnostic(diagnostic, "admin_isolation", "admin_isolation_failed")
        raise FlowError("fixture Kong Admin listener isolation could not be verified") from None

    _set_admin_probe_diagnostic(diagnostic, "resty_client_preflight", "pending")
    try:
        _admin_client_preflight(container_id)
    except AdminProbeError as error:
        _set_admin_probe_diagnostic(diagnostic, "resty_client_preflight", error.category)
        raise FlowError("fixture Kong Admin HTTP client preflight failed") from None
    _set_admin_probe_diagnostic(diagnostic, "resty_client_preflight", "none")

    _set_admin_probe_diagnostic(diagnostic, "root_get", "pending")
    try:
        root = _admin_json(container_id, "/")
    except AdminProbeError as error:
        _set_admin_probe_diagnostic(diagnostic, "root_get", error.category)
        raise FlowError("fixture Kong Admin root metadata request failed") from None
    _set_admin_probe_diagnostic(diagnostic, "root_get", "none")

    version = root.get("version")
    if version != "3.16.0.0":
        _set_admin_probe_diagnostic(diagnostic, "gateway_version", "gateway_version_mismatch")
        raise FlowError("fixture Kong Admin API did not report the exact pinned Gateway version")
    _set_admin_probe_diagnostic(diagnostic, "gateway_version", "none")
    plugins = root.get("plugins")
    available = plugins.get("available_on_server") if isinstance(plugins, dict) else None
    if not isinstance(available, dict):
        _set_admin_probe_diagnostic(diagnostic, "plugin_inventory", "plugin_inventory_missing")
        raise FlowError("fixture Kong Admin API omitted loaded plugin metadata")

    priorities = {}
    for name, expected_priority in ADMIN_PLUGIN_NAMES.items():
        _set_admin_probe_diagnostic(diagnostic, "plugin_metadata", "pending", name)
        item = available.get(name)
        if not isinstance(item, dict) or type(item.get("priority")) is not int:
            _set_admin_probe_diagnostic(diagnostic, "plugin_metadata", "plugin_metadata_incomplete", name)
            raise FlowError("fixture stock plugin priority metadata is incomplete")
        plugin_version = item.get("version")
        if not isinstance(plugin_version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", plugin_version):
            _set_admin_probe_diagnostic(diagnostic, "plugin_metadata", "plugin_version_malformed", name)
            raise FlowError("fixture stock plugin version metadata is malformed")
        priorities[name] = {"version": plugin_version, "priority": item["priority"]}
        if item["priority"] != expected_priority:
            _set_admin_probe_diagnostic(diagnostic, "plugin_metadata", "plugin_priority_mismatch", name)
            raise FlowError("fixture stock plugin priority differs from the reviewed 3.16 contract")
        _set_admin_probe_diagnostic(diagnostic, "plugin_metadata", "none", name)
    _set_admin_probe_diagnostic(diagnostic, "plugin_inventory", "none")

    fields = {}
    for plugin_name, wanted in ADMIN_FIELD_ALLOWLIST.items():
        _set_admin_probe_diagnostic(diagnostic, "plugin_schema", "pending", plugin_name)
        try:
            schema = _admin_json(container_id, "/schemas/plugins/" + urllib.parse.quote(plugin_name, safe="-"))
        except AdminProbeError as error:
            _set_admin_probe_diagnostic(diagnostic, "plugin_schema", error.category, plugin_name)
            raise FlowError("fixture stock plugin schema request failed") from None
        observed = _schema_field_observations(schema, set(wanted))
        current = {}
        for field in sorted(wanted):
            matches = observed[field]
            valid = len(matches) == 1 and matches[0]["type"] != "invalid"
            current[field] = {
                "present": valid,
                "type": matches[0]["type"] if valid else "ambiguous_or_missing",
                "enum": matches[0]["enum"] if valid else [],
            }
        if any(not item["present"] for item in current.values()):
            _set_admin_probe_diagnostic(diagnostic, "plugin_schema", "plugin_schema_fields_incomplete", plugin_name)
            raise FlowError("fixture stock plugin schema omitted or duplicated a required metadata field")
        fields[plugin_name] = current
        _set_admin_probe_diagnostic(diagnostic, "plugin_schema", "none", plugin_name)
    if fields["tls-handshake-modifier"]["tls_client_certificate"]["enum"] != ["REQUEST"]:
        _set_admin_probe_diagnostic(diagnostic, "plugin_schema", "tls_request_enum_mismatch", "tls-handshake-modifier")
        raise FlowError("TLS handshake modifier schema no longer exposes REQUEST mode")
    configuration = root.get("configuration")
    tls_policy = extract_tls_policy_metadata(configuration)
    _set_admin_probe_diagnostic(diagnostic, "complete", "none")
    return {
        "gateway_version": version,
        "plugins": priorities,
        "fields": fields,
        "admin_host_published": False,
        "tls_policy": tls_policy,
    }


def extract_tls_policy_metadata(configuration) -> dict:
    """Keep only exact allowlisted inbound TLS settings from Kong's Admin root."""
    if not isinstance(configuration, dict):
        return {"metadata_source": "not_proven", "cipher_suite": "not_proven", "protocols": []}
    suite = configuration.get("ssl_cipher_suite")
    protocols = configuration.get("ssl_protocols")
    exact_tls13 = protocols == "TLSv1.3" or protocols == ["TLSv1.3"]
    return {
        "metadata_source": "admin_root_configuration",
        "cipher_suite": "modern" if suite == "modern" else "not_proven",
        "protocols": ["TLSv1.3"] if exact_tls13 else [],
    }


def validate_runtime_state_contract() -> dict:
    """Report only booleans after checking the rendered, hash-bound API state."""
    path = PREVIEW / "api-runtime.yml"
    try:
        state = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        raise FlowError("hash-bound API runtime state could not be parsed") from None
    if not isinstance(state, dict):
        raise FlowError("hash-bound API runtime state was not a mapping")
    services = state.get("services")
    if not isinstance(services, list) or len(services) != 1 or not isinstance(services[0], dict):
        raise FlowError("API runtime state did not have exactly one owned API Service")
    service = services[0]
    expected_tags = {"fapi2-demo", "api"}
    expected_route_id = "14d51ff4-613c-4769-96ce-330cd8075855"
    expected_service_id = "a5fe77b4-93fd-4f84-bb31-71c245dedd09"
    expected_plugin_ids = {
        "pre-function": "4374b81d-77c4-4da1-9dfe-fbb0949a13ba",
        "openid-connect": "ed488e53-d29d-4db7-ba89-78b3bbf35df3",
        "tls-handshake-modifier": "6c3a195b-2fa7-4ed8-8ae4-72db3d2c537c",
        "tls-metadata-headers": "a6b8e2df-3612-47db-b863-b6dee55f2dc4",
    }
    expected_plugin_names = set(expected_plugin_ids)

    def has_expected_tags(entity) -> bool:
        tags = entity.get("tags") if isinstance(entity, dict) else None
        return isinstance(tags, list) and len(tags) == len(expected_tags) and set(tags) == expected_tags

    def has_expected_identity(entity, name: str, entity_id: str) -> bool:
        return (
            isinstance(entity, dict)
            and entity.get("name") == name
            # decK v1.53.1's render output omits entity IDs; where retained,
            # bind them to the fixed IDs in the source state hash.
            and entity.get("id") in (None, entity_id)
            and has_expected_tags(entity)
        )

    if not has_expected_identity(service, "fapi-api-resource-server", expected_service_id):
        raise FlowError("API Service identity or ownership tags changed")
    if (
        service.get("name") != "fapi-api-resource-server"
        or state.get("plugins") not in (None, [])
        or state.get("routes") not in (None, [])
        or service.get("plugins") not in (None, [])
    ):
        raise FlowError("API plugins or routes escaped their reviewed Service and Route scope")
    routes = service.get("routes")
    if not isinstance(routes, list) or len(routes) != 1:
        raise FlowError("API Service did not contain exactly one owned Route")
    route = routes[0]
    route_service = route.get("service")
    if route_service is not None and route_service not in (
        service.get("name"), expected_service_id,
        {"name": service.get("name")}, {"id": expected_service_id},
    ):
        raise FlowError("API Route explicitly referenced a conflicting Service")
    if (
        not has_expected_identity(route, "fapi-api-resource-server-route", expected_route_id)
        or route.get("paths") != [API_PATH]
        or route.get("protocols") != ["https"]
        or not isinstance(route.get("snis"), list)
        or any(not isinstance(name, str) for name in route["snis"])
        or len(route["snis"]) != 2
        or set(route["snis"]) != {"kong-api", "localhost"}
        or route.get("strip_path") is not True
    ):
        raise FlowError("API HTTPS Route identity, scope, or listener contract changed")
    route_plugins = route.get("plugins")
    if not isinstance(route_plugins, list) or len(route_plugins) != len(expected_plugin_names):
        raise FlowError("API Route did not contain the exact reviewed stock plugin set")
    plugin_records = {}
    for plugin in route_plugins:
        if not isinstance(plugin, dict) or not isinstance(plugin.get("name"), str):
            raise FlowError("API Route plugin record was malformed")
        name = plugin["name"]
        plugin_service = plugin.get("service")
        if (
            name not in expected_plugin_names
            or name in plugin_records
            or plugin.get("id") not in (None, expected_plugin_ids[name])
            or not has_expected_tags(plugin)
            or plugin.get("route") not in (None, route.get("name"), expected_route_id)
            or plugin_service not in (None, service.get("name"), expected_service_id)
            or plugin.get("consumer") is not None
            or not isinstance(plugin.get("config"), dict)
        ):
            raise FlowError("API stock plugin identity or Route ownership changed")
        plugin_records[name] = plugin
    if set(plugin_records) != expected_plugin_names:
        raise FlowError("API Route stock plugin inventory was incomplete")
    pre_function_config = plugin_records["pre-function"]["config"]
    pre_function_access = pre_function_config.get("access")
    tmh_config = plugin_records["tls-metadata-headers"]["config"]
    if (
        not isinstance(pre_function_access, list)
        or len(pre_function_access) != 1
        or not isinstance(pre_function_access[0], str)
        or not pre_function_access[0]
        or tmh_config.get("inject_client_cert_details") is not True
        or tmh_config.get("client_cert_header_name") != "X-Client-Cert"
    ):
        raise FlowError("API Route header or trusted TLS metadata plugin contract changed")
    config = plugin_records["openid-connect"].get("config")
    thm_config = plugin_records["tls-handshake-modifier"].get("config")
    if not isinstance(config, dict):
        raise FlowError("API OIDC state config was malformed")
    upstream_target_exact = (
        service.get("protocol") == "https"
        and service.get("host") == "pop-verifier"
        and service.get("port") == 9443
        and service.get("path") == "/evidence"
    )
    upstream_tls_verified = service.get("tls_verify") is True
    upstream_client_certificate_bound = (
        service.get("client_certificate") == "55555555-5555-4555-8555-555555555555"
    )
    foundation_ca_reused = (
        service.get("ca_certificates") == ["33333333-3333-4333-8333-333333333333"]
    )
    dedicated_mtls_introspection = (
        config.get("issuer") == "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration"
        and config.get("introspection_endpoint") == "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token/introspect"
        and config.get("mtls_introspection_endpoint") == "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token/introspect"
        and config.get("client_id") == ["api-gateway-introspection"]
        and config.get("client_auth") == ["tls_client_auth"]
        and config.get("auth_methods") == ["introspection"]
        and config.get("introspection_endpoint_auth_method") == "tls_client_auth"
        and config.get("tls_client_auth_cert_id") == "44444444-4444-4444-8444-444444444444"
        and config.get("ssl_verify") is True
        and config.get("tls_client_auth_ssl_verify") is True
    )
    pre_function_access = plugin_records["pre-function"]["config"].get("access")
    pre_function_script = (
        pre_function_access[0]
        if isinstance(pre_function_access, list) and len(pre_function_access) == 1 and isinstance(pre_function_access[0], str)
        else ""
    )
    query_guard_bound = (
        "pcall(kong.request.get_query, 1000)" in pre_function_script
        and 'normalized == "access-token"' in pre_function_script
        and "argument_count >= 1000" in pre_function_script
        and 'Bearer error="invalid_token"' in pre_function_script
        and "kong.response.exit(401" in pre_function_script
        and "get_raw_query" not in pre_function_script
        and "kong.log" not in pre_function_script
    )
    trusted_client_cert_metadata = (
        tmh_config.get("inject_client_cert_details") is True
        and tmh_config.get("client_cert_header_name") == "X-Client-Cert"
    )
    fields = {
        "route_plugin_inventory_exact": True,
        "upstream_target_exact": upstream_target_exact,
        "upstream_tls_verified": upstream_tls_verified,
        "upstream_client_certificate_bound": upstream_client_certificate_bound,
        "foundation_ca_reused": foundation_ca_reused,
        "dedicated_mtls_introspection": dedicated_mtls_introspection,
        "header_sanitizer_bound": isinstance(pre_function_access, list) and len(pre_function_access) == 1 and isinstance(pre_function_access[0], str) and bool(pre_function_access[0]),
        "query_auth_guard_bound": query_guard_bound,
        "trusted_client_cert_metadata": trusted_client_cert_metadata,
        "introspection_active_required": config.get("introspection_check_active") is True,
        "introspection_cache_disabled": config.get("cache_introspection") is False,
        "token_cache_disabled": config.get("cache_tokens") is False,
        "authorization_header_only": config.get("bearer_token_param_type") == ["header"],
        "required_api_audience": config.get("audience_required") == ["fapi-demo-api"],
        "required_openid_scope": config.get("scopes_required") == ["openid"],
        "public_token_issuer_preserved": config.get("issuers_allowed") == [PUBLIC_ISSUER],
        "authorization_header_forwarded": config.get("upstream_access_token_header") == "authorization:bearer",
        "route_https_only": route.get("protocols") == ["https"],
        "tls_handshake_requests_client_certificate": thm_config.get("tls_client_certificate") == "REQUEST",
    }
    if not all(fields.values()):
        raise FlowError("hash-bound API runtime state violated a required auth, cache, issuer, or TLS contract")
    return fields


def bounded_callback_server(wp2):
    class BoundedCallbackServer(wp2.CallbackServer):
        def __init__(self, pki):
            require_callback_port_free()
            try:
                super().__init__(pki)
            except OSError:
                raise FlowError("fixed loopback OAuth callback port is unavailable") from None
            self.server.daemon_threads = True

        def __enter__(self):
            self.thread.start()
            return self

        def __exit__(self, *_args):
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                raise FlowError("OAuth callback listener did not stop within its bound")

        def receive(self, expected_state, expected_path, timeout=120):
            return super().receive(expected_state, expected_path, timeout=min(timeout, 120))

    return BoundedCallbackServer


class PinnedSNIHTTPSConnection(http.client.HTTPSConnection):
    """Connect to loopback while independently choosing the TLS SNI name."""

    def __init__(self, server_name: str, context: ssl.SSLContext, certificate=None, private_key=None):
        super().__init__("127.0.0.1", API_PORT, timeout=12, context=context)
        self.server_name = server_name
        self.client_certificate = certificate
        self.client_private_key = private_key

    def connect(self):
        raw = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.server_name)


class ApiTlsFailure(FlowError):
    def __init__(self, layer: str, reason: str = "other_tls_error", verify_code: int | None = None):
        self.layer = layer if layer in {"client_tls_configuration", "tls_handshake", "server_certificate_validation", "transport"} else "transport"
        self.reason = reason if reason in TLS_FAILURE_REASONS else "other_tls_error"
        self.verify_code = verify_code if type(verify_code) is int and verify_code in TLS_VERIFY_CODES else None
        super().__init__(self.reason)


TLS_VERIFY_CODES = frozenset({18, 19, 20, 21, 27, 62})
TLS_FAILURE_REASONS = frozenset({
    "client_offer_unavailable", "client_hello_missing", "target_cipher_not_offered",
    "peer_alert_protocol_version", "peer_alert_handshake_failure",
    "peer_alert_insufficient_security", "server_san_mismatch", "server_untrusted_ca",
    "client_tls_configuration", "transport", "other_tls_error",
})
PEER_ALERT_REASONS = {
    "TLSV1_ALERT_PROTOCOL_VERSION": "peer_alert_protocol_version",
    "SSLV3_ALERT_PROTOCOL_VERSION": "peer_alert_protocol_version",
    "TLSV1_ALERT_HANDSHAKE_FAILURE": "peer_alert_handshake_failure",
    "SSLV3_ALERT_HANDSHAKE_FAILURE": "peer_alert_handshake_failure",
    "TLSV1_ALERT_INSUFFICIENT_SECURITY": "peer_alert_insufficient_security",
    "SSLV3_ALERT_INSUFFICIENT_SECURITY": "peer_alert_insufficient_security",
}
LOCAL_TLS_FAILURE_REASONS = frozenset({
    "NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_SHARED_CIPHER",
    "NO_SUITABLE_SIGNATURE_ALGORITHM", "LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED",
})


def classify_tls_exception(error: ssl.SSLError) -> ApiTlsFailure:
    code = getattr(error, "verify_code", None)
    if type(code) is int and code == 62:
        return ApiTlsFailure("server_certificate_validation", "server_san_mismatch", code)
    if type(code) is int and code in {18, 19, 20, 21, 27}:
        return ApiTlsFailure("server_certificate_validation", "server_untrusted_ca", code)
    reason = getattr(error, "reason", None)
    if isinstance(reason, str) and reason in PEER_ALERT_REASONS:
        return ApiTlsFailure("tls_handshake", PEER_ALERT_REASONS[reason])
    if isinstance(reason, str) and reason in LOCAL_TLS_FAILURE_REASONS:
        return ApiTlsFailure("client_tls_configuration", "client_offer_unavailable")
    return ApiTlsFailure("tls_handshake", "other_tls_error")


def _header_pairs(headers):
    if headers is None:
        return []
    if isinstance(headers, dict):
        return list(headers.items())
    if isinstance(headers, (list, tuple)) and all(
        isinstance(item, (list, tuple)) and len(item) == 2 for item in headers
    ):
        return [(name, value) for name, value in headers]
    raise FlowError("API request headers must be ordered name/value pairs")


def api_request_target_log_category(path):
    return (
        "public_fixed_protocol_constant"
        if isinstance(path, str) and path in HARMLESS_API_QUERY_TARGETS
        else "oauth_token"
    )


def serialize_api_request(method, path, pairs, body=None):
    request = bytearray(f"{method} {path} HTTP/1.1\r\n".encode("ascii"))
    for name, value in pairs:
        request.extend(name.encode("ascii"))
        request.extend(b": ")
        request.extend(value.encode("latin-1"))
        request.extend(b"\r\n")
    request.extend(b"\r\n")
    if body:
        request.extend(body)
    return bytes(request)


def request_api(pki, sni, certificate=None, private_key=None, path=API_PATH, headers=None, body=None, method="GET", *, minimum_tls=None, maximum_tls=None, cipher_suite=None, verify_server=True, server_ca_file=None, allow_san_mismatch=False, sensitive_header_source="api_request_header"):
    """Send ordered raw header pairs and preserve duplicate response headers."""
    allowed_sni = {"localhost", "kong-api"}
    if allow_san_mismatch:
        allowed_sni.add("wp3-san-mismatch.invalid")
    if not isinstance(sni, str) or sni not in allowed_sni:
        raise FlowError("API SNI is outside the fixed fixture allowlist")
    if not isinstance(path, str) or not path.startswith("/") or "\r" in path or "\n" in path or len(path.encode("utf-8")) > MAX_REQUEST_TARGET_BYTES:
        raise FlowError("API request target was rejected")
    if not re.fullmatch(r"[A-Z]{3,12}", method):
        raise FlowError("API request method was rejected")
    try:
        context = ssl.create_default_context(cafile=str(server_ca_file or pki / "ca.crt"))
    except (OSError, ssl.SSLError, ValueError):
        raise ApiTlsFailure("client_tls_configuration", "client_tls_configuration") from None
    if not verify_server:
        raise FlowError("server certificate verification cannot be disabled in WP3 probes")
    context.minimum_version = minimum_tls or ssl.TLSVersion.TLSv1_2
    context.maximum_version = maximum_tls or ssl.TLSVersion.MAXIMUM_SUPPORTED
    if cipher_suite is not None:
        try:
            context.set_ciphers(cipher_suite)
        except ssl.SSLError:
            raise ApiTlsFailure("client_tls_configuration", "client_offer_unavailable") from None
    if certificate is not None or private_key is not None:
        if not certificate or not private_key:
            raise ApiTlsFailure("client_tls_configuration", "client_tls_configuration")
        try:
            context.load_cert_chain(str(certificate), str(private_key))
        except (OSError, ssl.SSLError):
            raise ApiTlsFailure("client_tls_configuration", "client_tls_configuration") from None
    pairs = [("Host", sni), ("Accept", "application/json"), ("Connection", "close")]
    pairs.extend(_header_pairs(headers))
    for name, value in pairs:
        if (
            not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
            or not isinstance(value, str) or any(char in value for char in "\r\n\x00")
            or len(name) > 128 or len(value) > 64 * 1024
        ):
            raise FlowError("API request contained an invalid header field")
    if body is not None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
            raise FlowError("API request body exceeded the local harness limit")
        if not any(name.lower() == "content-type" for name, _ in pairs):
            pairs.append(("Content-Type", "application/x-www-form-urlencoded"))
        if not any(name.lower() == "content-length" for name, _ in pairs):
            pairs.append(("Content-Length", str(len(body))))
    _remember_headers(pairs, source=sensitive_header_source)
    if "?" in path:
        path_category = api_request_target_log_category(path)
        remember_sensitive(path, path_category, source="api_request_target", field="api_query")
        if path_category != "public_fixed_protocol_constant":
            try:
                query_values = urllib.parse.parse_qsl(
                    urllib.parse.urlsplit(path).query, keep_blank_values=True, max_num_fields=128,
                )
            except (ValueError, UnicodeError):
                query_values = []
            for _name, query_value in query_values:
                remember_sensitive(
                    query_value, "oauth_token", source="api_request_target", field="api_query",
                )
    if body:
        remember_sensitive(body.decode("latin-1"), "oauth_token", source="api_request_body", field="api_body")
    raw_socket = None
    tls_socket = None
    try:
        raw_socket = socket.create_connection(("127.0.0.1", API_PORT), timeout=12)
        try:
            tls_socket = context.wrap_socket(raw_socket, server_hostname=sni)
            raw_socket = None
        except ssl.SSLError as error:
            raise classify_tls_exception(error) from None
        request = serialize_api_request(method, path, pairs, body)
        tls_socket.settimeout(12)
        tls_socket.sendall(request)
        response = http.client.HTTPResponse(tls_socket)
        response.begin()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            API_RESPONSE_SCAN["response_count"] = API_RESPONSE_SCAN.get("response_count", 0) + 1
            API_RESPONSE_SCAN["completed"] = False
            API_RESPONSE_SCAN["failure_reason"] = "response_size_or_shape_limit"
            raise FlowError("API response exceeded the local harness limit")
        response_headers = [(name.lower(), value) for name, value in response.getheaders()]
        if not scan_api_response(raw, response_headers):
            raise FlowError("API response failed the bounded sensitive-material scan")
        try:
            parsed_body = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeError, json.JSONDecodeError):
            parsed_body = None
        return response.status, response_headers, parsed_body
    except ApiTlsFailure:
        raise
    except ssl.SSLError as error:
        raise classify_tls_exception(error) from None
    except (OSError, http.client.HTTPException, TimeoutError):
        raise ApiTlsFailure("transport", "transport") from None
    finally:
        if tls_socket is not None:
            tls_socket.close()
        if raw_socket is not None:
            raw_socket.close()


TLS13_APPROVED_AEAD_CIPHERS = frozenset({
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
})
TLS_VERSION_NAMES = {0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}


def tls_handshake_probe(pki, sni, certificate, private_key, *, minimum_tls=None, maximum_tls=None, cipher_suite=None, server_ca_file=None, allow_san_mismatch=False, observe=False):
    allowed_sni = {"localhost", "kong-api"}
    if allow_san_mismatch:
        allowed_sni.add("wp3-san-mismatch.invalid")
    if sni not in allowed_sni:
        raise ApiTlsFailure("client_tls_configuration", "client_tls_configuration")
    try:
        context = ssl.create_default_context(cafile=str(server_ca_file or pki / "ca.crt"))
        context.minimum_version = minimum_tls or ssl.TLSVersion.TLSv1_2
        context.maximum_version = maximum_tls or ssl.TLSVersion.MAXIMUM_SUPPORTED
    except (OSError, ssl.SSLError, ValueError):
        raise ApiTlsFailure("client_tls_configuration", "client_tls_configuration") from None
    if cipher_suite is not None:
        try:
            context.set_ciphers(cipher_suite)
        except ssl.SSLError:
            raise ApiTlsFailure("client_tls_configuration", "client_offer_unavailable") from None
    try:
        context.load_cert_chain(str(certificate), str(private_key))
    except (OSError, ssl.SSLError, ValueError):
        raise ApiTlsFailure("client_tls_configuration", "client_tls_configuration") from None
    raw_socket = socket.create_connection(("127.0.0.1", API_PORT), timeout=12)
    try:
        try:
            tls_socket = context.wrap_socket(raw_socket, server_hostname=sni)
        except ssl.SSLError as error:
            raise classify_tls_exception(error) from None
        if observe:
            protocol = tls_socket.version()
            negotiated_cipher = tls_socket.cipher()
            cipher_name = negotiated_cipher[0] if isinstance(negotiated_cipher, tuple) and negotiated_cipher else None
            metadata = {
                "protocol": protocol if protocol in {"TLSv1.2", "TLSv1.3"} else "not_proven",
                "cipher": cipher_name if cipher_name in TLS13_APPROVED_AEAD_CIPHERS else "not_proven",
            }
            tls_socket.close()
            return metadata
        tls_socket.close()
        return True
    except ApiTlsFailure:
        raise
    except (OSError, TimeoutError):
        raise ApiTlsFailure("transport", "transport") from None
    finally:
        try:
            raw_socket.close()
        except OSError:
            pass


def client_hello_offerability(pki, sni, certificate, private_key, *, minimum_tls=None, maximum_tls=None, cipher_suite=None, expected_cipher_id=None):
    """Prove in memory that this client can put a bounded ClientHello on the wire."""
    if sni not in {"localhost", "kong-api"}:
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_tls_configuration"}
    try:
        context = ssl.create_default_context(cafile=str(pki / "ca.crt"))
        context.minimum_version = minimum_tls or ssl.TLSVersion.TLSv1_2
        context.maximum_version = maximum_tls or ssl.TLSVersion.MAXIMUM_SUPPORTED
        if cipher_suite is not None:
            context.set_ciphers(cipher_suite)
        context.load_cert_chain(str(certificate), str(private_key))
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        connection = context.wrap_bio(incoming, outgoing, server_hostname=sni)
        try:
            connection.do_handshake()
        except ssl.SSLWantReadError:
            pass
        transcript = outgoing.read(64 * 1024)
    except (OSError, ssl.SSLError, ValueError):
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_offer_unavailable"}

    handshake = bytearray()
    offset = 0
    while offset + 5 <= len(transcript):
        record_type = transcript[offset]
        record_length = int.from_bytes(transcript[offset + 3:offset + 5], "big")
        offset += 5
        if record_length == 0 or offset + record_length > len(transcript):
            break
        if record_type != 22:
            break
        handshake.extend(transcript[offset:offset + record_length])
        offset += record_length
    if len(handshake) < 4 or handshake[0] != 1:
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_hello_missing"}
    message_length = int.from_bytes(handshake[1:4], "big")
    if message_length + 4 > len(handshake):
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_hello_missing"}
    body = memoryview(handshake)[4:4 + message_length]
    legacy_version = int.from_bytes(body[0:2], "big") if len(body) >= 2 else 0
    index = 2 + 32
    if len(body) <= index:
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_hello_missing"}
    session_length = body[index]
    index += 1 + session_length
    if len(body) < index + 2:
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_hello_missing"}
    cipher_length = int.from_bytes(body[index:index + 2], "big")
    index += 2
    if cipher_length < 2 or cipher_length % 2 or len(body) < index + cipher_length:
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_hello_missing"}
    suites = {
        int.from_bytes(body[position:position + 2], "big")
        for position in range(index, index + cipher_length, 2)
    }
    index += cipher_length
    if len(body) <= index:
        return {"client_hello_emitted": False, "target_cipher_offered": False, "offered_protocols": [], "reason": "client_hello_missing"}
    compression_length = body[index]
    index += 1 + compression_length
    offered_versions = []
    if len(body) >= index + 2:
        extensions_length = int.from_bytes(body[index:index + 2], "big")
        index += 2
        end = index + extensions_length
        if end <= len(body):
            while index + 4 <= end:
                extension_type = int.from_bytes(body[index:index + 2], "big")
                extension_length = int.from_bytes(body[index + 2:index + 4], "big")
                index += 4
                if index + extension_length > end:
                    offered_versions = []
                    break
                extension = body[index:index + extension_length]
                if extension_type == 43 and extension_length >= 3:
                    vector_length = extension[0]
                    if vector_length + 1 == extension_length and vector_length % 2 == 0:
                        offered_versions = [
                            TLS_VERSION_NAMES[version]
                            for offset in range(1, extension_length, 2)
                            if (version := int.from_bytes(extension[offset:offset + 2], "big")) in TLS_VERSION_NAMES
                        ]
                index += extension_length
    if not offered_versions and legacy_version in TLS_VERSION_NAMES:
        offered_versions = [TLS_VERSION_NAMES[legacy_version]]
    offered = expected_cipher_id is None or expected_cipher_id in suites
    reason = "none" if offered else "target_cipher_not_offered"
    return {
        "client_hello_emitted": True,
        "target_cipher_offered": offered,
        "offered_protocols": offered_versions,
        "reason": reason,
    }


def observe_tls_client_certificate_request(pki, sni, certificate, private_key) -> bool:
    """Use OpenSSL's handshake trace in memory; emit only the request boolean."""
    binary = shutil.which("openssl")
    if not binary or sni not in {"localhost", "kong-api"}:
        raise FlowError("bounded TLS certificate-request observer is unavailable")
    try:
        result = subprocess.run(
            [
                binary, "s_client", "-connect", "127.0.0.1:18443", "-servername", sni,
                "-verify_return_error", "-CAfile", str(pki / "ca.crt"),
                "-cert", str(certificate), "-key", str(private_key), "-msg", "-brief",
            ],
            cwd=ROOT, input=b"", check=False, capture_output=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise FlowError("TLS certificate-request observation exceeded its local bound") from None
    transcript = result.stdout + result.stderr
    return result.returncode == 0 and b"CertificateRequest" in transcript


def _challenge_parts(value: str):
    if not isinstance(value, str) or len(value) > 4096:
        return None
    # RFC 9110 requires 1*SP between the auth-scheme and credentials.  BWS
    # around '=' and OWS around list commas are accepted below.
    if value.lower() == "bearer":
        return {}
    match = re.match(r"(?i)^Bearer +", value)
    if not match:
        return None
    rest = value[match.end():]
    fields = []
    index = 0
    while index < len(rest):
        key_match = re.match(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", rest[index:])
        if not key_match:
            return None
        key = key_match.group(0).lower()
        index += key_match.end()
        while index < len(rest) and rest[index] in " \t":
            index += 1
        if index >= len(rest) or rest[index] != "=":
            return None
        index += 1
        while index < len(rest) and rest[index] in " \t":
            index += 1
        if index >= len(rest):
            return None
        if rest[index] == '"':
            index += 1
            value_chars = []
            closed = False
            while index < len(rest):
                char = rest[index]
                index += 1
                if char == '"':
                    closed = True
                    break
                if char == "\\":
                    if index >= len(rest):
                        return None
                    char = rest[index]
                    index += 1
                if (ord(char) < 0x20 and char != "\t") or ord(char) == 0x7f:
                    return None
                value_chars.append(char)
            if not closed:
                return None
            parameter = "".join(value_chars)
        else:
            token = re.match(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", rest[index:])
            if not token:
                return None
            parameter = token.group(0)
            index += token.end()
        fields.append((key, parameter))
        while index < len(rest) and rest[index] in " \t":
            index += 1
        if index == len(rest):
            break
        if rest[index] != ",":
            return None
        index += 1
        while index < len(rest) and rest[index] in " \t":
            index += 1
        if index >= len(rest):
            return None
    if len({key for key, _ in fields}) != len(fields):
        return None
    if any(key not in {"error", "error_description", "error_uri", "realm", "scope"} for key, _ in fields):
        return None
    return dict(fields)


def rfc6750_error(headers, expected=None):
    if isinstance(headers, list):
        values = [value for name, value in headers if isinstance(name, str) and name.lower() == "www-authenticate"]
    elif isinstance(headers, dict):
        values = [value for name, value in headers.items() if isinstance(name, str) and name.lower() == "www-authenticate"]
    else:
        return "malformed"
    if len(values) != 1:
        return "malformed"
    parsed = _challenge_parts(values[0])
    if parsed is None:
        return "malformed"
    if "error" not in parsed:
        return "error_absent"
    if parsed.get("error") not in {"invalid_token", "insufficient_scope"}:
        return "malformed"
    error = parsed["error"]
    if expected is not None and error != expected:
        return "malformed"
    return error


def challenge_for_status(status, headers):
    expected = "invalid_token" if status == 401 else "insufficient_scope" if status == 403 else None
    if expected is None:
        return "not_applicable"
    if isinstance(headers, list):
        challenge_headers = [
            value for name, value in headers
            if isinstance(name, str) and name.lower() == "www-authenticate"
        ]
    elif isinstance(headers, dict):
        challenge_headers = [
            value for name, value in headers.items()
            if isinstance(name, str) and name.lower() == "www-authenticate"
        ]
    else:
        challenge_headers = []
    if not challenge_headers:
        return "missing_header"
    return rfc6750_error(headers, expected)


def verify_capture(wp2, evidence, token, claims, cert_path):
    expected_fields = {
        "request_header_count", "authorization_header_count", "authorization_single_bearer",
        "authorization_sha256", "authorization_matches_expected_token", "cookie_header_count",
        "cookie_absent", "client_assertion_header_count", "client_assertion_type_header_count",
        "client_assertion_like_header_count", "client_assertion_unknown_suffix_header_count",
        "client_assertion_headers_absent", "x_fapi_header_count", "x_fapi_duplicate_header_count",
        "x_fapi_underscore_prefix_count", "x_fapi_headers_absent", "x_demo_header_count",
        "x_demo_duplicate_header_count", "x_demo_underscore_prefix_count",
        "x_demo_unexpected_header_count", "x_demo_unexpected_headers_absent",
        "department_header_count", "department_header_matches_expected_claim", "route_header_count",
        "route_header_matches_expected_claim", "x_client_cert_like_header_count",
        "x_client_cert_unknown_suffix_header_count", "x_client_cert_duplicate_header_count",
        "x_client_cert_underscore_alias_count", "x_client_cert_stock_detail_counts",
        "x_client_cert_stock_details_complete", "x_client_cert_fingerprint_matches_forwarded_leaf",
        "caller_spoof_sentinel_match_count", "x_client_cert_header_count",
        "forwarded_certificate_single_url_encoded_pem_leaf", "forwarded_certificate_thumbprint_prefix12",
        "forwarded_certificate_thumbprint", "forwarded_certificate_matches_expected_route",
        "status", "api_peer_pin_matches", "api_peer_common_name_matches", "request_count",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_fields or evidence.get("status") != "captured":
        raise FlowError("TLS capture response did not contain a sanitized evidence object")
    expected_token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    expected_cert_thumbprint = wp2.certificate_thumbprint(cert_path)
    cnf = claims.get("cnf", {}).get("x5t#S256") if isinstance(claims.get("cnf"), dict) else None
    if not isinstance(cnf, str) or not hmac.compare_digest(cnf, expected_cert_thumbprint):
        raise FlowError("verified Keycloak token does not bind to the Route certificate")
    if (
        not isinstance(evidence.get("authorization_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", evidence["authorization_sha256"])
        or not isinstance(evidence.get("forwarded_certificate_thumbprint"), str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", evidence["forwarded_certificate_thumbprint"])
        or evidence.get("authorization_matches_expected_token") is not None
        or evidence.get("forwarded_certificate_matches_expected_route") is not None
    ):
        raise FlowError("capture digest fields did not match the in-memory comparison contract")
    if evidence.get("forwarded_certificate_thumbprint_prefix12") != expected_cert_thumbprint[:12]:
        raise FlowError("capture certificate digest prefix did not match the Route certificate")
    comparisons = {
        "api_peer_pin_matches": True,
        "api_peer_common_name_matches": True,
        "authorization_single_bearer": True,
        "authorization_sha256": expected_token_digest,
        "cookie_absent": True,
        "client_assertion_headers_absent": True,
        "client_assertion_like_header_count": 0,
        "client_assertion_unknown_suffix_header_count": 0,
        "x_fapi_headers_absent": True,
        "x_demo_unexpected_headers_absent": True,
        "department_header_matches_expected_claim": True,
        "route_header_matches_expected_claim": True,
        "x_client_cert_unknown_suffix_header_count": 0,
        "x_client_cert_duplicate_header_count": 0,
        "x_client_cert_underscore_alias_count": 0,
        "x_client_cert_stock_details_complete": True,
        "x_client_cert_fingerprint_matches_forwarded_leaf": True,
        "caller_spoof_sentinel_match_count": 0,
        "x_client_cert_header_count": 1,
        "forwarded_certificate_single_url_encoded_pem_leaf": True,
        "forwarded_certificate_thumbprint": expected_cert_thumbprint,
    }
    for field, expected in comparisons.items():
        observed = evidence.get(field)
        if isinstance(expected, str):
            if not isinstance(observed, str) or not hmac.compare_digest(observed, expected):
                raise FlowError("Gateway capture evidence did not match the signed token or fixture identity")
        elif observed != expected:
            raise FlowError("Gateway capture evidence did not satisfy the fixed header-boundary contract")
    expected_detail_counts = {
        "serial": 1,
        "issuer_dn": 1,
        "subject_dn": 1,
        "fingerprint": 1,
        "chain": 1,
    }
    observed_detail_counts = evidence.get("x_client_cert_stock_detail_counts")
    if (
        not isinstance(observed_detail_counts, dict)
        or set(observed_detail_counts) != set(expected_detail_counts)
        or any(type(value) is not int or value != 1 for value in observed_detail_counts.values())
    ):
        raise FlowError("stock TLS metadata header counts did not match the fixed certificate-detail contract")
    for field in expected_fields:
        if field.endswith("_count") or field in {"request_count", "request_header_count", "authorization_header_count", "cookie_header_count", "client_assertion_header_count", "client_assertion_type_header_count", "client_assertion_like_header_count", "client_assertion_unknown_suffix_header_count", "x_fapi_header_count", "x_fapi_duplicate_header_count", "x_fapi_underscore_prefix_count", "x_demo_header_count", "x_demo_duplicate_header_count", "x_demo_underscore_prefix_count", "x_demo_unexpected_header_count", "department_header_count", "route_header_count", "x_client_cert_like_header_count", "x_client_cert_unknown_suffix_header_count", "x_client_cert_duplicate_header_count", "x_client_cert_underscore_alias_count", "caller_spoof_sentinel_match_count", "x_client_cert_header_count"}:
            if type(evidence.get(field)) is not int or not 0 <= evidence[field] <= 4096:
                raise FlowError("capture count field was not a bounded integer")
    bool_fields = {
        "authorization_single_bearer", "cookie_absent", "client_assertion_headers_absent",
        "x_fapi_headers_absent", "x_demo_unexpected_headers_absent",
        "department_header_matches_expected_claim", "route_header_matches_expected_claim",
        "x_client_cert_stock_details_complete", "x_client_cert_fingerprint_matches_forwarded_leaf",
        "forwarded_certificate_single_url_encoded_pem_leaf", "api_peer_pin_matches",
        "api_peer_common_name_matches",
    }
    if any(type(evidence.get(field)) is not bool for field in bool_fields):
        raise FlowError("capture boolean field was malformed")
    if evidence.get("department_header_matches_expected_claim") is not True or evidence.get("route_header_matches_expected_claim") is not True:
        raise FlowError("claim-derived Gateway headers did not match the fixed Engineering fixture claims")
    if claims.get(f"{wp2.NAMESPACE}/department") != EXPECTED_DEPARTMENT or claims.get(f"{wp2.NAMESPACE}/route") != EXPECTED_ROUTE:
        raise FlowError("verified access token did not contain the expected Engineering fixture claims")


MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_SERVICE_LOG_BYTES = MAX_LOG_BYTES
MAX_LOG_SCAN_SECONDS = 60
LOG_SERVICE_NAMES = ("keycloak", "kong-api", "pop-verifier")
LOG_CREDENTIAL_PATTERN_CHECKS = (
    ("private_key_pem", r"-----BEGIN (?:RSA |EC |PRIVATE )?PRIVATE KEY-----"),
    ("bearer_authorization", r"(?i)authorization:\s*bearer\s+\S+"),
    ("cookie_or_forwarded_certificate", r"(?i)(?:set-cookie|cookie|x-client-cert):\s*\S+"),
    ("client_assertion_form", r"(?i)(?:client_assertion|client_assertion_type)=\S+"),
    ("oauth_token_field", r"(?i)(?:access_token|id_token|assertion)=\S+"),
    ("jwt_shape", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
)
API_RESPONSE_SCAN = {}


def reset_api_response_scan() -> None:
    API_RESPONSE_SCAN.clear()
    API_RESPONSE_SCAN.update({
        "completed": True,
        "failure_reason": "none",
        "response_count": 0,
        "scanned_byte_count": 0,
        "secret_value_match_count": 0,
        "secret_match_category_counts": {category: 0 for category in LOG_VALUE_CATEGORIES},
        "credential_pattern_matches": [],
    })


def scan_api_response(raw_body: bytes, headers: list[tuple[str, str]]) -> bool:
    """Scan bounded API response bytes in memory; never retain or return values."""
    API_RESPONSE_SCAN["response_count"] += 1
    if (
        not isinstance(raw_body, bytes)
        or len(raw_body) > MAX_RESPONSE_BYTES
        or not isinstance(headers, list)
        or len(headers) > 256
        or any(
            not isinstance(name, str) or not isinstance(value, str)
            or len(name) > 256 or len(value) > 16 * 1024
            for name, value in headers
        )
    ):
        API_RESPONSE_SCAN["completed"] = False
        API_RESPONSE_SCAN["failure_reason"] = "response_size_or_shape_limit"
        return False
    material = raw_body.decode("latin-1") + "\n" + "\n".join(
        name + ": " + value for name, value in headers
    )
    material_bytes = len(raw_body) + sum(len(name) + len(value) + 2 for name, value in headers)
    if material_bytes > 256 * 1024:
        API_RESPONSE_SCAN["completed"] = False
        API_RESPONSE_SCAN["failure_reason"] = "response_size_or_shape_limit"
        return False
    API_RESPONSE_SCAN["scanned_byte_count"] += material_bytes
    compact = "".join(material.split())
    matches = {
        (category, value)
        for category, value in normalize_log_candidates([])
        if candidate_log_match(category, value, material, compact)
    }
    secret_matches = {item for item in matches if item[0] not in PUBLIC_LOG_CATEGORIES}
    counts = API_RESPONSE_SCAN["secret_match_category_counts"]
    for category, _value in secret_matches:
        counts[category] = min(10000, counts[category] + 1)
    API_RESPONSE_SCAN["secret_value_match_count"] = min(
        10000, API_RESPONSE_SCAN["secret_value_match_count"] + len(secret_matches),
    )
    patterns = (
        ("private_key_pem", r"-----BEGIN (?:RSA |EC |PRIVATE )?PRIVATE KEY-----"),
        ("bearer_authorization", r"(?i)authorization:\s*bearer\s+\S+"),
        ("cookie_or_forwarded_certificate", r"(?i)(?:set-cookie|cookie|x-client-cert):\s*\S+"),
        ("client_assertion_form", r"(?i)(?:client_assertion|client_assertion_type)=\S+"),
        ("oauth_token_field", r"(?i)(?:access_token|id_token|assertion)=\S+"),
        ("jwt_shape", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    )
    pattern_matches = [name for name, expression in patterns if re.search(expression, material)]
    API_RESPONSE_SCAN["credential_pattern_matches"] = sorted(set(
        API_RESPONSE_SCAN["credential_pattern_matches"] + pattern_matches
    ))
    return not secret_matches and not pattern_matches


def api_response_scan_receipt() -> dict:
    return {
        "api_response_completed": API_RESPONSE_SCAN.get("completed") is True,
        "api_response_failure_reason": API_RESPONSE_SCAN.get("failure_reason", "not_started"),
        "api_response_count": API_RESPONSE_SCAN.get("response_count", 0),
        "api_response_scanned_byte_count": API_RESPONSE_SCAN.get("scanned_byte_count", 0),
        "api_response_secret_value_match_count": API_RESPONSE_SCAN.get("secret_value_match_count", 0),
        "api_response_secret_match_category_counts": dict(API_RESPONSE_SCAN.get(
            "secret_match_category_counts", {category: 0 for category in LOG_VALUE_CATEGORIES}
        )),
        "api_response_credential_pattern_matches": list(API_RESPONSE_SCAN.get("credential_pattern_matches", [])),
    }


def compose_service_logs() -> tuple[dict[str, str], dict[str, dict], str]:
    """Read exact owned-service logs into bounded memory without merging provenance."""
    service_status = {
        service: {
            "completed": False,
            "failure_reason": "container_inventory_unavailable",
            "scanned_byte_count": 0,
        }
        for service in LOG_SERVICE_NAMES
    }
    try:
        containers = verify_owned_project_containers(allow_stopped=True)
    except FlowError:
        return {}, service_status, "container_inventory_unavailable"
    if not isinstance(containers, dict) or set(containers) != set(LOG_SERVICE_NAMES) or any(
        not isinstance(containers.get(service), str) or not containers[service]
        for service in LOG_SERVICE_NAMES
    ):
        return {}, service_status, "container_inventory_unavailable"

    service_status = {
        service: {
            "completed": False,
            "failure_reason": "log_stream_unavailable",
            "scanned_byte_count": 0,
        }
        for service in LOG_SERVICE_NAMES
    }
    buffers = {service: bytearray() for service in LOG_SERVICE_NAMES}
    processes: dict[str, subprocess.Popen] = {}
    eof_services = set()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + MAX_LOG_SCAN_SECONDS
    aggregate_bytes = 0
    aggregate_failure = "none"
    try:
        for service in LOG_SERVICE_NAMES:
            try:
                process = subprocess.Popen(
                    ["docker", "logs", containers[service]],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
            except OSError:
                service_status[service]["failure_reason"] = "log_stream_unavailable"
                continue
            processes[service] = process
            if process.stdout is None:
                service_status[service]["failure_reason"] = "log_stream_unavailable"
                process.kill()
                process.wait(timeout=5)
                continue
            try:
                selector.register(process.stdout, selectors.EVENT_READ, data=service)
                service_status[service]["failure_reason"] = "none"
            except (OSError, ValueError):
                service_status[service]["failure_reason"] = "log_stream_unavailable"
                process.kill()
                process.wait(timeout=5)

        while selector.get_map() and aggregate_failure == "none":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                aggregate_failure = "time_limit_exceeded"
                for key in list(selector.get_map().values()):
                    service = key.data
                    service_status[service]["failure_reason"] = "time_limit_exceeded"
                    try:
                        selector.unregister(key.fileobj)
                    except (KeyError, ValueError):
                        pass
                break
            for key, _events in selector.select(timeout=min(1.0, remaining)):
                service = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                except OSError:
                    service_status[service]["failure_reason"] = "log_read_failed"
                    try:
                        selector.unregister(key.fileobj)
                    except (KeyError, ValueError):
                        pass
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    eof_services.add(service)
                    continue
                service_bytes = service_status[service]["scanned_byte_count"]
                if service_bytes + len(chunk) > MAX_SERVICE_LOG_BYTES or aggregate_bytes + len(chunk) > MAX_LOG_BYTES:
                    service_status[service]["scanned_byte_count"] = min(
                        MAX_SERVICE_LOG_BYTES, service_bytes + len(chunk)
                    )
                    service_status[service]["failure_reason"] = "byte_limit_exceeded"
                    aggregate_failure = "byte_limit_exceeded"
                    for active_key in list(selector.get_map().values()):
                        active_service = active_key.data
                        if service_status[active_service]["failure_reason"] == "none":
                            service_status[active_service]["failure_reason"] = "byte_limit_exceeded"
                        try:
                            selector.unregister(active_key.fileobj)
                        except (KeyError, ValueError):
                            pass
                    break
                buffers[service].extend(chunk)
                service_status[service]["scanned_byte_count"] = service_bytes + len(chunk)
                aggregate_bytes += len(chunk)

        for service, process in processes.items():
            if process.poll() is None and (
                aggregate_failure in {"time_limit_exceeded", "byte_limit_exceeded"}
                or service_status[service]["failure_reason"] not in {"none", "log_stream_unavailable"}
            ):
                process.kill()
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    remaining = 0.01
                return_code = process.wait(timeout=min(5.0, remaining))
            except subprocess.TimeoutExpired:
                if service_status[service]["failure_reason"] == "none":
                    service_status[service]["failure_reason"] = "time_limit_exceeded"
                aggregate_failure = aggregate_failure if aggregate_failure != "none" else "time_limit_exceeded"
                process.kill()
                process.wait(timeout=5)
                continue
            if service_status[service]["failure_reason"] == "none":
                if return_code != 0:
                    service_status[service]["failure_reason"] = "log_read_failed"
                elif service not in eof_services:
                    service_status[service]["failure_reason"] = "log_read_failed"
                else:
                    service_status[service]["completed"] = True
        if aggregate_failure == "none":
            for service in LOG_SERVICE_NAMES:
                if service_status[service]["completed"] is not True:
                    aggregate_failure = service_status[service]["failure_reason"]
                    break
        logs = {
            service: buffers[service].decode("utf-8", "replace")
            for service in LOG_SERVICE_NAMES
            if service_status[service]["completed"] is True
        }
        return logs, service_status, aggregate_failure
    except (OSError, subprocess.TimeoutExpired):
        for service in LOG_SERVICE_NAMES:
            service_status[service]["completed"] = False
            service_status[service]["failure_reason"] = "log_read_failed"
        return {}, service_status, "log_read_failed"
    finally:
        selector.close()
        for process in processes.values():
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            if process.stdout is not None:
                process.stdout.close()


def compose_logs() -> str:
    """Compatibility wrapper for diagnostics; production scans retain service boundaries."""
    logs, _service_status, failure_reason = compose_service_logs()
    if failure_reason != "none":
        raise LogScanError(failure_reason)
    return "\n".join(logs[service] for service in LOG_SERVICE_NAMES)


def category_counts(candidates):
    counts = {category: 0 for category in LOG_VALUE_CATEGORIES}
    for category, _value in candidates:
        counts[category] += 1
    return counts


def _log_text_observations(logs: str, candidates: set[tuple[str, str]]) -> tuple[dict, dict, list[str]]:
    compact_logs = "".join(logs.split())
    matches = {
        (category, value)
        for category, value in candidates
        if candidate_log_match(category, value, logs, compact_logs)
    }
    matched_by_category = category_counts(matches)
    secret_matches = {item for item in matches if item[0] in LOG_CREDENTIAL_FAILURE_CATEGORIES}
    secret_matches_by_category = category_counts(secret_matches)
    pattern_matches = sorted({
        name for name, pattern in LOG_CREDENTIAL_PATTERN_CHECKS if re.search(pattern, logs)
    })
    return matched_by_category, secret_matches_by_category, pattern_matches


def _matching_candidate_values(logs: str, candidates: set[tuple[str, str]]) -> set[tuple[str, str]]:
    compact_logs = "".join(logs.split())
    return {
        (category, value)
        for category, value in candidates
        if candidate_log_match(category, value, logs, compact_logs)
    }


def _candidate_provenance_counts(matches: set[tuple[str, str]]) -> list[dict]:
    counts = {}
    for candidate in matches:
        category, _value = candidate
        sources = SENSITIVE_VALUE_PROVENANCE.get(candidate)
        if not sources:
            sources = {("explicit_candidate_input", "unkeyed_value")}
        for source, field in sources:
            if source not in LOG_CANDIDATE_SOURCES or field not in LOG_CANDIDATE_FIELDS:
                source, field = "unclassified_callsite", "other"
            counts[(category, source, field)] = counts.get((category, source, field), 0) + 1
    return [
        {"category": category, "source": source, "field": field, "matched_value_count": count}
        for (category, source, field), count in sorted(counts.items())
    ]


def _log_context_for_line(service: str, line: str) -> str:
    lowered = line.lower()
    if (
        service == "keycloak"
        and "org.keycloak.events" in lowered
        and "introspect_token_error" in lowered
        and re.search(
            r"(?i)(?:^|[\s,{])error=(?:user_disabled|\"user_disabled\"|'user_disabled')(?:$|[\s,}])",
            line,
        )
    ):
        return "keycloak_introspection_token_error"
    if "/protocol/openid-connect/token" in lowered:
        return "oauth_token_endpoint_request"
    if "/protocol/openid-connect/ext/par/request" in lowered or "/pushed_authorization_request" in lowered:
        return "oauth_par_endpoint_request"
    if "/protocol/openid-connect/auth" in lowered:
        return "oauth_authorization_endpoint_request"
    if service == "kong-api" and "/fapi-api/evidence?" in lowered and "access_token=" in lowered:
        return "api_query_access_token_request"
    if service == "kong-api" and "/fapi-api/evidence" in lowered:
        return "api_resource_request"
    return "other_service_log_context"


def _matched_log_context_counts(service: str, logs: str, matches: set[tuple[str, str]]) -> dict[str, int]:
    counts = {context: 0 for context in LOG_MATCH_CONTEXTS}
    if not matches:
        return counts
    lines = logs.splitlines()
    for candidate in matches:
        candidate_contexts = {
            _log_context_for_line(service, line)
            for line in lines
            if candidate_log_match(candidate[0], candidate[1], line, "".join(line.split()))
        }
        if not candidate_contexts:
            candidate_contexts.add("unclassified_log_context")
        for context in candidate_contexts:
            counts[context] += 1
    return counts


def _service_log_scan_row(
    service: str, candidates: set[tuple[str, str]], status: dict,
    logs: str | None, candidate_count: int | None = None,
) -> dict:
    categories = {category: 0 for category in LOG_VALUE_CATEGORIES}
    total_candidates = len(candidates) if candidate_count is None else candidate_count
    completed = status.get("completed") is True and isinstance(logs, str)
    if completed:
        matched, secrets, patterns = _log_text_observations(logs, candidates)
        checked = len(candidates)
        matched_values = _matching_candidate_values(logs, candidates)
        provenance = _candidate_provenance_counts(matched_values)
        contexts = _matched_log_context_counts(service, logs, matched_values)
    else:
        matched, secrets, patterns = dict(categories), dict(categories), []
        checked = 0
        provenance = []
        contexts = {context: 0 for context in LOG_MATCH_CONTEXTS}
    passed = completed and not any(secrets.values()) and not patterns
    return {
        "completed": completed,
        "passed": passed,
        "failure_reason": status.get("failure_reason", "log_read_failed"),
        "scanned_byte_count": status.get("scanned_byte_count", 0),
        "candidate_value_count": total_candidates,
        "checked_value_count": checked,
        "matched_source_category_counts": matched,
        "secret_match_category_counts": secrets,
        "credential_pattern_matches": patterns,
        "matched_candidate_provenance": provenance,
        "matched_log_context_counts": contexts,
    }


def _unscanned_service_log_rows(candidate_count: int, failure_reason: str) -> dict[str, dict]:
    # Candidate values are never materialized in the receipt. This helper is
    # only used when the scanner itself raised before it could return rows.
    rows = {}
    for service in LOG_SERVICE_NAMES:
        status = {"completed": False, "failure_reason": failure_reason, "scanned_byte_count": 0}
        rows[service] = _service_log_scan_row(service, set(), status, None, candidate_count)
    return rows


def candidate_log_match(category, value, logs, compact_logs):
    variants = {value, "".join(value.split())}
    encoded = urllib.parse.quote(value, safe="")
    if encoded != value:
        variants.add(encoded)
    if category in {"certificate", "privatekey"}:
        variants.add(json.dumps(value, ensure_ascii=True)[1:-1])
    return any(variant and (variant in logs or "".join(variant.split()) in compact_logs) for variant in variants)


def normalize_log_candidates(values):
    candidates = set()
    for item in [*values, *SENSITIVE_VALUES]:
        if isinstance(item, tuple) and len(item) == 2:
            category, value = item
            if category not in LOG_VALUE_CATEGORIES:
                category = "unknown"
            source = "explicit_candidate_input"
            field = _candidate_field_label(("value",))
        elif isinstance(item, str):
            category, value = "unknown", item
            source = "explicit_candidate_input"
            field = "unkeyed_value"
        else:
            continue
        if isinstance(value, str) and len(value) >= 8:
            candidates.add((category, value))
            if (category, value) not in SENSITIVE_VALUE_PROVENANCE:
                remember_candidate_provenance(category, value, source, field)
    for records in PENDING_PROTOCOL_IDENTIFIERS.values():
        for record in records:
            candidates.add((record["category"], record["value"]))
            remember_candidate_provenance(
                record["category"], record["value"], record["source"], record["field"],
            )
    candidates.update(
        ("public_fixed_protocol_constant", value)
        for value in PUBLIC_FIXED_PROTOCOL_CONSTANTS
        if len(value) >= 8
    )
    candidates.update(
        ("public_fixture_identifier", value)
        for value in PUBLIC_FIXTURE_IDENTIFIERS
        if len(value) >= 8
    )
    for category, value in candidates:
        if (category, value) not in SENSITIVE_VALUE_PROVENANCE:
            source = "public_protocol_inventory" if category == "public_fixed_protocol_constant" else "public_fixture_inventory" if category == "public_fixture_identifier" else "explicit_candidate_input"
            remember_candidate_provenance(category, value, source, "other")
    return candidates


def scan_logs_for_sensitive_values(values: list[tuple[str, str] | str]) -> dict:
    flush_pending_protocol_identifiers()
    candidates = normalize_log_candidates(values)
    candidates_by_category = category_counts(candidates)
    logs_by_service, statuses, collection_failure = compose_service_logs()
    service_scans = {
        service: _service_log_scan_row(
            service, candidates, statuses.get(service, {}), logs_by_service.get(service)
        )
        for service in LOG_SERVICE_NAMES
    }
    if collection_failure != "none":
        return {
            "passed": False,
            "completed": False,
            "failure_reason": collection_failure,
            "candidate_value_count": len(candidates),
            "checked_value_count": 0,
            "secret_value_match_count": 0,
            "source_category_counts": candidates_by_category,
            "matched_source_category_counts": {category: 0 for category in LOG_VALUE_CATEGORIES},
            "secret_match_category_counts": {category: 0 for category in LOG_VALUE_CATEGORIES},
            "credential_pattern_match_count": 0,
            "credential_pattern_matches": [],
            "public_fixture_identifier_observation_count": 0,
            "public_fixed_protocol_constant_observation_count": 0,
            "service_scans": service_scans,
            **api_response_scan_receipt(),
        }
    logs = "\n".join(logs_by_service[service] for service in LOG_SERVICE_NAMES)
    compact_logs = "".join(logs.split())
    matches = {
        (category, value)
        for category, value in candidates
        if candidate_log_match(category, value, logs, compact_logs)
    }
    matched_by_category = category_counts(matches)
    secret_matches = {item for item in matches if item[0] in LOG_CREDENTIAL_FAILURE_CATEGORIES}
    secret_matches_by_category = category_counts(secret_matches)
    pattern_matches = sorted({
        name for name, pattern in LOG_CREDENTIAL_PATTERN_CHECKS if re.search(pattern, logs)
    })
    return {
        "passed": not secret_matches and not pattern_matches,
        "completed": True,
        "failure_reason": "none",
        "candidate_value_count": len(candidates),
        "checked_value_count": len(candidates),
        "secret_value_match_count": len(secret_matches),
        "source_category_counts": candidates_by_category,
        "matched_source_category_counts": matched_by_category,
        "secret_match_category_counts": secret_matches_by_category,
        "credential_pattern_match_count": len(pattern_matches),
        "credential_pattern_matches": pattern_matches,
        "public_fixture_identifier_observation_count": matched_by_category["public_fixture_identifier"],
        "public_fixed_protocol_constant_observation_count": matched_by_category["public_fixed_protocol_constant"],
        "service_scans": service_scans,
        **api_response_scan_receipt(),
    }


def collect_fixture_sensitive_values() -> list[tuple[str, str]]:
    values = []
    license_value = os.environ.get("KONG_LICENSE_DATA", "")
    values.append(("license", license_value))
    remember_sensitive(
        license_value, "license", source="runtime_role_inventory", field="license_material",
    )
    for name, value in load_runtime_role_values().items():
        category = "certificate" if "CERT" in name.upper() else "privatekey" if "KEY" in name.upper() else "unknown"
        values.append((category, value))
        field = "certificate_file" if category == "certificate" else "private_key_file" if category == "privatekey" else "other"
        remember_sensitive(value, category, source="runtime_role_inventory", field=field)
    for path in sorted((PREVIEW / "pki").glob("*")):
        if path.suffix not in {".key", ".crt"}:
            continue
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise FlowError("private fixture key permissions changed")
        category = "privatekey" if path.suffix == ".key" else "certificate"
        value = path.read_text(encoding="ascii")
        values.append((category, value))
        field = "private_key_file" if category == "privatekey" else "certificate_file"
        remember_sensitive(value, category, source="fixture_pki_inventory", field=field)
    for name in ("bootstrap.env", "accounts.env"):
        file_path = PREVIEW / name
        if file_path.is_symlink() or not file_path.is_file() or stat.S_IMODE(file_path.stat().st_mode) != 0o600:
            raise FlowError("private fixture account file permissions changed")
        for line in file_path.read_text().splitlines():
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.endswith("_USERNAME") and value in PUBLIC_FIXTURE_USERNAMES:
                continue
            category = category_for_sensitive_key(name) or "unknown"
            values.append((category, value))
            remember_sensitive(
                value,
                category,
                source="fixture_account_inventory",
                field=_candidate_field_label((name,)),
            )
    return values


def verify_owned_project_containers(*, allow_stopped: bool) -> dict:
    command = ["docker", "ps"]
    if allow_stopped:
        command.append("--all")
    command.extend(["--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"])
    result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise FlowError("could not inspect the isolated WP3 runtime")
    ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(ids) != 3:
        raise FlowError("the dedicated WP3 project does not have exactly three expected services")
    inspected = subprocess.run(["docker", "inspect", *ids], cwd=ROOT, check=False, capture_output=True, text=True, timeout=30)
    if inspected.returncode != 0:
        raise FlowError("could not inspect isolated WP3 service identities")
    try:
        containers = json.loads(inspected.stdout)
    except json.JSONDecodeError:
        raise FlowError("isolated WP3 service metadata is malformed") from None
    observed = {}
    for container in containers:
        labels = container.get("Config", {}).get("Labels", {})
        service = labels.get("com.docker.compose.service")
        if labels.get("com.docker.compose.project") != PROJECT or service not in IMAGES:
            raise FlowError("an unexpected container was found in the WP3 project")
        if container.get("Config", {}).get("Image") != IMAGES[service][0]:
            raise FlowError("an isolated WP3 service image changed from its pinned reference")
        if not allow_stopped and container.get("State", {}).get("Running") is not True:
            raise FlowError("an isolated WP3 service is not running")
        if service in observed:
            raise FlowError("an isolated WP3 service is duplicated")
        observed[service] = container.get("Id")
    if set(observed) != set(IMAGES):
        raise FlowError("the isolated WP3 service set is incomplete")
    return observed


def verify_running_project() -> dict:
    return verify_owned_project_containers(allow_stopped=False)


def capture_request_count(container_id: str) -> int:
    code = "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9444/count', timeout=3).read(64).decode('ascii'))"
    result = subprocess.run(
        ["docker", "exec", container_id, "python", "-c", code],
        cwd=ROOT, check=False, capture_output=True, timeout=6,
    )
    if result.returncode != 0 or len(result.stdout) > 128:
        raise FlowError("capture counter could not be read through its container-loopback observer")
    try:
        body = json.loads(result.stdout.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise FlowError("capture counter response was malformed") from None
    if not isinstance(body, dict) or set(body) != {"request_count"} or type(body["request_count"]) is not int or not 0 <= body["request_count"] <= 10000:
        raise FlowError("capture counter response did not match its strict one-field schema")
    return body["request_count"]


def write_runtime_receipt(payload: dict) -> None:
    evidence = PREVIEW / "evidence"
    if evidence.is_symlink() or not evidence.is_dir() or stat.S_IMODE(evidence.stat().st_mode) != 0o700:
        raise RuntimeReceiptFailure("evidence_directory_unsafe", "private WP3 evidence directory is missing or unsafe")
    try:
        validate_runtime_receipt(payload)
    except PreviewError:
        raise RuntimeReceiptFailure("schema_rejected", "WP3 runtime receipt failed its strict private schema") from None
    path = evidence / "wp3-runtime-receipt.json"
    try:
        with path.open("x", encoding="utf-8") as output:
            json.dump(payload, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
        os.chmod(path, 0o600)
    except FileExistsError:
        raise RuntimeReceiptFailure("destination_exists", "WP3 runtime receipt already exists") from None
    except (OSError, TypeError, ValueError, UnicodeError):
        raise RuntimeReceiptFailure("write_failed", "WP3 runtime receipt could not be written safely") from None


def safe_execution_phase(execution: dict) -> str:
    phase = execution.get("phase") if isinstance(execution, dict) else None
    return phase if isinstance(phase, str) and phase in WP3_EXECUTION_PHASES else "preflight"


def initial_cases() -> list[dict]:
    rows = []
    for case_id in ("RS-VALID-01", "RS-INT-AUD-02"):
        for route in ("A", "B"):
            rows.append({
                "case_id": case_id,
                "route": route,
                "outcome": "not_run",
                "phase": "not_started",
                "layer": "not_run",
                "http_status": None,
                "rfc6750_challenge": "not_run",
            })
    variants = {
        "SCHEMA-PRIORITY-01": ("exact_3_16_metadata",),
        "RS-QUERY-01": (
            "query_only_token", "query_encoded_name", "query_duplicate_name",
            "query_mixed_case_name", "query_dash_alias", "query_late_name",
            "query_arg_limit_1000", "query_arg_truncated_1001", "harmless_query_control",
        ),
        "RS-BODY-01": ("body_only_token",),
        "RS-COOKIE-01": ("cookie_only_token",),
        "RS-AUD-01": ("genuine_api_audience_absent", "restored_positive_control"),
        "RS-SCOPE-01": ("genuine_openid_scope_absent",),
        "RS-ACTIVE-01": ("enabled_control", "disabled_same_token", "restored_control"),
        "POP-01": ("no_client_certificate",),
        "POP-02": ("other_route_certificate",),
        "POP-03": ("outside_ca_certificate",),
        "ERR-01": ("invalid_bearer",),
        "HEADER-CERT-01": ("spoof_alias_duplicates", "headers_101", "headers_999", "headers_1000", "headers_1001"),
        "TLS-RS-01": ("tls_11", "tls_12_only", "weak_cipher", "server_san_mismatch", "untrusted_server_ca"),
        "LEAK-01": ("whole_runtime_lifecycle",),
    }
    for case_id, case_variants in variants.items():
        for variant in case_variants:
            row = {
                "case_id": case_id,
                "outcome": "not_run",
                "phase": "separate_runtime_phase",
                "layer": "not_run",
                "http_status": None,
                "rfc6750_challenge": "not_run",
                "variant": variant,
            }
            if case_id == "TLS-RS-01":
                row.update({
                    "client_hello_offered": "not_run",
                    "offered_protocols": "not_run",
                    "tls_policy_proven": "not_run",
                    "negotiated_protocol": "not_run",
                    "negotiated_cipher": "not_run",
                    "upstream_unchanged": "not_run",
                    "tls_failure_reason": "not_run",
                    "tls_verify_code": None,
                    "post_negative_valid_control": "not_run",
                })
            if case_id == "RS-QUERY-01":
                row["request_target_byte_count"] = "not_run"
                row["query_argument_count"] = "not_run"
            if case_id == "HEADER-CERT-01":
                row.update({
                    "input_wire_header_count": None,
                    "upstream_header_count": None,
                    "parser_source": "not_run",
                    "wire_grammar_valid": "not_run",
                    "upstream_unchanged": "not_run",
                    "response_scan_clean": "not_run",
                    "post_negative_valid_control": "not_run",
                    "parser_log_scan_completed": "not_run",
                    "parser_error_marker_delta": None,
                    "parser_api_request_marker_delta": None,
                })
            rows.append(row)
    return rows


def mark_route_case(rows, case_id, route, outcome, phase, layer, status=None, challenge=None):
    if phase not in WP3_CASE_PHASES:
        raise FlowError("route acceptance recorder rejected an unknown fixed phase")
    for row in rows:
        if row.get("case_id") == case_id and row.get("route") == route:
            row.update({
                "outcome": outcome,
                "phase": phase,
                "layer": layer,
                "http_status": status,
                "rfc6750_challenge": challenge if challenge is not None else "not_applicable",
            })


def mark_route_pipeline_started(rows, route_label):
    mark_route_case(rows, "RS-VALID-01", route_label, "running", "authorization", "keycloak")


def mark_route_introspection_started(rows, route_label):
    mark_route_case(
        rows,
        "RS-INT-AUD-02",
        route_label,
        "running",
        "dedicated_mtls_introspection",
        "keycloak",
    )


def mark_variant_case(rows, case_id, variant, outcome, phase, layer, status=None, challenge="not_applicable", *, request_target_byte_count=None, query_argument_count=None, client_hello_offered=None, offered_protocols=None, tls_policy_proven=None, negotiated_protocol=None, negotiated_cipher=None, upstream_unchanged=None, tls_failure_reason=None, tls_verify_code=None, post_negative_valid_control=None, input_wire_header_count=None, upstream_header_count=None, parser_source=None, wire_grammar_valid=None, response_scan_clean=None, parser_log_scan_completed=None, parser_error_marker_delta=None, parser_api_request_marker_delta=None):
    allowed_outcomes = {"not_run", "running", "pass", "fail", "needs_design"}
    allowed_layers = {
        "not_run", "harness", "keycloak", "token_validation", "api_gateway",
        "api_gateway_tls", "server_certificate_validation", "tls_handshake",
        "upstream_capture", "gateway+upstream_capture", "active_check",
        "client_tls_configuration", "transport",
        "nginx_parser",
    }
    if outcome not in allowed_outcomes or layer not in allowed_layers or phase not in WP3_CASE_PHASES:
        raise FlowError("acceptance recorder rejected an unknown safe outcome, layer, or fixed phase")
    for row in rows:
        if row.get("case_id") == case_id and row.get("variant") == variant:
            row.update({
                "outcome": outcome, "phase": phase, "layer": layer,
                "http_status": status, "rfc6750_challenge": challenge,
            })
            if case_id == "RS-QUERY-01" and request_target_byte_count is not None:
                row["request_target_byte_count"] = request_target_byte_count
            if case_id == "RS-QUERY-01" and query_argument_count is not None:
                row["query_argument_count"] = query_argument_count
            if case_id == "TLS-RS-01":
                if client_hello_offered is not None:
                    row["client_hello_offered"] = client_hello_offered
                if offered_protocols is not None:
                    row["offered_protocols"] = offered_protocols
                if tls_policy_proven is not None:
                    row["tls_policy_proven"] = tls_policy_proven
                if negotiated_protocol is not None:
                    row["negotiated_protocol"] = negotiated_protocol
                if negotiated_cipher is not None:
                    row["negotiated_cipher"] = negotiated_cipher
                if upstream_unchanged is not None:
                    row["upstream_unchanged"] = upstream_unchanged
                if tls_failure_reason is not None:
                    row["tls_failure_reason"] = tls_failure_reason
                if tls_verify_code is not None:
                    row["tls_verify_code"] = tls_verify_code
                if post_negative_valid_control is not None:
                    row["post_negative_valid_control"] = post_negative_valid_control
            if case_id == "HEADER-CERT-01":
                if input_wire_header_count is not None:
                    row["input_wire_header_count"] = input_wire_header_count
                if upstream_header_count is not None:
                    row["upstream_header_count"] = upstream_header_count
                if parser_source is not None:
                    row["parser_source"] = parser_source
                if wire_grammar_valid is not None:
                    row["wire_grammar_valid"] = wire_grammar_valid
                if upstream_unchanged is not None:
                    row["upstream_unchanged"] = upstream_unchanged
                if response_scan_clean is not None:
                    row["response_scan_clean"] = response_scan_clean
                if post_negative_valid_control is not None:
                    row["post_negative_valid_control"] = post_negative_valid_control
                if parser_log_scan_completed is not None:
                    row["parser_log_scan_completed"] = parser_log_scan_completed
                if parser_error_marker_delta is not None:
                    row["parser_error_marker_delta"] = parser_error_marker_delta
                if parser_api_request_marker_delta is not None:
                    row["parser_api_request_marker_delta"] = parser_api_request_marker_delta
            return
    raise FlowError("acceptance recorder could not find its declared case variant")


def safe_nonnegative_count(value, maximum=4096):
    if type(value) is int and 0 <= value <= maximum:
        return value
    return None


def record_capture_observation(capture, evidence):
    if not isinstance(evidence, dict):
        return
    capture["request_count"] = safe_nonnegative_count(evidence.get("request_count"), 10000)
    for target, source in (
        ("api_peer_pin_matches", "api_peer_pin_matches"),
        ("api_peer_common_name_matches", "api_peer_common_name_matches"),
        ("authorization_single_bearer", "authorization_single_bearer"),
        ("cookie_absent", "cookie_absent"),
        ("client_assertion_headers_absent", "client_assertion_headers_absent"),
        ("x_fapi_headers_absent", "x_fapi_headers_absent"),
        ("x_demo_unexpected_headers_absent", "x_demo_unexpected_headers_absent"),
        ("department_header_matches_expected_claim", "department_header_matches_expected_claim"),
        ("route_header_matches_expected_claim", "route_header_matches_expected_claim"),
        ("forwarded_certificate_single_url_encoded_pem_leaf", "forwarded_certificate_single_url_encoded_pem_leaf"),
    ):
        capture[target] = evidence.get(source) is True
    capture["authorization_sha256_present"] = isinstance(evidence.get("authorization_sha256"), str)
    capture["forwarded_certificate_thumbprint_present"] = isinstance(evidence.get("forwarded_certificate_thumbprint"), str)
    capture["x_client_cert_like_header_count"] = safe_nonnegative_count(evidence.get("x_client_cert_like_header_count"))
    capture["x_client_cert_header_count"] = safe_nonnegative_count(evidence.get("x_client_cert_header_count"))
    capture["x_client_cert_unknown_suffix_header_count"] = safe_nonnegative_count(evidence.get("x_client_cert_unknown_suffix_header_count"))
    capture["x_client_cert_duplicate_header_count"] = safe_nonnegative_count(evidence.get("x_client_cert_duplicate_header_count"))
    capture["x_client_cert_underscore_alias_count"] = safe_nonnegative_count(evidence.get("x_client_cert_underscore_alias_count"))
    capture["x_client_cert_stock_details_complete"] = evidence.get("x_client_cert_stock_details_complete") is True
    capture["x_client_cert_fingerprint_matches_forwarded_leaf"] = evidence.get("x_client_cert_fingerprint_matches_forwarded_leaf") is True
    capture["caller_spoof_sentinel_match_count"] = safe_nonnegative_count(evidence.get("caller_spoof_sentinel_match_count"))
    details = evidence.get("x_client_cert_stock_detail_counts")
    if isinstance(details, dict) and set(details) == {"serial", "issuer_dn", "subject_dn", "fingerprint", "chain"}:
        capture["x_client_cert_stock_detail_counts"] = {
            name: safe_nonnegative_count(details[name])
            for name in ("serial", "issuer_dn", "subject_dn", "fingerprint", "chain")
        }
    capture["client_assertion_unknown_suffix_header_count"] = evidence.get("client_assertion_unknown_suffix_header_count")


def exchange_and_validate_token(wp2, grant, issuer, metadata, jwks, pki, signing_key, phase_callback):
    phase_callback("token_exchange")
    token_response = wp2.exchange_code(grant, issuer, metadata, pki, signing_key)
    response_collection = remember_sensitive(token_response, source="oauth_token_response")
    phase_callback("token_signature_and_claim_validation")
    token, claims, header = wp2.verify_access_token(token_response, grant, issuer, jwks)
    resolve_verified_token_response_identifiers(response_collection, claims, grant, token)
    remember_sensitive(token, "oauth_token", source="oauth_verified_access_token", field="access_token")
    return token, claims, header


def run_positive_flows(cases: list[dict], capture: dict, tls: dict, sensitive_values: list[tuple[str, str]], execution: dict) -> dict:
    execution["phase"] = "crypto_dependency_preflight"
    host_crypto = host_crypto_diagnostics()
    execution["host_runtime"] = host_crypto
    if (
        host_crypto["pyjwt_importable"] is not True
        or host_crypto["cryptography_importable"] is not True
        or host_crypto["pyjwt_version"] != "2.14.0"
    ):
        raise FlowError("host PS256 verification dependencies are absent or differ from the pinned PyJWT version")
    execution["phase"] = "license_presence_check"
    if not os.environ.get("KONG_LICENSE_DATA"):
        raise FlowError("Kong license is absent from the current process environment")
    execution["phase"] = "preparation_receipt_verification"
    preview_receipt = verify_preparation_receipt()
    execution["phase"] = "rendered_state_contract_validation"
    execution["state_contract"] = validate_runtime_state_contract()
    execution["phase"] = "running_project_inventory"
    containers = verify_running_project()
    execution["phase"] = "fixture_transport_setup"
    wp2 = load_wp2_flow()
    install_fixture_transport(wp2)
    pki = PREVIEW / "pki"
    execution["phase"] = "fixture_sensitive_candidate_load"
    register_public_route_certificate_thumbprints(wp2, pki)
    sensitive_values.extend(collect_fixture_sensitive_values())
    execution["phase"] = "bounded_runtime_readiness"
    readiness = wait_for_runtime_ready(wp2, pki, containers)
    capture["fixture_underscores_in_headers_on"] = readiness["fixture_underscores_in_headers_on"]
    execution["header_parser_metadata"] = readiness["header_parser_metadata"]
    execution["phase"] = "exact_gateway_schema_and_priority_probe"
    execution["schema_probe_diagnostic"] = {"stage": "not_started", "reason": "not_started", "plugin": "none"}
    execution["schema_probe"] = probe_loaded_schema_priorities(
        containers["kong-api"], execution["schema_probe_diagnostic"]
    )
    execution["effective_inbound_tls_policy"] = derive_effective_inbound_tls_policy(
        readiness["nginx_config_dump"],
        dump_succeeded=True,
        openresty_version=readiness["nginx_version"],
        image_metadata=preview_receipt["images"].get("kong-api"),
        admin_tls_metadata=execution["schema_probe"]["tls_policy"],
    )
    tls_policy_proven = execution["effective_inbound_tls_policy"]["effective_inbound_tls_proven"] is True
    mark_variant_case(cases, "SCHEMA-PRIORITY-01", "exact_3_16_metadata", "pass", "exact_runtime_admin_metadata", "harness")
    execution["phase"] = "tls_client_certificate_request_sni_probe"
    tls["localhost_sni_requested_client_certificate"] = observe_tls_client_certificate_request(
        pki, "localhost", pki / "route-a.crt", pki / "route-a.key"
    )
    tls["kong_api_sni_requested_client_certificate"] = observe_tls_client_certificate_request(
        pki, "kong-api", pki / "route-b.crt", pki / "route-b.key"
    )
    if not tls["localhost_sni_requested_client_certificate"] or not tls["kong_api_sni_requested_client_certificate"]:
        raise FlowError("TLS handshake did not request a client certificate for both configured SNI names")
    execution["phase"] = "public_issuer_metadata_and_jwks"
    issuer, metadata, jwks = load_fixture_metadata(wp2, pki)
    if issuer != PUBLIC_ISSUER:
        raise FlowError("public Keycloak issuer mapping changed")
    bootstrap = PREVIEW / "bootstrap.env"
    accounts = wp2.read_env(PREVIEW / "accounts.env")
    engineering_accounts = dict(accounts)
    engineering_accounts["WP2_SALES_USERNAME"] = accounts["WP2_ENGINEERING_USERNAME"]
    engineering_accounts["WP2_SALES_PASSWORD"] = accounts["WP2_ENGINEERING_PASSWORD"]
    for name, value in engineering_accounts.items():
        if not (name.endswith("_USERNAME") and value in PUBLIC_FIXTURE_USERNAMES):
            remember_sensitive(
                value,
                category_for_sensitive_key(name) or "unknown",
                source="fixture_account_inventory",
                field=_candidate_field_label((name,)),
            )

    execution["phase"] = "ephemeral_keycloak_user_profile_sync"
    admin = wp2.admin_bearer(FIXTURE_ORIGIN, pki, bootstrap)
    remember_sensitive(admin, "oauth_token", source="oauth_admin_bearer", field="admin_bearer")
    wp2.sync_user_profile(FIXTURE_ORIGIN, pki, admin)
    wp2.sync_fixture_user_attributes(FIXTURE_ORIGIN, pki, admin)
    CallbackServer = bounded_callback_server(wp2)
    route_contexts = {}

    with CallbackServer(pki) as callback_server:
        for route_key, sni, route_label in (("a", "localhost", "A"), ("b", "kong-api", "B")):
            record_route_execution_phase(execution, route_label, "authorization")
            mark_route_pipeline_started(cases, route_label)
            phase = "authorization"
            try:
                grant = authorize_code_with_scopes(
                    wp2, route_key, {"openid", "profile"}, metadata, issuer,
                    pki, callback_server, pki / "route-b-pkj.key", engineering_accounts,
                )
                remember_sensitive(grant, source="oauth_route_grant")
                for cookie in callback_server.cookie_jar:
                    remember_sensitive(
                        cookie.value, "cookie", source="oauth_browser_cookie_jar", field="cookie_value",
                    )

                def record_token_phase(next_phase):
                    nonlocal phase
                    if next_phase not in {"token_exchange", "token_signature_and_claim_validation"}:
                        raise FlowError("token phase recorder rejected an unknown fixed phase")
                    phase = next_phase
                    record_route_execution_phase(execution, route_label, phase)

                token, claims, _header = exchange_and_validate_token(
                    wp2, grant, issuer, metadata, jwks, pki, pki / "route-b-pkj.key", record_token_phase
                )

                phase = "dedicated_mtls_introspection"
                record_route_execution_phase(execution, route_label, phase)
                mark_route_introspection_started(cases, route_label)
                introspection = wp2.introspect(token, metadata, pki)
                introspection_collection = remember_sensitive(
                    introspection, source="oauth_introspection_response", token_binding=token,
                )
                wp2.verify_introspection(introspection, claims)
                resolve_verified_introspection_identifiers(
                    introspection_collection, claims, grant, token,
                    active=introspection.get("active") is True,
                )
                mark_route_case(cases, "RS-INT-AUD-02", route_label, "pass", "dedicated_mtls_introspection", "keycloak", 200, "not_applicable")

                phase = "api_tls_and_authorization"
                record_route_execution_phase(execution, route_label, phase)
                route_certificate = grant["certificate"]
                route_private_key = grant["private_key"]
                spoof_headers = {
                    "Authorization": f"Bearer {token}",
                    "Cookie": "WP3-COOKIE-SENTINEL",
                    "X-Demo-Department": "spoofed-department",
                    "X-Demo-Route": "spoofed-route",
                    "x_demo_Arbitrary": "spoofed-unknown-demo",
                    "X-Fapi-Route": "spoofed-route",
                    "x_fapi_Arbitrary": "spoofed-unknown-fapi",
                    "client_assertion": "WP3-ASSERTION-SENTINEL",
                    "Client_Assertion_Type": "WP3-ASSERTION-TYPE-SENTINEL",
                    "cLiEnT_AsSeRtIoN_UnknownSuffix": "WP3-ASSERTION-SUFFIX-SENTINEL",
                }
                spoof_headers.update(CLIENT_CERT_SPOOF_HEADERS)
                for name, value in spoof_headers.items():
                    if name.lower() == "authorization":
                        remember_sensitive(token, "oauth_token", source="api_caller_spoof_header", field="access_token")
                    elif name.lower() == "cookie":
                        remember_sensitive(value, "cookie", source="api_caller_spoof_header", field="cookie_value")
                    else:
                        remember_sensitive(value, "spoof_sentinel", source="api_caller_spoof_header", field="spoof_header")
                status, response_headers, evidence = request_api(
                    pki, sni, route_certificate, route_private_key, headers=spoof_headers,
                    sensitive_header_source="api_caller_spoof_header",
                )
                record_capture_observation(capture, evidence)
                if status != 200:
                    mark_route_case(cases, "RS-VALID-01", route_label, "fail", phase, "api_gateway", status, challenge_for_status(status, response_headers))
                    raise FlowError("valid Keycloak-issued token was rejected by the isolated API Gateway")

                phase = "upstream_mtls_and_header_evidence"
                record_route_execution_phase(execution, route_label, phase)
                verify_capture(wp2, evidence, token, claims, route_certificate)
                mark_route_case(cases, "RS-VALID-01", route_label, "pass", phase, "gateway+upstream_capture", 200, "not_applicable")
                tls["localhost_sni_positive" if sni == "localhost" else "kong_api_sni_positive"] = True
                route_contexts[route_label] = {
                    "grant": grant,
                    "token": token,
                    "claims": claims,
                    "introspection": introspection,
                    "sni": sni,
                }
            except Exception as error:
                observed_status = getattr(error, "status", None)
                if type(observed_status) is not int:
                    observed_status = 200 if phase == "upstream_mtls_and_header_evidence" else None
                if phase in {"authorization", "token_exchange", "dedicated_mtls_introspection"}:
                    safe_layer = "keycloak" if observed_status is not None else "keycloak_tls_or_harness"
                elif phase == "token_signature_and_claim_validation":
                    safe_layer = "token_validation"
                elif phase == "upstream_mtls_and_header_evidence":
                    safe_layer = "upstream_capture"
                else:
                    safe_layer = "api_gateway_tls_or_harness"
                for acceptance_id in ("RS-VALID-01", "RS-INT-AUD-02"):
                    row = next((item for item in cases if item.get("case_id") == acceptance_id and item.get("route") == route_label), None)
                    if row is not None and row["outcome"] == "running":
                        mark_route_case(cases, acceptance_id, route_label, "fail", phase, safe_layer, observed_status)
                raise FlowError(f"positive Route {route_label} flow stopped during {phase}") from None

    execution["phase"] = "positive_a_b_complete"
    return {
        "images": preview_receipt["images"],
        "wp2": wp2,
        "issuer": issuer,
        "metadata": metadata,
        "jwks": jwks,
        "pki": pki,
        "admin": admin,
        "accounts": engineering_accounts,
        "callback_server_class": CallbackServer,
        "routes": route_contexts,
        "containers": containers,
        "capture": capture,
        "tls_policy_proven": tls_policy_proven,
        "header_parser_metadata": readiness["header_parser_metadata"],
    }


def verified_resource_claims(wp2, token, jwks, issuer, grant, *, required_scopes, required_audience=(), forbidden_scopes=(), forbidden_audience=()):
    header, claims = wp2.verify_ps256(token, jwks, issuer=issuer)
    if header.get("alg") != "PS256":
        raise FlowError("Keycloak token signature algorithm was not PS256")
    now = time.time()
    if not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + 30:
        raise FlowError("Keycloak token issue time was invalid")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
        raise FlowError("Keycloak token was expired")
    if claims.get("iss") != issuer or claims.get("azp") != grant["client"]["client_id"]:
        raise FlowError("Keycloak token issuer or authorized party was invalid")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise FlowError("Keycloak token subject was absent")
    audience = wp2.audiences(claims)
    if not set(required_audience).issubset(audience):
        raise FlowError("Keycloak token omitted an audience required by the fixture")
    if not set(forbidden_audience).isdisjoint(audience):
        raise FlowError("Keycloak token retained an audience forbidden by this fixture")
    scopes = set(claims.get("scope", "").split())
    if not set(required_scopes).issubset(scopes) or not set(forbidden_scopes).isdisjoint(scopes):
        raise FlowError("Keycloak token scope set did not match its genuine OAuth grant")
    cnf = claims.get("cnf", {}).get("x5t#S256") if isinstance(claims.get("cnf"), dict) else None
    expected_cnf = wp2.certificate_thumbprint(grant["certificate"])
    if not isinstance(cnf, str) or not hmac.compare_digest(cnf, expected_cnf):
        raise FlowError("Keycloak token certificate binding did not match its Route certificate")
    for claim in ("department", "route"):
        key = f"{wp2.NAMESPACE}/{claim}"
        if not isinstance(claims.get(key), str) or not claims[key]:
            raise FlowError("Keycloak token omitted its namespaced fixture claims")
    return header, claims


def _client_and_mapper(wp2, admin, client_id):
    clients = wp2.request_json(FIXTURE_ORIGIN, "/admin/realms/fapi-demo/clients?clientId=" + urllib.parse.quote(client_id, safe=""), PREVIEW / "pki/ca.crt", bearer=admin)
    if not isinstance(clients, list):
        raise FlowError("Keycloak route-client lookup was malformed")
    matching = [item for item in clients if isinstance(item, dict) and item.get("clientId") == client_id and isinstance(item.get("id"), str)]
    if len(matching) != 1:
        raise FlowError("Keycloak route-client lookup was not unique")
    client_uuid = matching[0]["id"]
    mappers = wp2.request_json(FIXTURE_ORIGIN, f"/admin/realms/fapi-demo/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models", PREVIEW / "pki/ca.crt", bearer=admin)
    if not isinstance(mappers, list):
        raise FlowError("Keycloak protocol-mapper lookup was malformed")
    matches = [item for item in mappers if isinstance(item, dict) and item.get("name") == "pop-verifier-audience"]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), str) or not isinstance(matches[0].get("config"), dict):
        raise FlowError("Keycloak API audience mapper was not unique")
    mapper = matches[0]
    config = mapper["config"]
    if config.get("included.custom.audience") != "fapi-demo-api" or config.get("introspection.token.claim") != "true" or config.get("access.token.claim") != "true":
        raise FlowError("Keycloak API audience mapper did not match its fresh fixture contract")
    introspection_matches = [item for item in mappers if isinstance(item, dict) and item.get("name") == "api-gateway-introspection-audience"]
    if len(introspection_matches) != 1 or not isinstance(introspection_matches[0].get("config"), dict):
        raise FlowError("Keycloak introspection audience mapper was not unique")
    introspection_mapper = introspection_matches[0]
    introspection_config = introspection_mapper["config"]
    if (
        introspection_config.get("included.custom.audience") != "api-gateway-introspection"
        or introspection_config.get("access.token.claim") != "true"
        or introspection_config.get("introspection.token.claim") != "true"
    ):
        raise FlowError("Keycloak dedicated introspection audience mapper did not match its fixture contract")
    mapper["_client_uuid"] = client_uuid
    mapper["_introspection_mapper_snapshot"] = json.loads(json.dumps(introspection_mapper))
    return client_uuid, mapper


def set_api_audience_mapper(wp2, admin, client_id, mapper, enabled):
    client_uuid = mapper["_client_uuid"]
    updated = json.loads(json.dumps({key: value for key, value in mapper.items() if key not in {"_client_uuid", "_introspection_mapper_snapshot"}}))
    updated["config"]["access.token.claim"] = "true" if enabled else "false"
    updated["config"]["introspection.token.claim"] = "true" if enabled else "false"
    path = f"/admin/realms/fapi-demo/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models/{urllib.parse.quote(updated['id'], safe='')}"
    wp2.request_json(FIXTURE_ORIGIN, path, PREVIEW / "pki/ca.crt", bearer=admin, method="PUT", json_body=updated)
    verified = wp2.request_json(FIXTURE_ORIGIN, f"/admin/realms/fapi-demo/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models", PREVIEW / "pki/ca.crt", bearer=admin)
    matches = [item for item in verified if isinstance(item, dict) and item.get("name") == "pop-verifier-audience"] if isinstance(verified, list) else []
    expected_value = "true" if enabled else "false"
    if len(matches) != 1 or any(matches[0].get("config", {}).get(name) != expected_value for name in ("access.token.claim", "introspection.token.claim")):
        raise FlowError("Keycloak API audience mapper change did not verify")
    _verify_introspection_audience_mapper_unchanged(wp2, admin, mapper)


def _verify_introspection_audience_mapper_unchanged(wp2, admin, mapper):
    snapshot = mapper.get("_introspection_mapper_snapshot")
    if not isinstance(snapshot, dict):
        raise FlowError("Keycloak dedicated introspection audience mapper snapshot is missing")
    client_uuid = mapper["_client_uuid"]
    collection = f"/admin/realms/fapi-demo/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models"
    observed = wp2.request_json(FIXTURE_ORIGIN, collection, PREVIEW / "pki/ca.crt", bearer=admin)
    matches = [item for item in observed if isinstance(item, dict) and item.get("name") == "api-gateway-introspection-audience"] if isinstance(observed, list) else []
    if len(matches) != 1 or matches[0] != snapshot:
        raise FlowError("Keycloak dedicated introspection audience mapper changed during the API-audience fixture toggle")


def restore_api_audience_mapper(wp2, admin, mapper):
    """Write back and read-verify the full original mapper representation."""
    client_uuid = mapper["_client_uuid"]
    original = {key: value for key, value in mapper.items() if key not in {"_client_uuid", "_introspection_mapper_snapshot"}}
    original = json.loads(json.dumps(original))
    path = f"/admin/realms/fapi-demo/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models/{urllib.parse.quote(original['id'], safe='')}"
    collection = f"/admin/realms/fapi-demo/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models"
    wp2.request_json(FIXTURE_ORIGIN, path, PREVIEW / "pki/ca.crt", bearer=admin, method="PUT", json_body=original)
    observed = wp2.request_json(FIXTURE_ORIGIN, collection, PREVIEW / "pki/ca.crt", bearer=admin)
    matches = [item for item in observed if isinstance(item, dict) and item.get("id") == original["id"]] if isinstance(observed, list) else []
    if len(matches) != 1 or matches[0] != original:
        raise FlowError("Keycloak API audience mapper did not restore its complete original representation")
    _verify_introspection_audience_mapper_unchanged(wp2, admin, mapper)


def api_user_representation(wp2, admin, username):
    path = "/admin/realms/fapi-demo/users?username=" + urllib.parse.quote(username, safe="")
    rows = wp2.request_json(FIXTURE_ORIGIN, path, PREVIEW / "pki/ca.crt", bearer=admin)
    matches = [row for row in rows if isinstance(row, dict) and row.get("username") == username and isinstance(row.get("id"), str)] if isinstance(rows, list) else []
    if len(matches) != 1:
        raise FlowError("Keycloak fixture user lookup was not unique")
    return matches[0]


def set_fixture_user_enabled(wp2, admin, user, enabled):
    updated = dict(user)
    updated["enabled"] = bool(enabled)
    path = "/admin/realms/fapi-demo/users/" + urllib.parse.quote(user["id"], safe="")
    wp2.request_json(FIXTURE_ORIGIN, path, PREVIEW / "pki/ca.crt", bearer=admin, method="PUT", json_body=updated)
    verified = wp2.request_json(FIXTURE_ORIGIN, path, PREVIEW / "pki/ca.crt", bearer=admin)
    if not isinstance(verified, dict) or verified.get("id") != user["id"] or verified.get("enabled") is not bool(enabled):
        raise FlowError("Keycloak fixture user state did not verify")


def authorize_code_with_scopes(wp2, route_key, scopes, metadata, issuer, pki, callback_server, signing_key, accounts):
    client = wp2.CLIENTS[route_key]
    verifier = wp2.b64url(os.urandom(32))
    challenge = wp2.b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = wp2.b64url(os.urandom(32))
    nonce = wp2.b64url(os.urandom(32))
    remember_sensitive(state, "unknown", source="oauth_authorization_state", field="state")
    remember_sensitive(nonce, "unknown", source="oauth_authorization_state", field="nonce")
    remember_sensitive(verifier, "verifier", source="oauth_authorization_state", field="pkce_verifier")
    remember_sensitive(challenge, "verifier", source="oauth_authorization_state", field="pkce_challenge")
    certificate = pki / client["certificate"]
    private_key = pki / client["key"]
    form = {
        **wp2.client_auth_form(client, issuer, signing_key),
        "response_type": "code",
        "redirect_uri": client["redirect_uri"],
        "scope": " ".join(sorted(scopes)),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    request = wp2.request_json(
        issuer, metadata["pushed_authorization_request_endpoint"], pki / "ca.crt",
        certificate, private_key, form=form,
    )
    request_uri = request.get("request_uri")
    if not isinstance(request_uri, str) or not request_uri.startswith("urn:ietf:params:oauth:request_uri:"):
        raise FlowError("Keycloak scope-only PAR response omitted its opaque request URI")
    remember_sensitive(request_uri, "unknown", source="oauth_par_response", field="par_request_uri")
    authorization_url = metadata["authorization_endpoint"] + "?" + urllib.parse.urlencode({"client_id": client["client_id"], "request_uri": request_uri})
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=wp2.ssl_context(pki / "ca.crt")),
        urllib.request.HTTPCookieProcessor(callback_server.cookie_jar),
        wp2.LocalAuthRedirectHandler(),
    )
    wp2.complete_authorization_page(opener, authorization_url, accounts)
    for cookie in callback_server.cookie_jar:
        remember_sensitive(
            cookie.value, "cookie", source="oauth_browser_cookie_jar", field="cookie_value",
        )
    callback = callback_server.receive(state, urllib.parse.urlsplit(client["redirect_uri"]).path)
    grant = {
        "route_key": route_key, "client": client, "code": callback["code"],
        "verifier": verifier, "nonce": nonce, "requested_scopes": set(scopes),
        "issued_at": callback["received_at"], "certificate": certificate, "private_key": private_key,
    }
    remember_sensitive(grant, source="oauth_route_grant")
    return grant


def check_api_expectation(case_rows, case_id, variant, context, capture_container, *, token, claims, cert_path, key_path, expected_status, expected_error, headers=None, path=API_PATH, body=None, method="GET", count_unchanged=True, sni="localhost", allow_absent_challenge_needs_design=False):
    before = capture_request_count(capture_container)
    status, response_headers, _body = request_api(
        context["pki"], sni, cert_path, key_path, path=path, headers=headers, body=body, method=method,
    )
    challenge = challenge_for_status(status, response_headers)
    if status == 200 and not count_unchanged:
        verify_capture(context["wp2"], _body, token, claims, cert_path)
        record_capture_observation(context["capture"], _body)
    after = capture_request_count(capture_container)
    if (
        allow_absent_challenge_needs_design
        and status == expected_status
        and challenge == "error_absent"
        and after == before
    ):
        mark_variant_case(case_rows, case_id, variant, "needs_design", "api_http_authorization", "api_gateway", status, challenge)
        return status, after
    accepted = status == expected_status and challenge == (expected_error or "not_applicable")
    accepted = accepted and ((after == before) if count_unchanged else (after == before + 1))
    outcome = "pass" if accepted else "fail"
    mark_variant_case(case_rows, case_id, variant, outcome, "api_http_authorization", "api_gateway", status, challenge)
    if not accepted:
        raise FlowError("isolated API request did not match its status, RFC 6750, and capture-count contract")
    return status, after


def _verify_direct_introspection(wp2, document, claims, *, active, require_api_audience=True, require_openid=True):
    if not isinstance(document, dict) or document.get("active") is not active:
        return False
    # An inactive introspection result is commonly just `{"active": false}`.
    # The exact same, freshly verified JWT and the enabled control around this
    # transition establish identity, claims, expiry, and certificate binding.
    if active is False:
        return True
    audiences = wp2.audiences(document)
    expected_audiences = {"api-gateway-introspection"}
    if require_api_audience:
        expected_audiences.add("fapi-demo-api")
    if not expected_audiences.issubset(audiences):
        return False
    if not require_api_audience and "fapi-demo-api" in audiences:
        return False
    token_scopes = set(claims.get("scope", "").split())
    observed_scopes = set(document.get("scope", "").split())
    if observed_scopes != token_scopes or (require_openid and "openid" not in observed_scopes) or (not require_openid and "openid" in observed_scopes):
        return False
    return all(document.get(name) == claims.get(name) for name in ("azp", "sub", "cnf", f"{wp2.NAMESPACE}/department", f"{wp2.NAMESPACE}/route"))


def _remember_headers(headers, *, source="api_request_header"):
    for name, value in headers:
        normalized = name.lower()
        if normalized == "cookie":
            remember_sensitive(value, "cookie", source=source, field="cookie_value")
        elif "assertion" in normalized:
            remember_sensitive(value, "assertion", source=source, field=_candidate_field_label((name,)))
        elif normalized == "authorization":
            bearer = re.fullmatch(r"(?i)Bearer[ ]+(.+)", value)
            remember_sensitive(
                bearer.group(1) if bearer else value,
                "oauth_token", source=source, field="authorization_header",
            )
        elif normalized.startswith(("x-client-cert", "x_client_cert", "x-fapi", "x_fapi", "x-demo", "x_demo")):
            remember_sensitive(value, "spoof_sentinel", source=source, field="spoof_header")


def _record_api_rejection(case_rows, case_id, variant, context, capture_id, **kwargs):
    mark_variant_case(case_rows, case_id, variant, "running", "api_http_authorization", "api_gateway")
    try:
        return check_api_expectation(case_rows, case_id, variant, context, capture_id, **kwargs)
    except ApiTlsFailure as error:
        mark_variant_case(case_rows, case_id, variant, "needs_design", error.layer, error.layer, None, "not_applicable")
    except Exception:
        row = next(row for row in case_rows if row["case_id"] == case_id and row.get("variant") == variant)
        if row["outcome"] in {"not_run", "running"}:
            mark_variant_case(case_rows, case_id, variant, "fail", "api_http_authorization", "api_gateway", None, "malformed")
    return None


def _run_query_guard_cases(case_rows, context, route):
    grant = route["grant"]
    capture_id = context["containers"]["pop-verifier"]
    token_value = urllib.parse.quote(route["token"], safe="")
    valid_authorization = [("Authorization", "Bearer " + route["token"])]
    repeated_harmless = "&".join(["x=1"] * 1000)
    late_key = "&".join(["x=1"] * 998 + [f"access_token={token_value}"])
    truncated_late_key = "&".join(["x=1"] * 1000 + [f"access_token={token_value}"])
    query_cases = (
        ("query_only_token", f"access_token={token_value}", 1, [], False),
        ("query_encoded_name", f"%61ccess%5Ftoken={token_value}", 1, valid_authorization, False),
        ("query_mixed_case_name", f"AcCeSs_ToKeN={token_value}", 1, valid_authorization, False),
        ("query_dash_alias", f"access-token={token_value}", 1, valid_authorization, False),
        ("query_duplicate_name", f"access_token=first&access_token={token_value}", 2, valid_authorization, False),
        ("query_late_name", late_key, 999, valid_authorization, False),
        ("query_arg_limit_1000", repeated_harmless, 1000, valid_authorization, False),
        ("query_arg_truncated_1001", truncated_late_key, 1001, valid_authorization, False),
        ("harmless_query_control", "probe=small", 1, valid_authorization, True),
    )
    for variant, query, argument_count, headers, harmless in query_cases:
        path = API_PATH + "?" + query
        try:
            target_bytes = len(path.encode("ascii"))
        except UnicodeError:
            target_bytes = MAX_REQUEST_TARGET_BYTES + 1
        mark_variant_case(
            case_rows, "RS-QUERY-01", variant, "running", "api_http_authorization",
            "api_gateway", request_target_byte_count=target_bytes,
            query_argument_count=argument_count,
        )
        if target_bytes > MAX_REQUEST_TARGET_BYTES:
            mark_variant_case(
                case_rows, "RS-QUERY-01", variant, "fail", "api_http_authorization",
                "harness", None, "malformed", request_target_byte_count=target_bytes,
                query_argument_count=argument_count,
            )
            raise FlowError("query fixture exceeded the bounded HTTP request-target size")
        try:
            if harmless:
                check_api_expectation(
                    case_rows, "RS-QUERY-01", variant, context, capture_id,
                    token=route["token"], claims=route["claims"],
                    cert_path=grant["certificate"], key_path=grant["private_key"],
                    expected_status=200, expected_error=None, headers=headers, path=path,
                    count_unchanged=False,
                )
            else:
                check_api_expectation(
                    case_rows, "RS-QUERY-01", variant, context, capture_id,
                    token=route["token"], claims=route["claims"],
                    cert_path=grant["certificate"], key_path=grant["private_key"],
                    expected_status=401, expected_error="invalid_token", headers=headers, path=path,
                    count_unchanged=True,
                )
        except ApiTlsFailure as error:
            mark_variant_case(
                case_rows, "RS-QUERY-01", variant, "needs_design", error.layer,
                error.layer, None, "not_applicable", request_target_byte_count=target_bytes,
                query_argument_count=argument_count,
            )
            raise FlowError("query-guard request failed before the Gateway response could be classified") from None
        except Exception:
            row = next(
                row for row in case_rows
                if row.get("case_id") == "RS-QUERY-01" and row.get("variant") == variant
            )
            if row.get("outcome") in {"not_run", "running"}:
                mark_variant_case(
                    case_rows, "RS-QUERY-01", variant, "fail", "api_http_authorization",
                    "api_gateway", None, "malformed", request_target_byte_count=target_bytes,
                    query_argument_count=argument_count,
                )
            raise FlowError("query-guard request did not match its status, challenge, and capture contract") from None


def _authorize_and_exchange(context, route_key="a", scopes=None):
    wp2 = context["wp2"]
    CallbackServer = context["callback_server_class"]
    with CallbackServer(context["pki"]) as callback:
        grant = authorize_code_with_scopes(
            wp2, route_key, scopes or {"openid", "profile"}, context["metadata"], context["issuer"],
            context["pki"], callback, context["pki"] / "route-b-pkj.key", context["accounts"],
        )
    token_response = wp2.exchange_code(grant, context["issuer"], context["metadata"], context["pki"], context["pki"] / "route-b-pkj.key")
    response_collection = remember_sensitive(token_response, source="oauth_token_response")
    token = token_response.get("access_token")
    if not isinstance(token, str):
        raise FlowError("Keycloak did not return an access token for its genuine OAuth grant")
    remember_sensitive(token, "oauth_token", source="oauth_verified_access_token", field="access_token")
    return grant, token, token_response, response_collection


def _check_capture_positive(case_rows, case_id, variant, context, route, headers=None, expected_total=None):
    mark_variant_case(case_rows, case_id, variant, "running", "api_header_boundary", "api_gateway")
    token = route["token"]
    grant = route["grant"]
    claim_data = route["claims"]
    input_wire_count = 3 + len(_header_pairs(headers))
    if expected_total is not None and input_wire_count != expected_total:
        mark_variant_case(
            case_rows, case_id, variant, "fail", "request_wire_header_count", "harness",
            input_wire_header_count=input_wire_count,
        )
        raise FlowError("serialized request header count differed from the planned fixture count")
    before = capture_request_count(context["containers"]["pop-verifier"])
    status, response_headers, evidence = request_api(
        context["pki"], route["sni"], grant["certificate"], grant["private_key"], headers=headers or [("Authorization", "Bearer " + token)],
    )
    after = capture_request_count(context["containers"]["pop-verifier"])
    upstream_count = safe_nonnegative_count(evidence.get("request_header_count"), 4096) if isinstance(evidence, dict) else None
    if status == 200:
        try:
            verify_capture(context["wp2"], evidence, token, claim_data, grant["certificate"])
        except Exception:
            mark_variant_case(
                case_rows, case_id, variant, "fail", "upstream_capture_evidence", "upstream_capture",
                200, "not_applicable", input_wire_header_count=input_wire_count,
                upstream_header_count=upstream_count,
            )
            raise
        outcome = "pass" if after == before + 1 and upstream_count is not None else "fail"
        record_capture_observation(context["capture"], evidence)
        challenge = "not_applicable"
    else:
        outcome = "fail"
        challenge = challenge_for_status(status, response_headers)
    mark_variant_case(
        case_rows, case_id, variant, outcome, "api_header_boundary",
        "gateway+upstream_capture" if status == 200 else "api_gateway", status, challenge,
        input_wire_header_count=input_wire_count, upstream_header_count=upstream_count,
    )
    if outcome != "pass":
        raise FlowError("header boundary control did not reach the pinned upstream exactly once")


def _header_pairs_for_total(total, token, final_pairs=()):
    baseline = [("Authorization", "Bearer " + token)]
    fixed_wire_fields = 3 + len(baseline)  # Host, Accept, Connection, then Authorization.
    filler = total - fixed_wire_fields - len(final_pairs)
    if filler < 0:
        raise FlowError("requested header count was smaller than the fixed HTTP envelope")
    pairs = baseline + [(f"X{index:04d}", "0") for index in range(filler)]
    pairs.extend(final_pairs)
    return pairs


def _valid_wire_header_pairs(pairs, expected_total, *, required_last=None):
    token_re = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
    if not isinstance(pairs, list) or 3 + len(pairs) != expected_total:
        return False
    for item in pairs:
        if not isinstance(item, tuple) or len(item) != 2:
            return False
        name, value = item
        if not isinstance(name, str) or not token_re.fullmatch(name):
            return False
        if not isinstance(value, str) or not value.isascii() or any(ord(character) < 0x20 and character != "\t" for character in value) or "\x7f" in value:
            return False
    return required_last is None or (pairs and pairs[-1] == required_last)


def _api_response_scan_delta_is_clean(before):
    after = API_RESPONSE_SCAN
    return (
        after.get("completed") is True
        and after.get("failure_reason") == "none"
        and after.get("response_count") == before.get("response_count", 0) + 1
        and after.get("secret_value_match_count", 0) == before.get("secret_value_match_count", 0)
        and set(after.get("credential_pattern_matches", [])) == set(before.get("credential_pattern_matches", []))
    )


NGINX_TOO_MANY_HEADERS_MARKER = "client sent too many header lines"
NGINX_API_REQUEST_MARKER = f'request: "GET {API_PATH} HTTP/1.1"'


def _nginx_header_rejection_observation():
    """Read bounded owned-service logs in memory and count only fixed NGINX markers."""
    logs, status, failure_reason = compose_service_logs()
    completed = (
        failure_reason == "none"
        and set(logs) == set(LOG_SERVICE_NAMES)
        and set(status) == set(LOG_SERVICE_NAMES)
        and all(row.get("completed") is True and row.get("failure_reason") == "none" for row in status.values())
    )
    if not completed:
        return {"completed": False, "error_marker_count": None, "api_request_marker_count": None}
    lines = logs["kong-api"].splitlines()
    error_lines = [line for line in lines if NGINX_TOO_MANY_HEADERS_MARKER in line]
    matching_api_lines = [line for line in error_lines if NGINX_API_REQUEST_MARKER in line]
    return {
        "completed": True,
        "error_marker_count": len(error_lines),
        "api_request_marker_count": len(matching_api_lines),
    }


def _run_header_matrix(case_rows, context, route):
    token, grant, claims = route["token"], route["grant"], route["claims"]
    capture_id = context["containers"]["pop-verifier"]
    spoof = [(name, value) for name, value in CLIENT_CERT_SPOOF_HEADERS.items()]
    spoof.extend([
        ("Cookie", "WP3-COOKIE-SENTINEL-DUP-1"), ("Cookie", "WP3-COOKIE-SENTINEL-DUP-2"),
        ("X-Demo-Department", "WP3-SPOOF-DEPARTMENT-DUP-1"),
        ("x_demo_department", "WP3-SPOOF-DEPARTMENT-DUP-2"),
        ("X-Demo-Arbitrary", "WP3-SPOOF-DEMO-UNKNOWN"),
        ("X-Fapi-Route", "WP3-SPOOF-FAPI-ROUTE"),
        ("x_fapi_Arbitrary", "WP3-SPOOF-FAPI-UNKNOWN"),
        ("client_assertion", "WP3-ASSERTION-SENTINEL-DUP-1"),
        ("CLIENT_ASSERTION", "WP3-ASSERTION-SENTINEL-DUP-2"),
        ("client_assertion_type", "WP3-ASSERTION-TYPE-SENTINEL"),
        ("client_assertion_Unknown", "WP3-ASSERTION-UNKNOWN-SENTINEL"),
    ])
    _remember_headers(spoof, source="api_caller_spoof_header")
    _check_capture_positive(
        case_rows, "HEADER-CERT-01", "spoof_alias_duplicates", context, route,
        [("Authorization", "Bearer " + token), *spoof],
    )

    attack = [("x_fapi_Arbitrary", "WP3-SPOOF-LAST-PREFIX-ATTACK")]
    remember_sensitive(attack[0][1], "spoof_sentinel", source="api_header_fixture", field="spoof_header")
    pairs_101 = _header_pairs_for_total(101, token, attack)
    _check_capture_positive(case_rows, "HEADER-CERT-01", "headers_101", context, route, pairs_101, 101)

    pairs_999 = _header_pairs_for_total(999, token)
    _check_capture_positive(case_rows, "HEADER-CERT-01", "headers_999", context, route, pairs_999, 999)

    for total, variant in ((1000, "headers_1000"), (1001, "headers_1001")):
        mark_variant_case(case_rows, "HEADER-CERT-01", variant, "running", "gateway_header_limit", "api_gateway")
        before = capture_request_count(capture_id)
        final_attack = ("x_fapi_Arbitrary", "WP3-SPOOF-1001-PARSER-BOUNDARY")
        if total == 1001:
            remember_sensitive(
                final_attack[1], "spoof_sentinel",
                source="api_header_fixture", field="spoof_header",
            )
            pairs = _header_pairs_for_total(total, token, [final_attack])
        else:
            pairs = _header_pairs_for_total(total, token)
        response_scan_before = {
            "response_count": API_RESPONSE_SCAN.get("response_count", 0),
            "secret_value_match_count": API_RESPONSE_SCAN.get("secret_value_match_count", 0),
            "credential_pattern_matches": list(API_RESPONSE_SCAN.get("credential_pattern_matches", [])),
        }
        parser_log_before = _nginx_header_rejection_observation() if total == 1001 else None
        post_control = False
        try:
            status, response_headers, _body = request_api(
                context["pki"], route["sni"], grant["certificate"], grant["private_key"], headers=pairs,
            )
            after = capture_request_count(capture_id)
            challenge = challenge_for_status(status, response_headers)
            upstream_unchanged = after == before
            wire_valid = total == 1001 and _valid_wire_header_pairs(
                pairs, total, required_last=final_attack,
            )
            response_clean = _api_response_scan_delta_is_clean(response_scan_before)
            parser_log_after = _nginx_header_rejection_observation() if total == 1001 and status == 400 else None
            parser_log_completed = (
                parser_log_before is not None
                and parser_log_before.get("completed") is True
                and parser_log_after is not None
                and parser_log_after.get("completed") is True
            )
            error_delta = (
                parser_log_after["error_marker_count"] - parser_log_before["error_marker_count"]
                if parser_log_completed else None
            )
            request_marker_delta = (
                parser_log_after["api_request_marker_count"] - parser_log_before["api_request_marker_count"]
                if parser_log_completed else None
            )
            parser_metadata = context.get("header_parser_metadata") or {}
            parser_source = (
                "pinned_image_default_1000"
                if parser_metadata.get("source") == "pinned_image_default_1000"
                and parser_metadata.get("nginx_version") == "openresty/1.29.2.5"
                and parser_metadata.get("default_header_limit") == 1000
                and parser_metadata.get("max_headers_override_absent") is True
                else "not_proven"
            )
            if status == 431:
                passed = total == 1000 and upstream_unchanged
                outcome = "pass" if passed else "needs_design" if total == 1001 and upstream_unchanged else "fail"
                phase, layer = "gateway_header_limit", "api_gateway"
            elif status == 400 and total == 1001 and upstream_unchanged:
                # Same-token 999-header control ran before this case. Run it again
                # after parser rejection and only then consider a parser-layer pass.
                post_control = False
                try:
                    _check_capture_positive(
                        case_rows, "HEADER-CERT-01", "headers_999", context, route,
                        pairs_999, 999,
                    )
                    post_control = True
                except Exception:
                    post_control = False
                passed = (
                    parser_source == "pinned_image_default_1000"
                    and wire_valid is True
                    and response_clean is True
                    and parser_log_completed is True
                    and error_delta == 1
                    and request_marker_delta == 1
                    and post_control is True
                )
                outcome = "pass" if passed else "needs_design"
                phase, layer = "nginx_parser_header_limit", "nginx_parser"
                if not passed:
                    parser_source = "not_proven"
            else:
                post_control = False
                passed = False
                outcome = "fail"
                phase, layer = "gateway_header_limit", "api_gateway"
            mark_variant_case(
                case_rows, "HEADER-CERT-01", variant, outcome, phase,
                layer, status, challenge, input_wire_header_count=3 + len(pairs),
                parser_source=parser_source if total == 1001 else "not_run",
                wire_grammar_valid=wire_valid if total == 1001 else "not_run",
                upstream_unchanged=upstream_unchanged,
                response_scan_clean=response_clean if total == 1001 else "not_run",
                post_negative_valid_control=post_control if total == 1001 else "not_run",
                parser_log_scan_completed=parser_log_completed if total == 1001 and parser_log_after is not None else "not_run",
                parser_error_marker_delta=error_delta,
                parser_api_request_marker_delta=request_marker_delta,
            )
            if not passed and outcome != "needs_design":
                raise FlowError("Gateway did not fail closed at the configured header inspection boundary")
        except ApiTlsFailure as error:
            mark_variant_case(
                case_rows, "HEADER-CERT-01", variant, "fail", error.layer, error.layer,
                None, "not_applicable", input_wire_header_count=3 + len(pairs),
            )
            raise FlowError("header limit request failed before the Gateway could classify it") from None


def _run_auth_location_and_pop(case_rows, context, route_a, route_b):
    token, grant, claims = route_a["token"], route_a["grant"], route_a["claims"]
    capture_id = context["containers"]["pop-verifier"]
    remember_sensitive(token, "oauth_token", source="oauth_verified_access_token", field="access_token")
    invalid_token = "WP3-INVALID-TOKEN-SENTINEL-0001"
    remember_sensitive(invalid_token, "spoof_sentinel", source="api_invalid_bearer_fixture", field="authorization_header")
    _record_api_rejection(
        case_rows, "ERR-01", "invalid_bearer", context, capture_id,
        token=invalid_token, claims=claims, cert_path=grant["certificate"], key_path=grant["private_key"],
        expected_status=401, expected_error="invalid_token",
        headers=[("Authorization", "Bearer " + invalid_token)],
    )
    _remember_headers([("Cookie", "access_token=" + token)], source="api_request_header")
    _run_query_guard_cases(case_rows, context, route_a)
    body = urllib.parse.urlencode({"access_token": token})
    remember_sensitive(body, "oauth_token", source="api_request_body", field="api_body")
    _record_api_rejection(
        case_rows, "RS-BODY-01", "body_only_token", context, capture_id,
        token=token, claims=claims, cert_path=grant["certificate"], key_path=grant["private_key"],
        expected_status=401, expected_error="invalid_token", headers=[], body=body, method="POST",
        allow_absent_challenge_needs_design=True,
    )
    _record_api_rejection(
        case_rows, "RS-COOKIE-01", "cookie_only_token", context, capture_id,
        token=token, claims=claims, cert_path=grant["certificate"], key_path=grant["private_key"],
        expected_status=401, expected_error="invalid_token", headers=[("Cookie", "access_token=" + token)],
        allow_absent_challenge_needs_design=True,
    )

    for case_id, variant, certificate, private_key in (
        ("POP-01", "no_client_certificate", None, None),
        ("POP-02", "other_route_certificate", route_b["grant"]["certificate"], route_b["grant"]["private_key"]),
        ("POP-03", "outside_ca_certificate", PREVIEW / "pki/outside-ca-client.crt", PREVIEW / "pki/outside-ca-client.key"),
    ):
        mark_variant_case(case_rows, case_id, variant, "running", "api_pop_rejection", "api_gateway")
        before = capture_request_count(capture_id)
        try:
            status, response_headers, _body = request_api(
                context["pki"], route_a["sni"], certificate, private_key,
                headers=[("Authorization", "Bearer " + token)],
            )
            after = capture_request_count(capture_id)
            challenge = challenge_for_status(status, response_headers)
            passed = status == 401 and challenge == "invalid_token" and after == before
            mark_variant_case(case_rows, case_id, variant, "pass" if passed else "fail", "api_pop_rejection", "api_gateway", status, challenge)
            if not passed:
                raise FlowError("PoP mismatch did not produce HTTP 401 with a valid RFC 6750 challenge")
        except ApiTlsFailure as error:
            mark_variant_case(case_rows, case_id, variant, "needs_design", error.layer, error.layer, None, "not_applicable")
            if case_id == "POP-03":
                # An untrusted TLS client certificate is not an HTTP PoP rejection.
                continue
            if case_id == "POP-01":
                continue
            raise FlowError("recognized alternate Route client certificate failed before HTTP PoP evaluation") from None


def _run_audience_negative(case_rows, context):
    wp2 = context["wp2"]
    client_id = wp2.CLIENTS["a"]["client_id"]
    capture_id = context["containers"]["pop-verifier"]
    original = None
    mutated = False
    phase = "mapper_lookup"
    mark_variant_case(case_rows, "RS-AUD-01", "genuine_api_audience_absent", "running", "audience_mapper_mutation", "keycloak")
    mark_variant_case(case_rows, "RS-AUD-01", "restored_positive_control", "running", "audience_mapper_restore", "keycloak")
    try:
        _client_uuid, original = _client_and_mapper(wp2, context["admin"], client_id)
        mutated = True
        phase = "audience_mapper_mutation"
        set_api_audience_mapper(wp2, context["admin"], client_id, original, False)
        phase = "genuine_oauth_token_issuance"
        grant, token, _token_response, token_collection = _authorize_and_exchange(context, "a", {"openid", "profile"})
        phase = "token_signature_and_claim_validation"
        _header, claims = verified_resource_claims(
            wp2, token, context["jwks"], context["issuer"], grant,
            required_scopes={"openid", "profile"}, required_audience={"api-gateway-introspection"},
            forbidden_audience={"fapi-demo-api"},
        )
        resolve_verified_token_response_identifiers(token_collection, claims, grant, token)
        remember_sensitive(token, "oauth_token", source="oauth_verified_access_token", field="access_token")
        remember_sensitive(token, "oauth_token", source="api_audience_fixture", field="access_token")
        phase = "direct_mtls_introspection"
        introspection = wp2.introspect(token, context["metadata"], context["pki"])
        introspection_collection = remember_sensitive(
            introspection, source="oauth_introspection_response", token_binding=token,
        )
        fixture_valid = (
            _verify_direct_introspection(wp2, introspection, claims, active=True, require_api_audience=False)
            and "api-gateway-introspection" in wp2.audiences(introspection)
            and "fapi-demo-api" not in wp2.audiences(introspection)
        )
        if fixture_valid:
            resolve_verified_introspection_identifiers(
                introspection_collection, claims, grant, token,
                active=introspection.get("active") is True,
            )
        phase = "api_audience_rejection"
        if claims.get("exp", 0) <= time.time():
            raise FlowError("audience-negative access token expired before its API request")
        before = capture_request_count(capture_id)
        status, response_headers, _response = request_api(
            context["pki"], "localhost", grant["certificate"], grant["private_key"],
            headers=[("Authorization", "Bearer " + token)],
        )
        after = capture_request_count(capture_id)
        challenge = challenge_for_status(status, response_headers)
        accepted_error = (status, challenge) in {
            (401, "invalid_token"),
            (403, "insufficient_scope"),
        }
        passed = fixture_valid and accepted_error and after == before
        mark_variant_case(case_rows, "RS-AUD-01", "genuine_api_audience_absent", "pass" if passed else "fail", "api_audience_rejection", "api_gateway", status, challenge)
        if not passed:
            raise FlowError("audience negative did not preserve an active token while rejecting the missing API audience")
    except Exception:
        row = next(row for row in case_rows if row["case_id"] == "RS-AUD-01")
        if row["outcome"] in {"not_run", "running"}:
            setup_phase = phase in {"mapper_lookup", "audience_mapper_mutation", "genuine_oauth_token_issuance"}
            mark_variant_case(
                case_rows, "RS-AUD-01", "genuine_api_audience_absent",
                "needs_design" if setup_phase else "fail", phase,
                "keycloak" if setup_phase else "token_validation" if phase == "token_signature_and_claim_validation" else "api_gateway",
            )
        if original is None:
            mark_variant_case(
                case_rows, "RS-AUD-01", "restored_positive_control", "needs_design",
                phase, "keycloak",
            )
    finally:
        if mutated and original is not None:
            try:
                restore_api_audience_mapper(wp2, context["admin"], original)
            except Exception:
                context["fixture_restore_failed"] = True
                mark_variant_case(case_rows, "RS-AUD-01", "genuine_api_audience_absent", "fail", "audience_mapper_restore", "keycloak")
                mark_variant_case(case_rows, "RS-AUD-01", "restored_positive_control", "fail", "audience_mapper_restore", "keycloak")
                raise FlowError("Keycloak API audience mapper restoration failed") from None
    if original is None:
        return
    phase = "audience_restore_token_validation"
    try:
        grant, token, _response, token_collection = _authorize_and_exchange(context, "a", {"openid", "profile"})
        _header, claims = verified_resource_claims(
            wp2, token, context["jwks"], context["issuer"], grant,
            required_scopes={"openid", "profile"},
            required_audience={"api-gateway-introspection", "fapi-demo-api"},
        )
        resolve_verified_token_response_identifiers(token_collection, claims, grant, token)
        remember_sensitive(token, "oauth_token", source="oauth_verified_access_token", field="access_token")
        phase = "audience_restore_introspection"
        introspection = wp2.introspect(token, context["metadata"], context["pki"])
        introspection_collection = remember_sensitive(
            introspection, source="oauth_introspection_response", token_binding=token,
        )
        introspection_valid = (
            _verify_direct_introspection(wp2, introspection, claims, active=True)
            and {"api-gateway-introspection", "fapi-demo-api"}.issubset(wp2.audiences(introspection))
        )
        if not introspection_valid:
            raise FlowError("restored mapper did not return an active token with both audience values")
        resolve_verified_introspection_identifiers(
            introspection_collection, claims, grant, token,
            active=introspection.get("active") is True,
        )
        phase = "audience_restore_positive_control"
        check_api_expectation(
            case_rows, "RS-AUD-01", "restored_positive_control", context, capture_id,
            token=token, claims=claims, cert_path=grant["certificate"], key_path=grant["private_key"],
            expected_status=200, expected_error=None,
            headers=[("Authorization", "Bearer " + token)], count_unchanged=False,
        )
    except Exception:
        row = next(
            row for row in case_rows
            if row.get("case_id") == "RS-AUD-01" and row.get("variant") == "restored_positive_control"
        )
        if row["outcome"] in {"not_run", "running"}:
            layer = "token_validation" if phase == "audience_restore_token_validation" else "keycloak" if phase == "audience_restore_introspection" else "api_gateway"
            mark_variant_case(case_rows, "RS-AUD-01", "restored_positive_control", "fail", phase, layer)
        raise FlowError("fresh restored-audience positive control failed") from None


def _run_scope_negative(case_rows, context):
    wp2 = context["wp2"]
    phase = "genuine_scope_oauth_grant"
    mark_variant_case(case_rows, "RS-SCOPE-01", "genuine_openid_scope_absent", "running", "authorization_scope_profile_only", "keycloak")
    try:
        grant, token, response, token_collection = _authorize_and_exchange(context, "a", {"profile"})
        phase = "token_signature_and_claim_validation"
        _header, claims = verified_resource_claims(
            wp2, token, context["jwks"], context["issuer"], grant,
            required_scopes={"profile"}, required_audience={"fapi-demo-api", "api-gateway-introspection"},
            forbidden_scopes={"openid"},
        )
        resolve_verified_token_response_identifiers(token_collection, claims, grant, token)
        remember_sensitive(token, "oauth_token", source="api_scope_fixture", field="access_token")
        # No ID token is required or consulted for this access-token-only grant.
        phase = "direct_mtls_introspection"
        introspection = wp2.introspect(token, context["metadata"], context["pki"])
        introspection_collection = remember_sensitive(
            introspection, source="oauth_introspection_response", token_binding=token,
        )
        introspection_valid = _verify_direct_introspection(
            wp2, introspection, claims, active=True, require_api_audience=True,
            require_openid=False,
        )
        if not introspection_valid:
            raise FlowError("scope-only token did not remain active with its audience and certificate binding")
        resolve_verified_introspection_identifiers(
            introspection_collection, claims, grant, token,
            active=introspection.get("active") is True,
        )
        cert, key = grant["certificate"], grant["private_key"]
        phase = "required_scope_rejection"
        if claims.get("exp", 0) <= time.time():
            raise FlowError("scope-negative access token expired before its API request")
        before = capture_request_count(context["containers"]["pop-verifier"])
        status, headers, _body = request_api(
            context["pki"], "localhost", cert, key, headers=[("Authorization", "Bearer " + token)],
        )
        after = capture_request_count(context["containers"]["pop-verifier"])
        challenge = challenge_for_status(status, headers)
        passed = status == 403 and challenge == "insufficient_scope" and after == before
        mark_variant_case(case_rows, "RS-SCOPE-01", "genuine_openid_scope_absent", "pass" if passed else "fail", "required_scope_rejection", "api_gateway", status, challenge)
        if not passed:
            raise FlowError("genuine profile-only token was not rejected for missing openid scope")
    except Exception:
        row = next(row for row in case_rows if row["case_id"] == "RS-SCOPE-01")
        if row["outcome"] in {"not_run", "running"}:
            setup_phase = phase == "genuine_scope_oauth_grant"
            mark_variant_case(
                case_rows, "RS-SCOPE-01", "genuine_openid_scope_absent",
                "needs_design" if setup_phase else "fail", phase,
                "keycloak" if setup_phase else "token_validation" if phase == "token_signature_and_claim_validation" else "active_check" if phase == "direct_mtls_introspection" else "api_gateway",
            )


def _run_active_transition(case_rows, context, route):
    wp2 = context["wp2"]
    token, claims, grant = route["token"], route["claims"], route["grant"]
    remember_sensitive(token, "oauth_token", source="api_active_transition", field="access_token")
    capture_id = context["containers"]["pop-verifier"]
    username = context["accounts"]["WP2_ENGINEERING_USERNAME"]
    original_user = None
    mutation_attempted = False
    phase = "enabled_control"
    mark_variant_case(case_rows, "RS-ACTIVE-01", "enabled_control", "running", "same_token_active_check", "active_check")
    mark_variant_case(case_rows, "RS-ACTIVE-01", "disabled_same_token", "running", "same_token_active_check", "active_check")
    mark_variant_case(case_rows, "RS-ACTIVE-01", "restored_control", "running", "same_token_active_check", "active_check")
    try:
        if claims.get("exp", 0) <= time.time():
            raise FlowError("active-transition access token expired before its enabled control")
        initial = wp2.introspect(token, context["metadata"], context["pki"])
        initial_collection = remember_sensitive(
            initial, source="oauth_introspection_response", token_binding=token,
        )
        active_before = _verify_direct_introspection(wp2, initial, claims, active=True)
        if not active_before:
            raise FlowError("same-token enabled control did not return active=true")
        resolve_verified_introspection_identifiers(
            initial_collection, claims, grant, token, active=initial.get("active") is True,
        )
        check_api_expectation(
            case_rows, "RS-ACTIVE-01", "enabled_control", context, capture_id,
            token=token, claims=claims, cert_path=grant["certificate"], key_path=grant["private_key"],
            expected_status=200, expected_error=None, headers=[("Authorization", "Bearer " + token)], count_unchanged=False,
        )
        phase = "enabled_user_lookup"
        original_user = api_user_representation(wp2, context["admin"], username)
        if original_user.get("enabled") is not True:
            raise FlowError("fresh fixture engineering user was not enabled before the transition")
        phase = "disable_fixture_user"
        mutation_attempted = True
        set_fixture_user_enabled(wp2, context["admin"], original_user, False)
        phase = "disabled_same_token_introspection"
        disabled = wp2.introspect(token, context["metadata"], context["pki"])
        remember_sensitive(
            disabled, source="oauth_introspection_response", token_binding=token,
        )
        if not _verify_direct_introspection(wp2, disabled, claims, active=False):
            mark_variant_case(case_rows, "RS-ACTIVE-01", "disabled_same_token", "needs_design", "same_token_active_check", "active_check")
            return
        phase = "disabled_same_token_api_request"
        if claims.get("exp", 0) <= time.time():
            raise FlowError("active-transition access token expired before its disabled API request")
        before = capture_request_count(capture_id)
        status, response_headers, _body = request_api(
            context["pki"], route["sni"], grant["certificate"], grant["private_key"],
            headers=[("Authorization", "Bearer " + token)],
        )
        after = capture_request_count(capture_id)
        challenge = challenge_for_status(status, response_headers)
        passed = status == 401 and challenge == "invalid_token" and after == before
        mark_variant_case(case_rows, "RS-ACTIVE-01", "disabled_same_token", "pass" if passed else "fail", "same_token_active_check", "active_check", status, challenge)
        if not passed:
            raise FlowError("Gateway did not reject the same token while direct introspection was inactive")
    except Exception:
        row = next(row for row in case_rows if row["case_id"] == "RS-ACTIVE-01" and row["variant"] == "disabled_same_token")
        if row["outcome"] in {"not_run", "running"}:
            setup_phase = phase in {"enabled_user_lookup", "disable_fixture_user", "disabled_same_token_introspection"}
            mark_variant_case(
                case_rows, "RS-ACTIVE-01", "disabled_same_token",
                "needs_design" if setup_phase else "fail", phase,
                "active_check" if setup_phase else "api_gateway",
            )
        if not mutation_attempted:
            mark_variant_case(case_rows, "RS-ACTIVE-01", "restored_control", "not_run", "fixture_not_mutated", "not_run")
        raise
    finally:
        if mutation_attempted and original_user is not None:
            try:
                set_fixture_user_enabled(wp2, context["admin"], original_user, True)
                if claims.get("exp", 0) <= time.time():
                    raise FlowError("active-transition access token expired before its restore control")
                restored = wp2.introspect(token, context["metadata"], context["pki"])
                restored_collection = remember_sensitive(
                    restored, source="oauth_introspection_response", token_binding=token,
                )
                if not _verify_direct_introspection(wp2, restored, claims, active=True):
                    raise FlowError("same token did not return active=true after fixture restoration")
                resolve_verified_introspection_identifiers(
                    restored_collection, claims, grant, token, active=restored.get("active") is True,
                )
                check_api_expectation(
                    case_rows, "RS-ACTIVE-01", "restored_control", context, capture_id,
                    token=token, claims=claims, cert_path=grant["certificate"], key_path=grant["private_key"],
                    expected_status=200, expected_error=None, headers=[("Authorization", "Bearer " + token)], count_unchanged=False,
                )
            except Exception:
                context["fixture_restore_failed"] = True
                mark_variant_case(case_rows, "RS-ACTIVE-01", "restored_control", "fail", "fixture_restore", "active_check")
                raise FlowError("Keycloak fixture user could not be restored with a positive token control") from None


def _tls13_aead_observation(observation):
    return (
        isinstance(observation, dict)
        and observation.get("protocol") == "TLSv1.3"
        and observation.get("cipher") in TLS13_APPROVED_AEAD_CIPHERS
    )


def _run_tls_negatives(case_rows, context, route):
    grant = route["grant"]
    pki = context["pki"]
    capture_id = context["containers"]["pop-verifier"]
    tls_policy_proven = context.get("tls_policy_proven") is True
    tests = (
        ("tls_11", {"minimum_tls": ssl.TLSVersion.TLSv1_1, "maximum_tls": ssl.TLSVersion.TLSv1_1, "cipher_suite": "AES128-SHA:@SECLEVEL=0"}, {"peer_alert_protocol_version", "peer_alert_handshake_failure", "peer_alert_insufficient_security"}, 0x002F, ["TLSv1.1"]),
        ("tls_12_only", {"minimum_tls": ssl.TLSVersion.TLSv1_2, "maximum_tls": ssl.TLSVersion.TLSv1_2, "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0"}, {"peer_alert_protocol_version"}, 0xC02F, ["TLSv1.2"]),
        ("weak_cipher", {"minimum_tls": ssl.TLSVersion.TLSv1_2, "maximum_tls": ssl.TLSVersion.TLSv1_2, "cipher_suite": "AES128-SHA:@SECLEVEL=0"}, {"peer_alert_protocol_version"}, 0x002F, ["TLSv1.2"]),
        ("server_san_mismatch", {}, {"server_san_mismatch"}, None, None),
        ("untrusted_server_ca", {"server_ca_file": PREVIEW / "pki/outside-ca-client.crt"}, {"server_untrusted_ca"}, None, None),
    )
    expected_verify_codes = {
        "server_san_mismatch": {62},
        "untrusted_server_ca": {18, 19, 20, 21, 27},
    }
    for variant, options, accepted_reasons, cipher_id, expected_protocols in tests:
        mark_variant_case(case_rows, "TLS-RS-01", variant, "running", "tls_negative", "api_gateway_tls")
        offer = client_hello_offerability(
            pki, route["sni"], grant["certificate"], grant["private_key"],
            minimum_tls=options.get("minimum_tls"), maximum_tls=options.get("maximum_tls"),
            cipher_suite=options.get("cipher_suite"), expected_cipher_id=cipher_id,
        )
        offered_protocols = offer.get("offered_protocols", [])
        offer_ok = offer.get("client_hello_emitted") is True and offer.get("target_cipher_offered") is True
        if expected_protocols is not None:
            offer_ok = offer_ok and offered_protocols == expected_protocols
        if not offer_ok:
            mark_variant_case(
                case_rows, "TLS-RS-01", variant, "needs_design", "client_offer_unavailable",
                "client_tls_configuration", client_hello_offered=False,
                offered_protocols=offered_protocols,
                tls_policy_proven=tls_policy_proven,
                tls_failure_reason=offer.get("reason", "client_offer_unavailable"),
            )
            continue

        try:
            # A complete TLS 1.3 handshake immediately precedes every negative.
            pre_control = tls_handshake_probe(
                pki, route["sni"], grant["certificate"], grant["private_key"], observe=True,
            )
        except Exception:
            pre_control = None
        if not _tls13_aead_observation(pre_control):
            mark_variant_case(
                case_rows, "TLS-RS-01", variant, "needs_design", "tls_positive_control",
                "tls_handshake", client_hello_offered=True,
                offered_protocols=offered_protocols,
                tls_policy_proven=tls_policy_proven,
                negotiated_protocol="not_run", negotiated_cipher="not_run",
                tls_failure_reason="other_tls_error",
            )
            continue

        before = capture_request_count(capture_id)
        sni = "wp3-san-mismatch.invalid" if variant == "server_san_mismatch" else route["sni"]
        try:
            status, response_headers, _response = request_api(
                pki, sni, grant["certificate"], grant["private_key"], headers=[],
                allow_san_mismatch=variant == "server_san_mismatch", **options,
            )
            after = capture_request_count(capture_id)
            post_control = _post_negative_tls_control(pki, route, capture_id, before)
            mark_variant_case(
                case_rows, "TLS-RS-01", variant, "fail", "tls_negative", "api_gateway",
                status, challenge_for_status(status, response_headers), client_hello_offered=True,
                offered_protocols=offered_protocols,
                tls_policy_proven=tls_policy_proven,
                negotiated_protocol=pre_control["protocol"], negotiated_cipher=pre_control["cipher"],
                upstream_unchanged=after == before,
                tls_failure_reason="other_tls_error", post_negative_valid_control=post_control,
            )
        except ApiTlsFailure as error:
            after = capture_request_count(capture_id)
            upstream_unchanged = after == before
            post_control = _post_negative_tls_control(pki, route, capture_id, before)
            if not upstream_unchanged:
                mark_variant_case(
                    case_rows, "TLS-RS-01", variant, "fail", error.reason, error.layer,
                    client_hello_offered=True, offered_protocols=offered_protocols,
                    tls_policy_proven=tls_policy_proven,
                    negotiated_protocol=pre_control["protocol"], negotiated_cipher=pre_control["cipher"],
                    upstream_unchanged=False, tls_failure_reason=error.reason,
                    tls_verify_code=error.verify_code, post_negative_valid_control=post_control,
                )
                raise FlowError("TLS negative unexpectedly incremented the upstream capture counter") from None
            reason_ok = error.reason in accepted_reasons and (
                variant not in expected_verify_codes
                or error.verify_code in expected_verify_codes[variant]
            )
            specific_tls12_proof = (
                variant not in {"tls_12_only", "weak_cipher"}
                or (
                    tls_policy_proven
                    and offered_protocols == ["TLSv1.2"]
                    and error.reason == "peer_alert_protocol_version"
                    and _tls13_aead_observation(pre_control)
                )
            )
            if variant == "weak_cipher":
                good_tls12_control = next(
                    (row for row in case_rows if row.get("case_id") == "TLS-RS-01" and row.get("variant") == "tls_12_only"),
                    None,
                )
                specific_tls12_proof = specific_tls12_proof and isinstance(good_tls12_control, dict) and good_tls12_control.get("outcome") == "pass"
            if not post_control:
                outcome = "needs_design"
                phase, layer = "post_negative_positive_control", "tls_handshake"
            elif reason_ok and specific_tls12_proof:
                outcome = "pass"
                phase, layer = "tls_negative", error.layer
            elif error.reason in accepted_reasons and not specific_tls12_proof:
                outcome = "needs_design"
                phase, layer = "tls_negative", error.layer
            else:
                outcome = "fail"
                phase, layer = "tls_negative", error.layer
            mark_variant_case(
                case_rows, "TLS-RS-01", variant, outcome, phase, layer,
                client_hello_offered=True,
                offered_protocols=offered_protocols,
                tls_policy_proven=tls_policy_proven,
                negotiated_protocol=pre_control["protocol"], negotiated_cipher=pre_control["cipher"],
                upstream_unchanged=True, tls_failure_reason=error.reason,
                tls_verify_code=error.verify_code, post_negative_valid_control=post_control,
            )
        except Exception:
            post_control = _post_negative_tls_control(pki, route, capture_id, before)
            mark_variant_case(
                case_rows, "TLS-RS-01", variant, "fail", "tls_negative", "api_gateway",
                client_hello_offered=True, offered_protocols=offered_protocols,
                tls_policy_proven=tls_policy_proven,
                negotiated_protocol=pre_control["protocol"], negotiated_cipher=pre_control["cipher"],
                upstream_unchanged=False, tls_failure_reason="other_tls_error",
                post_negative_valid_control=post_control,
            )
            raise


def _post_negative_tls_control(pki, route, capture_id, expected_count):
    try:
        grant = route["grant"]
        observation = tls_handshake_probe(
            pki, route["sni"], grant["certificate"], grant["private_key"], observe=True,
        )
        return _tls13_aead_observation(observation) and capture_request_count(capture_id) == expected_count
    except Exception:
        return False


def run_negative_matrix(case_rows, context, execution):
    execution["scope"] = "wp3_positive_and_required_negative_matrix"
    execution["phase"] = "negative_matrix_preflight"
    route_a = context["routes"].get("A")
    route_b = context["routes"].get("B")
    if not route_a or not route_b:
        raise FlowError("both exact Route positive controls are required before negative tests")
    groups = (
        ("auth_location_pop", _run_auth_location_and_pop, {"RS-QUERY-01", "RS-BODY-01", "RS-COOKIE-01", "POP-01", "POP-02", "POP-03", "ERR-01"}, (route_a, route_b)),
        ("header_boundary", _run_header_matrix, {"HEADER-CERT-01"}, (route_a,)),
        ("audience_negative", _run_audience_negative, {"RS-AUD-01", "RS-ACTIVE-01"}, ()),
        ("scope_negative", _run_scope_negative, {"RS-SCOPE-01"}, ()),
        ("active_transition", _run_active_transition, {"RS-ACTIVE-01"}, (route_a,)),
        ("tls_negatives", _run_tls_negatives, {"TLS-RS-01"}, (route_a,)),
    )
    failures = []
    for name, operation, case_ids, arguments in groups:
        execution["phase"] = "negative_" + name
        try:
            operation(case_rows, context, *arguments)
        except Exception:
            failures.append(name)
            for row in case_rows:
                if row["case_id"] in case_ids and row["outcome"] == "running":
                    if "variant" in row:
                        mark_variant_case(case_rows, row["case_id"], row["variant"], "fail", execution["phase"], "harness")
                    else:
                        row.update({"outcome": "fail", "phase": execution["phase"], "layer": "harness", "http_status": None, "rfc6750_challenge": "malformed"})
            if context.get("fixture_restore_failed"):
                break
    execution["negative_group_failures"] = failures
    execution["phase"] = "negative_matrix_complete"
    return {"completed": not failures, "failed_groups": failures}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-run-wp3-api-probes", action="store_true")
    args = parser.parse_args()
    if not args.allow_run_wp3_api_probes:
        parser.error("the isolated WP3 Keycloak and Gateway probes require a separate preview approval")

    SENSITIVE_VALUES.clear()
    PUBLIC_ROUTE_CERT_THUMBPRINTS.clear()
    PUBLIC_ROUTE_CERT_THUMBPRINTS.clear()
    reset_api_response_scan()
    case_rows = initial_cases()
    execution = {
        "scope": "wp3_positive_and_required_negative_matrix", "outcome": "running",
        "phase": "preflight", "layer": "harness", "http_status": None,
        "host_runtime": None, "schema_probe": None, "header_parser_metadata": None,
        "schema_probe_diagnostic": {"stage": "not_started", "reason": "not_started", "plugin": "none"},
        "state_contract": None,
        "effective_inbound_tls_policy": None,
        "negative_group_failures": [],
    }
    capture = {
        "request_count": 0,
        "api_peer_pin_matches": "not_run",
        "api_peer_common_name_matches": "not_run",
        "authorization_single_bearer": "not_run",
        "authorization_sha256_present": "not_run",
        "forwarded_certificate_thumbprint_present": "not_run",
        "forwarded_certificate_single_url_encoded_pem_leaf": "not_run",
        "cookie_absent": "not_run",
        "client_assertion_headers_absent": "not_run",
        "client_assertion_unknown_suffix_header_count": "not_run",
        "fixture_underscores_in_headers_on": "not_run",
        "x_fapi_headers_absent": "not_run",
        "x_demo_unexpected_headers_absent": "not_run",
        "department_header_matches_expected_claim": "not_run",
        "route_header_matches_expected_claim": "not_run",
        "x_client_cert_like_header_count": "not_run",
        "x_client_cert_header_count": "not_run",
        "x_client_cert_unknown_suffix_header_count": "not_run",
        "x_client_cert_duplicate_header_count": "not_run",
        "x_client_cert_underscore_alias_count": "not_run",
        "x_client_cert_stock_details_complete": "not_run",
        "x_client_cert_stock_detail_counts": {
            "serial": "not_run",
            "issuer_dn": "not_run",
            "subject_dn": "not_run",
            "fingerprint": "not_run",
            "chain": "not_run",
        },
        "x_client_cert_fingerprint_matches_forwarded_leaf": "not_run",
        "caller_spoof_sentinel_match_count": "not_run",
    }
    tls = {
        "localhost_sni_positive": "not_run",
        "kong_api_sni_positive": "not_run",
        "localhost_sni_requested_client_certificate": "not_run",
        "kong_api_sni_requested_client_certificate": "not_run",
        "no_client_certificate_handshake_rejected": "not_run",
        "tls_11_rejected": "not_run",
        "tls_12_only_rejected": "not_run",
        "weak_cipher_rejected": "not_run",
        "untrusted_server_certificate_rejected": "not_run",
        "san_mismatch_rejected": "not_run",
    }
    images = {}
    sensitive_values: list[tuple[str, str]] = []
    failure = False
    containers_started = False
    try:
        try:
            containers_started = bool(verify_owned_project_containers(allow_stopped=True))
        except Exception:
            containers_started = False
        sensitive_values.extend(collect_fixture_sensitive_values())
        result = run_positive_flows(case_rows, capture, tls, sensitive_values, execution)
        images = result["images"]
        execution["outcome"] = "pass"
        execution["layer"] = "isolated_positive_a_b"
        matrix = run_negative_matrix(case_rows, result, execution)
        if not matrix["completed"]:
            execution["outcome"] = "fail"
            failed_groups = matrix.get("failed_groups", [])
            if failed_groups:
                execution["phase"] = "negative_" + failed_groups[-1]
            failure = True
            print(
                f"WP3_RUNTIME_FAILURE phase={safe_execution_phase(execution)} reason=negative_matrix_failed",
                file=sys.stderr,
            )
    except Exception:
        failure = True
        execution["outcome"] = "fail"
        execution["layer"] = "harness_or_transport"
        print(
            f"WP3_RUNTIME_FAILURE phase={safe_execution_phase(execution)} reason=probe_failed",
            file=sys.stderr,
        )
        try:
            images = verify_preparation_receipt()["images"]
            sensitive_values.extend(collect_fixture_sensitive_values())
        except Exception:
            pass
    if not failure:
        execution["phase"] = "whole_runtime_log_scan"
    try:
        log_scan = scan_logs_for_sensitive_values(sensitive_values)
    except Exception:
        if not failure:
            execution["phase"] = "whole_runtime_log_scan"
            failure = True
        log_scan = {
            "passed": False,
            "completed": False,
            "failure_reason": "log_read_failed",
            "candidate_value_count": len(normalize_log_candidates(sensitive_values)),
            "checked_value_count": 0,
            "secret_value_match_count": 0,
            "source_category_counts": category_counts(normalize_log_candidates(sensitive_values)),
            "matched_source_category_counts": {category: 0 for category in LOG_VALUE_CATEGORIES},
            "secret_match_category_counts": {category: 0 for category in LOG_VALUE_CATEGORIES},
            "credential_pattern_match_count": 0,
            "credential_pattern_matches": [],
            "public_fixture_identifier_observation_count": 0,
            "public_fixed_protocol_constant_observation_count": 0,
            "service_scans": _unscanned_service_log_rows(
                len(normalize_log_candidates(sensitive_values)), "log_read_failed"
            ),
            **api_response_scan_receipt(),
        }
    api_scan = api_response_scan_receipt()
    if not api_scan["api_response_completed"]:
        log_scan["passed"] = False
        log_scan["completed"] = False
        log_scan["failure_reason"] = "api_response_scan_incomplete"
    elif api_scan["api_response_secret_value_match_count"] or api_scan["api_response_credential_pattern_matches"]:
        log_scan["passed"] = False
    logs_clean = log_scan["passed"] and log_scan["completed"]
    if log_scan["completed"] and not log_scan["passed"]:
        if not failure:
            execution["phase"] = "whole_runtime_log_scan"
        failure = True
    if not api_scan["api_response_count"] and logs_clean:
        leak_outcome = "not_run"
        leak_phase = "startup_logs_only_no_api_traffic"
    elif logs_clean:
        leak_outcome = "pass"
        leak_phase = "whole_runtime_log_scan"
    elif log_scan["completed"]:
        leak_outcome = "fail"
        leak_phase = "whole_runtime_log_scan"
    else:
        leak_outcome = "needs_design"
        leak_phase = "whole_runtime_log_scan"
    mark_variant_case(
        case_rows, "LEAK-01", "whole_runtime_lifecycle", leak_outcome,
        leak_phase, "harness",
        None, "not_applicable",
    )
    for variant, tls_field in (
        ("tls_11", "tls_11_rejected"),
        ("tls_12_only", "tls_12_only_rejected"),
        ("weak_cipher", "weak_cipher_rejected"),
        ("server_san_mismatch", "san_mismatch_rejected"),
        ("untrusted_server_ca", "untrusted_server_certificate_rejected"),
    ):
        row = next(item for item in case_rows if item["case_id"] == "TLS-RS-01" and item["variant"] == variant)
        tls[tls_field] = True if row["outcome"] == "pass" else False if row["outcome"] == "fail" else "not_run"
    pop_none = next(item for item in case_rows if item["case_id"] == "POP-01")
    tls["no_client_certificate_handshake_rejected"] = True if pop_none["layer"] == "tls_handshake" else False if pop_none["outcome"] == "fail" else "not_run"
    acceptance_outcomes = [row["outcome"] for row in case_rows]
    if any(outcome in {"fail", "running"} for outcome in acceptance_outcomes) or failure:
        failure = True
        full_acceptance = "fail"
        result_name = "fail"
    elif any(outcome in {"not_run", "needs_design"} for outcome in acceptance_outcomes) or not log_scan["completed"]:
        full_acceptance = "needs_design" if "needs_design" in acceptance_outcomes else "not_run"
        result_name = "partial"
    else:
        full_acceptance = "pass"
        result_name = "pass"
    execution["outcome"] = result_name
    if not failure:
        execution["phase"] = "runtime_complete"
    if failure:
        execution["layer"] = "harness_or_transport"
    elif result_name == "partial":
        execution["layer"] = "isolated_runtime_partial"
    else:
        execution["layer"] = "isolated_runtime_full"
    payload = {
        "schema_version": 1,
        "scope": "wp3-api-runtime-isolated-validation",
        "result": result_name,
        "host_ports": {"keycloak": 18444, "api_gateway": 18443, "oauth_callback": 8443},
        "images": images,
        "cases": {
            "scope": execution["scope"],
            "execution": execution,
            "acceptance": case_rows,
            "full_wp3_acceptance": full_acceptance,
        },
        "tls": tls,
        "capture": capture,
        "log_scan": log_scan,
        "containers_started": containers_started,
        "konnect_read_or_write_performed": False,
    }
    try:
        write_runtime_receipt(payload)
    except RuntimeReceiptFailure as error:
        print(
            f"WP3_RUNTIME_RECEIPT_FAILURE phase={safe_execution_phase(execution)} reason={error.reason}",
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(
            f"WP3_RUNTIME_RECEIPT_FAILURE phase={safe_execution_phase(execution)} reason=write_failed",
            file=sys.stderr,
        )
        return 1
    for case in case_rows:
        route = f" route={case['route']}" if "route" in case else ""
        status = f" http={case['http_status']}" if case["http_status"] is not None else ""
        print(f"{case['case_id']}{route}: {case['outcome'].upper()} phase={case['phase']} layer={case['layer']}{status}")
    print(
        "WP3 runtime log scan: "
        f"{'PASS' if logs_clean else 'FAIL'} completed={log_scan['completed']} "
        f"secret_matches={log_scan['secret_value_match_count']} "
        f"pattern_categories={log_scan['credential_pattern_match_count']} "
        f"api_responses={log_scan['api_response_count']} "
        f"api_response_secret_matches={log_scan['api_response_secret_value_match_count']} "
        f"api_response_pattern_categories={len(log_scan['api_response_credential_pattern_matches'])} "
        f"public_identifier_observations={log_scan['public_fixture_identifier_observation_count']}"
    )
    print(f"WP3 isolated runtime scope: {result_name.upper()} ({execution['scope']}); unverified cases remain explicitly not_run/needs_design.")
    print("Sanitized receipt created with booleans, counts, safe enums, and image digests only.")
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
