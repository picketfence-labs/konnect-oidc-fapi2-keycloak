#!/usr/bin/env python3
"""Prepare fresh WP3 API runtime fixture assets without starting containers."""

from __future__ import annotations

import hashlib
import argparse
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PREVIEW = ROOT / ".generated/wp3-preview"
COMPOSE_FILE = ROOT / "tests/harness/docker-compose.wp3.yml"
CAPTURE_HELPER = ROOT / "tests/harness/wp3-capture-server.py"
FLOW_RUNNER = ROOT / "tests/harness/wp3_flow.py"
TLS_METADATA_HELPER = ROOT / "tests/harness/wp3_tls_metadata.py"
TLS_METADATA_TESTS = ROOT / "tests/test_wp3_tls_metadata.py"
QUERY_GUARD_TESTS = ROOT / "tests/test_wp3_query_guard.py"
PROJECT = "wp3-isolated-api-rs"
VOLUME = "wp3-isolated-api-rs-keycloak-data"
IMAGES = {
    "kong-api": (
        "kong/kong-gateway:3.16.0.0@sha256:e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4",
        "e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4",
    ),
    "keycloak": (
        "quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c",
        "82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c",
    ),
    "pop-verifier": (
        "python:3.11@sha256:db07fba48daaf1c68c03676aadc73866414d25b4c278029f9873c784517613bf",
        "db07fba48daaf1c68c03676aadc73866414d25b4c278029f9873c784517613bf",
    ),
}
HOST_PORTS = (8443, 18443, 18444)
CERTIFICATE_IDS = {
    "44444444-4444-4444-8444-444444444444": "api-introspection",
    "55555555-5555-4555-8555-555555555555": "api-upstream",
}
WP3_CASE_VARIANTS = {
    "SCHEMA-PRIORITY-01": {"exact_3_16_metadata"},
    "RS-QUERY-01": {
        "query_only_token", "query_encoded_name", "query_mixed_case_name",
        "query_dash_alias", "query_duplicate_name", "query_late_name",
        "query_arg_limit_1000", "query_arg_truncated_1001", "harmless_query_control",
    },
    "RS-BODY-01": {"body_only_token"},
    "RS-COOKIE-01": {"cookie_only_token"},
    "RS-AUD-01": {"genuine_api_audience_absent", "restored_positive_control"},
    "RS-SCOPE-01": {"genuine_openid_scope_absent"},
    "RS-ACTIVE-01": {"enabled_control", "disabled_same_token", "restored_control"},
    "POP-01": {"no_client_certificate"},
    "POP-02": {"other_route_certificate"},
    "POP-03": {"outside_ca_certificate"},
    "ERR-01": {"invalid_bearer"},
    "HEADER-CERT-01": {"spoof_alias_duplicates", "headers_101", "headers_999", "headers_1000", "headers_1001"},
    "TLS-RS-01": {"tls_11", "tls_12_only", "weak_cipher", "server_san_mismatch", "untrusted_server_ca"},
    "LEAK-01": {"whole_runtime_lifecycle"},
}
WP3_ROUTE_CASES = {"RS-VALID-01", "RS-INT-AUD-02"}
WP3_EXECUTION_PHASES = {
    "preflight", "crypto_dependency_preflight", "fixture_preflight", "license_presence_check",
    "preparation_receipt_verification", "rendered_state_contract_validation",
    "running_project_inventory", "fixture_transport_setup", "fixture_sensitive_candidate_load",
    "bounded_runtime_readiness",
    "exact_gateway_schema_and_priority_probe", "tls_client_certificate_request_sni_probe",
    "public_issuer_metadata_and_jwks", "ephemeral_keycloak_user_profile_sync",
    "positive_a_b_complete", "negative_matrix_preflight", "negative_auth_location_pop",
    "negative_header_boundary", "negative_audience_negative", "negative_scope_negative",
    "negative_active_transition", "negative_tls_negatives", "negative_matrix_complete",
    "whole_runtime_log_scan", "runtime_complete",
} | {
    f"route_{route}_{phase}"
    for route in ("A", "B")
    for phase in (
        "authorization", "token_exchange", "token_signature_and_claim_validation",
        "dedicated_mtls_introspection", "api_tls_and_authorization",
        "upstream_mtls_and_header_evidence",
    )
}
WP3_EXECUTION_LAYERS = {
    "harness", "harness_or_transport", "isolated_positive_a_b", "isolated_runtime_partial",
    "isolated_runtime_full",
}
WP3_SCHEMA_PROBE_STAGES = {
    "not_started", "admin_isolation", "resty_client_preflight", "root_get",
    "gateway_version", "plugin_inventory", "plugin_metadata", "plugin_schema", "complete",
}
WP3_SCHEMA_PROBE_REASONS = {
    "not_started", "pending", "none", "admin_isolation_failed", "resty_binary_missing",
    "resty_http_module_missing", "resty_client_failed", "resty_client_timeout",
    "resty_connect_failed", "resty_request_failed", "admin_redirect_rejected",
    "admin_status_rejected", "admin_body_read_failed", "admin_body_too_large",
    "admin_response_malformed", "gateway_version_mismatch", "plugin_inventory_missing",
    "plugin_metadata_incomplete", "plugin_version_malformed", "plugin_priority_mismatch",
    "plugin_schema_fields_incomplete", "tls_request_enum_mismatch",
}
WP3_SCHEMA_PROBE_PLUGINS = {"none", "pre-function", "openid-connect", "tls-handshake-modifier", "tls-metadata-headers"}
WP3_LOG_SERVICES = {"keycloak", "kong-api", "pop-verifier"}
WP3_LOG_FAILURE_REASONS = {
    "none", "container_inventory_unavailable", "log_stream_unavailable",
    "log_read_failed", "time_limit_exceeded", "byte_limit_exceeded",
}
WP3_LOG_PATTERN_CATEGORIES = {
    "private_key_pem", "bearer_authorization", "cookie_or_forwarded_certificate",
    "client_assertion_form", "oauth_token_field", "jwt_shape",
}
WP3_LOG_CANDIDATE_SOURCES = {
    "unclassified_callsite", "fixture_pki_inventory", "fixture_account_inventory",
    "runtime_role_inventory", "oauth_form_submission", "oauth_route_grant",
    "oauth_authorization_state", "oauth_par_response", "oauth_token_response",
    "oauth_verified_access_token", "oauth_introspection_response", "oauth_admin_bearer",
    "oauth_browser_cookie_jar", "api_request_target", "api_request_body",
    "api_request_header", "api_caller_spoof_header", "api_invalid_bearer_fixture",
    "api_audience_fixture", "api_scope_fixture", "api_active_transition",
    "api_header_fixture", "public_protocol_inventory", "public_fixture_inventory",
    "explicit_candidate_input",
}
WP3_LOG_CANDIDATE_FIELDS = {
    "unkeyed_value", "other", "access_token", "id_token", "refresh_token",
    "authorization_code", "session_code", "state", "nonce", "pkce_verifier", "pkce_challenge",
    "par_request_uri", "cookie_value", "admin_bearer", "client_assertion",
    "client_assertion_type", "api_query", "api_body", "authorization_header",
    "spoof_header", "username", "password", "issuer", "audience", "scope",
    "department", "route", "certificate_thumbprint", "certificate_file",
    "private_key_file", "license_material", "token_field_other", "session_state",
    "session_id", "sid", "subject", "sub", "object_id", "id", "client_id",
    "redirect_uri", "azp", "preferred_username", "name", "email", "auth_time", "jti",
    "form_field_name",
}
WP3_LOG_MATCH_CONTEXTS = {
    "oauth_token_endpoint_request", "oauth_par_endpoint_request",
    "oauth_authorization_endpoint_request", "api_query_access_token_request",
    "keycloak_introspection_token_error",
    "api_resource_request", "other_service_log_context", "unclassified_log_context",
}
WP3_CASE_PHASES = {
    "not_started", "authorization", "token_exchange", "token_signature_and_claim_validation",
    "dedicated_mtls_introspection", "api_tls_and_authorization", "upstream_mtls_and_header_evidence",
    "separate_runtime_phase", "exact_runtime_admin_metadata", "api_http_authorization",
    "api_pop_rejection", "api_header_boundary", "upstream_capture_evidence",
    "request_wire_header_count", "gateway_header_limit",
    "request_parser_rejected_before_gateway_policy", "nginx_parser_header_limit", "audience_mapper_mutation", "mapper_lookup",
    "genuine_oauth_token_issuance", "direct_mtls_introspection", "api_audience_rejection",
    "audience_mapper_restore", "audience_restore_token_validation", "audience_restore_introspection",
    "audience_restore_positive_control", "authorization_scope_profile_only", "genuine_scope_oauth_grant",
    "required_scope_rejection", "same_token_active_check", "enabled_control", "enabled_user_lookup",
    "disable_fixture_user", "disabled_same_token_introspection", "disabled_same_token_api_request",
    "fixture_restore", "fixture_not_mutated", "client_offer_unavailable", "tls_positive_control",
    "tls_negative", "post_negative_positive_control", "peer_alert_protocol_version",
    "peer_alert_handshake_failure", "peer_alert_insufficient_security", "server_san_mismatch",
    "server_untrusted_ca", "client_tls_configuration", "transport", "other_tls_error",
    "whole_runtime_log_scan", "startup_logs_only_no_api_traffic", "negative_auth_location_pop", "negative_header_boundary",
    "negative_audience_negative", "negative_scope_negative", "negative_active_transition",
    "negative_tls_negatives", "server_certificate_validation", "tls_handshake", "upstream_capture",
    "active_check", "keycloak", "token_validation", "api_gateway", "gateway+upstream_capture",
    "api_gateway_tls",
}


class PreviewError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreviewError(message)


def command(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, cwd=ROOT, env=env, check=False, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        raise PreviewError("a required local preparation command failed") from None


def _tcp_port_has_open_owner(port: int) -> bool:
    # Inspect every open TCP descriptor using this port, not just listeners.
    # Kernel TIME_WAIT state has no process-owned descriptor; a bound socket or
    # established connection does and must remain a collision.
    result = command(["lsof", "-nP", f"-iTCP:{port}"])
    if result.returncode == 0 and result.stdout.strip() and not result.stderr.strip():
        return True
    if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
        return False
    raise PreviewError("could not confirm isolated preview TCP socket state")


def require_loopback_port_free(port: int) -> None:
    """Reject active listeners while allowing a proven TIME_WAIT-only bind race."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
        return
    except OSError as error:
        if error.errno not in {98, 48, 10048, 1, 13}:  # EADDRINUSE / sandbox EPERM / EACCES
            raise PreviewError(f"could not inspect isolated preview port {port}") from None
    finally:
        probe.close()

    if _tcp_port_has_open_owner(port):
        raise PreviewError(f"required isolated preview port {port} is already in use")

    # A closed callback connection can leave the local address in TIME_WAIT.
    # Confirm that SO_REUSEADDR can bind it; an active listener was already
    # rejected above and process-owned bound/connected sockets were rejected
    # by the all-descriptor lsof check.
    reuse_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        reuse_probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        reuse_probe.bind(("127.0.0.1", port))
    except OSError as error:
        if error.errno in {98, 48, 10048}:
            raise PreviewError(f"required isolated preview port {port} is already in use") from None
        raise PreviewError(f"could not inspect isolated preview port {port}") from None
    finally:
        reuse_probe.close()


def require_ports_free() -> None:
    for port in HOST_PORTS:
        require_loopback_port_free(port)


def require_isolated_project_absent() -> None:
    daemon = command(["docker", "info", "--format", "{{.ServerVersion}}"])
    require(daemon.returncode == 0 and bool(daemon.stdout.strip()), "Docker daemon is unavailable")
    containers = command([
        "docker", "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"
    ])
    require(containers.returncode == 0, "could not inspect the dedicated WP3 Compose project")
    require(not containers.stdout.strip(), "refusing to reuse an existing WP3 isolated runtime container")
    volumes = command([
        "docker", "volume", "ls", "--quiet", "--filter", f"name={VOLUME}"
    ])
    require(volumes.returncode == 0, "could not inspect the dedicated WP3 Compose volume")
    require(VOLUME not in {line.strip() for line in volumes.stdout.splitlines()},
            "refusing to reuse an existing WP3 isolated runtime volume")


def inspect_images() -> dict[str, dict[str, str]]:
    observed = {}
    for service, (reference, digest) in IMAGES.items():
        result = command(["docker", "image", "inspect", reference])
        require(result.returncode == 0, f"pinned {service} image is not available in the local image cache")
        try:
            image = json.loads(result.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            raise PreviewError(f"pinned {service} image metadata is malformed") from None
        repo_digests = image.get("RepoDigests")
        require(
            image.get("Architecture") == "arm64"
            and isinstance(repo_digests, list)
            and any(isinstance(item, str) and item.endswith("@sha256:" + digest) for item in repo_digests),
            f"pinned {service} image architecture or digest does not match",
        )
        observed[service] = {"digest": digest, "architecture": image["Architecture"]}
    return observed


def load_wp2_preparer():
    source = ROOT / "tests/harness/prepare_wp2_preview.py"
    spec = importlib.util.spec_from_file_location("wp2_preview_preparer", source)
    if spec is None or spec.loader is None:
        raise PreviewError("WP2 isolated fixture generator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_pem(name: str) -> str:
    path = PREVIEW / "pki" / name
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise PreviewError("fresh fixture certificate material is missing or has broad permissions")
    return path.read_text(encoding="ascii")


def escaped_pem(name: str) -> str:
    return json.dumps(read_pem(name), ensure_ascii=True)[1:-1]


def runtime_role_values() -> dict[str, str]:
    return {
        "DECK_FAPI_CA_CERT_YAML": escaped_pem("ca.crt"),
        "DECK_API_INTROSPECTION_CERT_YAML": escaped_pem("api-introspection.crt"),
        "API_INTROSPECTION_KEY": read_pem("api-introspection.key"),
        "DECK_API_UPSTREAM_CERT_YAML": escaped_pem("api-upstream.crt"),
        "API_UPSTREAM_KEY": read_pem("api-upstream.key"),
    }


def load_runtime_role_values() -> dict[str, str]:
    path = PREVIEW / "runtime-api.json"
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise PreviewError("private WP3 API role input file is absent or unsafe")
    if path.stat().st_size > 32_768:
        raise PreviewError("private WP3 API role input file exceeds its size limit")
    try:
        role_values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PreviewError("private WP3 API role input file is malformed") from None
    if not isinstance(role_values, dict) or set(role_values) != set(runtime_role_values()):
        raise PreviewError("private WP3 API role input fields changed")
    if role_values != runtime_role_values():
        raise PreviewError("private WP3 API role inputs do not match the fresh fixture")
    return role_values


def openssl_der(pem: str) -> bytes:
    result = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-outform", "DER"],
        input=pem.encode("ascii"), capture_output=True, check=False, timeout=10,
    )
    if result.returncode != 0 or not result.stdout:
        raise PreviewError("fresh public certificate failed local X.509 parsing")
    return result.stdout


def canonical_sha256(value: object) -> str:
    content = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def render_gateway_config(role_values: dict[str, str]) -> dict:
    rendered = PREVIEW / ".deck-rendered.yml"
    environment = os.environ.copy()
    environment.update(role_values)
    render = command([
        "deck", "file", "render", "--populate-env-vars", "--format", "yaml",
        "-o", str(rendered), str(ROOT / "kong/api-gateway.yaml"),
    ], env=environment)
    require(render.returncode == 0 and rendered.is_file(), "decK could not render the API runtime fixture")
    os.chmod(rendered, 0o600)
    try:
        state = yaml.safe_load(rendered.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        raise PreviewError("decK rendered API runtime fixture is malformed") from None
    require(isinstance(state, dict), "decK rendered API runtime fixture is not a mapping")
    certificates = state.get("certificates")
    require(isinstance(certificates, list) and len(certificates) == 2,
            "rendered API runtime fixture certificate set changed")
    role_keys = {
        "44444444-4444-4444-8444-444444444444": "API_INTROSPECTION_KEY",
        "55555555-5555-4555-8555-555555555555": "API_UPSTREAM_KEY",
    }
    for certificate in certificates:
        if not isinstance(certificate, dict) or certificate.get("id") not in role_keys:
            raise PreviewError("rendered API runtime fixture certificate identity changed")
        expected_ref = "{vault://env/" + role_keys[certificate["id"]] + "}"
        require(certificate.get("key") == expected_ref,
                "decK rendering changed a fresh API certificate Vault reference")
        name = CERTIFICATE_IDS[certificate["id"]]
        require(
            openssl_der(certificate.get("cert", "")) == openssl_der(read_pem(f"{name}.crt")),
            "decK template expansion changed a fresh API public certificate",
        )
    config_path = PREVIEW / "api-runtime.yml"
    with config_path.open("x", encoding="utf-8") as output:
        yaml.safe_dump(state, output, sort_keys=False, allow_unicode=True)
    os.chmod(config_path, 0o600)
    rendered.unlink()
    return state


def compose_config_check(role_values: dict[str, str]) -> None:
    if not os.environ.get("KONG_LICENSE_DATA"):
        raise PreviewError("Kong license is absent from the current process environment")
    environment = os.environ.copy()
    environment["API_INTROSPECTION_KEY"] = role_values["API_INTROSPECTION_KEY"]
    environment["API_UPSTREAM_KEY"] = role_values["API_UPSTREAM_KEY"]
    result = command([
        "docker", "compose", "--env-file", "/dev/null",
        "--project-directory", str(ROOT), "--project-name", PROJECT,
        "-f", str(COMPOSE_FILE), "config", "--quiet",
    ], env=environment)
    if result.returncode != 0:
        raise PreviewError("isolated WP3 Compose configuration validation failed")


def issue_outside_ca_client_identity() -> None:
    """Create a fresh self-signed client identity for a single POP negative."""
    key_path = PREVIEW / "pki/outside-ca-client.key"
    cert_path = PREVIEW / "pki/outside-ca-client.crt"
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-days", "30", "-subj", "/CN=wp3-outside-ca-client",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=clientAuth",
            "-keyout", str(key_path), "-out", str(cert_path),
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
    )
    if result.returncode != 0 or not key_path.is_file() or not cert_path.is_file():
        raise PreviewError("fresh outside-CA client identity generation failed")
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o600)


def write_private_receipt(receipt: dict) -> None:
    evidence = PREVIEW / "evidence"
    evidence.mkdir(mode=0o700)
    os.chmod(evidence, 0o700)
    path = evidence / "wp3-preparation-receipt.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    os.chmod(path, 0o600)


def fixture_file_digests() -> dict[str, str]:
    digests = {}
    for path in sorted(PREVIEW.rglob("*")):
        if path.is_symlink():
            raise PreviewError("WP3 fixture contains an unexpected symlink")
        if path.is_file():
            relative = path.relative_to(PREVIEW).as_posix()
            if relative in {
                "evidence/wp3-preparation-receipt.json",
                "evidence/wp3-runtime-receipt.json",
            }:
                continue
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise PreviewError("WP3 fixture file has unsafe permissions")
            digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def verify_preparation_receipt() -> dict:
    path = PREVIEW / "evidence/wp3-preparation-receipt.json"
    if PREVIEW.is_symlink() or not path.is_file() or path.is_symlink():
        raise PreviewError("WP3 preparation receipt is absent or unsafe")
    if stat.S_IMODE(path.stat().st_mode) != 0o600 or path.stat().st_size > 16_384:
        raise PreviewError("WP3 preparation receipt permissions or size are invalid")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PreviewError("WP3 preparation receipt is malformed") from None
    expected = {
        "schema_version", "scope", "images", "host_ports", "upstream_capture",
        "listener_sni", "oidc_public_issuer", "keycloak_harness_target",
        "keycloak_advertised_hostname", "license_present", "normal_env_loaded",
        "pki_and_accounts_generated_fresh", "api_runtime_config_rendered",
        "api_runtime_state_sha256", "runtime_role_inputs_sha256",
        "rendered_runtime_config_sha256", "rendered_runtime_file_sha256",
        "compose_file_sha256", "capture_helper_sha256", "flow_runner_sha256",
        "tls_metadata_helper_sha256", "tls_metadata_test_sha256", "fixture_files_sha256",
        "query_guard_test_sha256",
        "compose_config_validated_quietly", "fixture_only_admin_loopback",
        "fixture_only_admin_gui_disabled", "outside_ca_client_certificate_prepared",
        "containers_started", "konnect_read_or_write_performed",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise PreviewError("WP3 preparation receipt fields are malformed")
    role_values = load_runtime_role_values()
    state_path = ROOT / "kong/api-gateway.yaml"
    runtime_path = PREVIEW / "api-runtime.yml"
    try:
        rendered_state = yaml.safe_load(runtime_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        raise PreviewError("WP3 rendered runtime config is malformed") from None
    booleans = {
        "license_present": True,
        "normal_env_loaded": False,
        "pki_and_accounts_generated_fresh": True,
        "api_runtime_config_rendered": True,
        "compose_config_validated_quietly": True,
        "fixture_only_admin_loopback": True,
        "fixture_only_admin_gui_disabled": True,
        "outside_ca_client_certificate_prepared": True,
        "containers_started": False,
        "konnect_read_or_write_performed": False,
    }
    if any(receipt.get(name) is not value for name, value in booleans.items()):
        raise PreviewError("WP3 preparation receipt lifecycle flags do not match")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("scope") != "wp3-api-runtime-isolated-preview-preparation"
        or receipt.get("api_runtime_state_sha256") != hashlib.sha256(state_path.read_bytes()).hexdigest()
        or receipt.get("runtime_role_inputs_sha256") != canonical_sha256(role_values)
        or receipt.get("rendered_runtime_config_sha256") != canonical_sha256(rendered_state)
        or receipt.get("rendered_runtime_file_sha256") != hashlib.sha256(runtime_path.read_bytes()).hexdigest()
        or receipt.get("compose_file_sha256") != hashlib.sha256(COMPOSE_FILE.read_bytes()).hexdigest()
        or CAPTURE_HELPER.is_symlink()
        or receipt.get("capture_helper_sha256") != hashlib.sha256(CAPTURE_HELPER.read_bytes()).hexdigest()
        or FLOW_RUNNER.is_symlink()
        or receipt.get("flow_runner_sha256") != hashlib.sha256(FLOW_RUNNER.read_bytes()).hexdigest()
        or TLS_METADATA_HELPER.is_symlink()
        or receipt.get("tls_metadata_helper_sha256") != hashlib.sha256(TLS_METADATA_HELPER.read_bytes()).hexdigest()
        or TLS_METADATA_TESTS.is_symlink()
        or receipt.get("tls_metadata_test_sha256") != hashlib.sha256(TLS_METADATA_TESTS.read_bytes()).hexdigest()
        or QUERY_GUARD_TESTS.is_symlink()
        or receipt.get("query_guard_test_sha256") != hashlib.sha256(QUERY_GUARD_TESTS.read_bytes()).hexdigest()
        or receipt.get("fixture_files_sha256") != fixture_file_digests()
        or receipt.get("images") != inspect_images()
    ):
        raise PreviewError("WP3 preparation receipt no longer matches fixture, state, or pinned images")
    if receipt.get("host_ports") != {"keycloak": 18444, "api_gateway": 18443, "oauth_callback": 8443}:
        raise PreviewError("WP3 preparation receipt host port contract changed")
    if (
        receipt.get("listener_sni") != ["localhost", "kong-api"]
        or receipt.get("oidc_public_issuer") != "https://localhost:8444/realms/fapi-demo"
        or receipt.get("keycloak_harness_target") != "https://localhost:18444"
        or receipt.get("keycloak_advertised_hostname") != "https://localhost:8444"
    ):
        raise PreviewError("WP3 preparation receipt issuer or SNI contract changed")
    if receipt.get("upstream_capture") != {
        "service_name": "pop-verifier", "container_port": 9443, "host_published": False
    }:
        raise PreviewError("WP3 preparation receipt upstream capture contract changed")
    return receipt


def validate_runtime_receipt(payload: object) -> None:
    """Fail closed on every persisted WP3 case, probe, and count field."""
    required = {
        "schema_version", "scope", "result", "host_ports", "images", "cases",
        "tls", "capture", "log_scan", "containers_started", "konnect_read_or_write_performed",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise PreviewError("WP3 runtime receipt fields do not match the private whitelist")
    if (
        payload.get("schema_version") != 1
        or payload.get("scope") != "wp3-api-runtime-isolated-validation"
        or not isinstance(payload.get("result"), str)
        or payload.get("result") not in {"pass", "fail", "partial"}
        or type(payload.get("containers_started")) is not bool
        or payload.get("konnect_read_or_write_performed") is not False
        or payload.get("host_ports") != {"keycloak": 18444, "api_gateway": 18443, "oauth_callback": 8443}
    ):
        raise PreviewError("WP3 runtime receipt lifecycle metadata is invalid")
    if payload.get("result") == "pass" and payload.get("containers_started") is not True:
        raise PreviewError("WP3 passing receipt requires a started isolated runtime")
    images = payload.get("images")
    if not isinstance(images, dict) or set(images) != set(IMAGES):
        raise PreviewError("WP3 runtime receipt image set is invalid")
    for service, (reference, digest) in IMAGES.items():
        if images[service] != {"digest": digest, "architecture": "arm64"}:
            raise PreviewError("WP3 runtime receipt image metadata is invalid")

    cases = payload.get("cases")
    if not isinstance(cases, dict) or set(cases) != {"scope", "execution", "acceptance", "full_wp3_acceptance"}:
        raise PreviewError("WP3 runtime acceptance record fields are invalid")
    if not isinstance(cases["scope"], str) or cases["scope"] not in {"wp3_positive_and_required_negative_matrix", "positive_a_b_only"}:
        raise PreviewError("WP3 runtime acceptance scope is invalid")
    if not isinstance(cases["full_wp3_acceptance"], str) or cases["full_wp3_acceptance"] not in {"pass", "fail", "partial", "not_run", "needs_design"}:
        raise PreviewError("WP3 full acceptance status is invalid")
    execution = cases["execution"]
    execution_fields = {
        "scope", "outcome", "phase", "layer", "http_status", "host_runtime", "schema_probe",
        "schema_probe_diagnostic", "state_contract", "header_parser_metadata",
        "effective_inbound_tls_policy", "negative_group_failures",
    }
    if not isinstance(execution, dict) or set(execution) != execution_fields:
        raise PreviewError("WP3 runtime execution metadata fields are invalid")
    if not isinstance(execution.get("outcome"), str) or execution.get("outcome") not in {"running", "pass", "fail", "partial"}:
        raise PreviewError("WP3 runtime execution outcome is invalid")
    if (
        execution.get("scope") != cases["scope"]
        or not isinstance(execution.get("phase"), str)
        or execution.get("phase") not in WP3_EXECUTION_PHASES
        or not isinstance(execution.get("layer"), str)
        or execution.get("layer") not in WP3_EXECUTION_LAYERS
    ):
        raise PreviewError("WP3 runtime execution phase metadata is invalid")
    status = execution.get("http_status")
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise PreviewError("WP3 runtime execution HTTP status is invalid")
    runtime = execution.get("host_runtime")
    if runtime is not None:
        if not isinstance(runtime, dict) or set(runtime) != {"interpreter", "python_version", "pyjwt_version", "pyjwt_importable", "cryptography_version", "cryptography_importable"}:
            raise PreviewError("WP3 host runtime dependency metadata is invalid")
        if not isinstance(runtime["interpreter"], str) or len(runtime["interpreter"]) > 256 or not re.fullmatch(r"[A-Za-z0-9_./-]+", runtime["interpreter"]):
            raise PreviewError("WP3 host runtime interpreter label is invalid")
        for name in ("python_version", "pyjwt_version", "cryptography_version"):
            if not isinstance(runtime[name], str) or len(runtime[name]) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", runtime[name]):
                raise PreviewError("WP3 host runtime version label is invalid")
        if type(runtime["pyjwt_importable"]) is not bool or type(runtime["cryptography_importable"]) is not bool:
            raise PreviewError("WP3 host runtime dependency flags are invalid")
    probe = execution.get("schema_probe")
    if probe is not None:
        if not isinstance(probe, dict) or set(probe) != {"gateway_version", "plugins", "fields", "admin_host_published", "tls_policy"}:
            raise PreviewError("WP3 exact Gateway schema probe fields are invalid")
        if probe.get("gateway_version") != "3.16.0.0" or probe.get("admin_host_published") is not False:
            raise PreviewError("WP3 exact Gateway schema probe contract is invalid")
        plugin_data = probe.get("plugins")
        if not isinstance(plugin_data, dict) or set(plugin_data) != {"pre-function", "openid-connect", "tls-handshake-modifier", "tls-metadata-headers"}:
            raise PreviewError("WP3 loaded plugin metadata fields are invalid")
        for name, expected_priority in {"pre-function": 1000000, "openid-connect": 1050, "tls-handshake-modifier": 997, "tls-metadata-headers": 996}.items():
            item = plugin_data[name]
            if not isinstance(item, dict) or set(item) != {"version", "priority"} or type(item["priority"]) is not int or item["priority"] != expected_priority or not isinstance(item["version"], str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", item["version"]):
                raise PreviewError("WP3 loaded stock plugin metadata is invalid")
        fields = probe.get("fields")
        if not isinstance(fields, dict) or set(fields) != {"openid-connect", "tls-handshake-modifier", "tls-metadata-headers"}:
            raise PreviewError("WP3 plugin schema field map is invalid")
        expected_fields = {
            "openid-connect": {"cache_introspection", "cache_tokens", "introspection_check_active", "upstream_headers", "audience_required", "scopes_required", "bearer_token_param_type", "proof_of_possession_mtls", "proof_of_possession_auth_methods_validation", "tls_client_auth_cert_id", "upstream_access_token_header", "issuer", "introspection_endpoint", "mtls_introspection_endpoint", "client_auth", "auth_methods"},
            "tls-handshake-modifier": {"tls_client_certificate"},
            "tls-metadata-headers": {"client_cert_header_name", "inject_client_cert_details"},
        }
        for plugin, names in expected_fields.items():
            if not isinstance(fields[plugin], dict) or set(fields[plugin]) != names:
                raise PreviewError("WP3 plugin schema allowlist is invalid")
            for name, item in fields[plugin].items():
                if not isinstance(item, dict) or set(item) != {"present", "type", "enum"} or item["present"] is not True or not isinstance(item["type"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", item["type"]) or not isinstance(item["enum"], list) or len(item["enum"]) > 16 or any(value not in {"REQUEST", "ON", "OFF", "header", "cookie", "query", "form", "introspection", "tls_client_auth", "strict", "true", "false"} for value in item["enum"]):
                    raise PreviewError("WP3 plugin schema field metadata is invalid")
        if fields["tls-handshake-modifier"]["tls_client_certificate"]["enum"] != ["REQUEST"]:
            raise PreviewError("WP3 TLS handshake mode metadata is invalid")
        tls_policy = probe["tls_policy"]
        if (
            not isinstance(tls_policy, dict)
            or set(tls_policy) != {"metadata_source", "cipher_suite", "protocols"}
            or tls_policy.get("metadata_source") not in {"admin_root_configuration", "not_proven"}
            or tls_policy.get("cipher_suite") not in {"modern", "not_proven"}
            or tls_policy.get("protocols") not in ([], ["TLSv1.3"])
        ):
            raise PreviewError("WP3 allowlisted TLS policy metadata is invalid")
    effective_tls = execution.get("effective_inbound_tls_policy")
    if (probe is None) != (effective_tls is None):
        raise PreviewError("WP3 effective TLS metadata must accompany the completed Admin schema probe")
    if effective_tls is not None:
        tls_metadata_fields = {
            "metadata_source", "image_binding", "openresty_version", "cipher_suite", "protocols",
            "active_ssl_protocol_directive_count", "admin_requested_protocols_status",
            "admin_requested_protocols", "admin_protocols_are_effective", "effective_inbound_tls_proven",
        }
        if not isinstance(effective_tls, dict) or set(effective_tls) != tls_metadata_fields:
            raise PreviewError("WP3 effective inbound TLS metadata fields are invalid")
        if (
            effective_tls.get("metadata_source") not in {"validated_nginx_t_dump", "not_proven"}
            or effective_tls.get("image_binding") not in {"pinned_gateway_image", "not_proven"}
            or effective_tls.get("openresty_version") not in {"pinned_openresty_1_29_2_5", "not_proven"}
            or effective_tls.get("cipher_suite") not in {"modern", "not_proven"}
            or effective_tls.get("protocols") not in ([], ["TLSv1.3"])
            or type(effective_tls.get("active_ssl_protocol_directive_count")) is not int
            or not 0 <= effective_tls["active_ssl_protocol_directive_count"] <= 16
            or effective_tls.get("admin_requested_protocols_status") not in {"reported", "not_proven"}
            or effective_tls.get("admin_requested_protocols") not in ([], ["TLSv1.2"], ["TLSv1.3"], ["TLSv1.2", "TLSv1.3"], ["TLSv1.3", "TLSv1.2"])
            or type(effective_tls.get("admin_protocols_are_effective")) is not bool
            or effective_tls.get("admin_protocols_are_effective") is not False
            or type(effective_tls.get("effective_inbound_tls_proven")) is not bool
        ):
            raise PreviewError("WP3 effective inbound TLS metadata values are invalid")
        if effective_tls.get("admin_requested_protocols_status") == "not_proven" and effective_tls.get("admin_requested_protocols"):
            raise PreviewError("WP3 unproven Admin TLS protocols contain an unclassified value")
        if effective_tls.get("admin_requested_protocols_status") == "reported" and not effective_tls.get("admin_requested_protocols"):
            raise PreviewError("WP3 reported Admin TLS protocols are empty")
        admin_tls = probe["tls_policy"]
        if not effective_tls_matches_admin_observation(effective_tls, admin_tls):
            raise PreviewError("WP3 effective TLS evidence disagrees with separately observed Admin settings")
        if effective_tls.get("effective_inbound_tls_proven") is True and (
            effective_tls.get("metadata_source") != "validated_nginx_t_dump"
            or effective_tls.get("image_binding") != "pinned_gateway_image"
            or effective_tls.get("openresty_version") != "pinned_openresty_1_29_2_5"
            or effective_tls.get("cipher_suite") != "modern"
            or effective_tls.get("protocols") != ["TLSv1.3"]
            or effective_tls.get("active_ssl_protocol_directive_count", 0) < 1
        ):
            raise PreviewError("WP3 effective inbound TLS proof lacks exact image, config, and policy evidence")
    header_parser = execution.get("header_parser_metadata")
    if header_parser is not None:
        if (
            not isinstance(header_parser, dict)
            or set(header_parser) != {"nginx_version", "max_headers_override_absent", "default_header_limit", "source"}
            or header_parser.get("nginx_version") not in {"openresty/1.29.2.5", "not_proven"}
            or type(header_parser.get("max_headers_override_absent")) is not bool
            or header_parser.get("default_header_limit") not in {None, 1000}
            or header_parser.get("source") not in {"pinned_image_default_1000", "not_proven"}
        ):
            raise PreviewError("WP3 fixed NGINX parser metadata is invalid")
        exact_parser_proof = (
            header_parser["nginx_version"] == "openresty/1.29.2.5"
            and header_parser["max_headers_override_absent"] is True
            and header_parser["default_header_limit"] == 1000
            and header_parser["source"] == "pinned_image_default_1000"
        )
        if (header_parser["source"] == "pinned_image_default_1000") != exact_parser_proof:
            raise PreviewError("WP3 NGINX parser metadata proof is inconsistent")
    probe_diagnostic = execution.get("schema_probe_diagnostic")
    if (
        not isinstance(probe_diagnostic, dict)
        or set(probe_diagnostic) != {"stage", "reason", "plugin"}
        or probe_diagnostic.get("stage") not in WP3_SCHEMA_PROBE_STAGES
        or probe_diagnostic.get("reason") not in WP3_SCHEMA_PROBE_REASONS
        or probe_diagnostic.get("plugin") not in WP3_SCHEMA_PROBE_PLUGINS
    ):
        raise PreviewError("WP3 schema probe diagnostic is invalid")
    if (
        probe_diagnostic["stage"] == "complete"
        and (probe_diagnostic["reason"] != "none" or probe_diagnostic["plugin"] != "none" or probe is None)
    ) or (probe is not None and probe_diagnostic["stage"] != "complete"):
        raise PreviewError("WP3 schema probe completion metadata is inconsistent")
    if probe_diagnostic["stage"] == "not_started" and (
        probe_diagnostic["reason"] != "not_started" or probe_diagnostic["plugin"] != "none"
    ):
        raise PreviewError("WP3 schema probe initial diagnostic is invalid")
    state_contract = execution.get("state_contract")
    if state_contract is not None:
        state_fields = {
            "route_plugin_inventory_exact", "upstream_target_exact", "upstream_tls_verified",
            "upstream_client_certificate_bound", "foundation_ca_reused", "dedicated_mtls_introspection",
            "header_sanitizer_bound", "query_auth_guard_bound", "trusted_client_cert_metadata",
            "introspection_active_required", "introspection_cache_disabled", "token_cache_disabled",
            "authorization_header_only", "required_api_audience", "required_openid_scope",
            "public_token_issuer_preserved", "authorization_header_forwarded", "route_https_only",
            "tls_handshake_requests_client_certificate",
        }
        if not isinstance(state_contract, dict) or set(state_contract) != state_fields or any(value is not True for value in state_contract.values()):
            raise PreviewError("WP3 rendered-state boolean contract is invalid")
    failures = execution.get("negative_group_failures")
    if not isinstance(failures, list) or len(failures) > 16 or any(name not in {"auth_location_pop", "header_boundary", "audience_negative", "scope_negative", "active_transition", "tls_negatives"} for name in failures):
        raise PreviewError("WP3 negative phase summary is invalid")

    rows = cases.get("acceptance")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise PreviewError("WP3 acceptance case count is invalid")
    outcomes = {"not_run", "running", "pass", "fail", "needs_design"}
    challenge_values = {"not_run", "not_applicable", "missing_header", "error_absent", "malformed", "invalid_token", "insufficient_scope"}
    layers = {"not_run", "harness", "keycloak", "token_validation", "api_gateway", "api_gateway_tls", "api_gateway_tls_or_harness", "keycloak_tls_or_harness", "server_certificate_validation", "tls_handshake", "upstream_capture", "gateway+upstream_capture", "active_check", "client_tls_configuration", "transport", "nginx_parser"}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("case_id"), str):
            raise PreviewError("WP3 acceptance case identity is invalid")
        allowed = {"case_id", "outcome", "phase", "layer", "http_status", "rfc6750_challenge"}
        if isinstance(row, dict) and "route" in row:
            allowed.add("route")
        if isinstance(row, dict) and "variant" in row:
            allowed.add("variant")
        if isinstance(row, dict) and row.get("case_id") == "TLS-RS-01":
            allowed.update({
                "client_hello_offered", "offered_protocols", "tls_policy_proven",
                "negotiated_protocol", "negotiated_cipher", "upstream_unchanged",
                "tls_failure_reason", "tls_verify_code", "post_negative_valid_control",
            })
        if isinstance(row, dict) and row.get("case_id") == "HEADER-CERT-01":
            allowed.update({
                "input_wire_header_count", "upstream_header_count", "parser_source",
                "wire_grammar_valid", "upstream_unchanged", "response_scan_clean",
                "post_negative_valid_control", "parser_log_scan_completed",
                "parser_error_marker_delta", "parser_api_request_marker_delta",
            })
        if isinstance(row, dict) and row.get("case_id") == "RS-QUERY-01":
            allowed.update({"request_target_byte_count", "query_argument_count"})
        if set(row) != allowed:
            raise PreviewError("WP3 acceptance case fields are invalid")
        if row["case_id"] in WP3_ROUTE_CASES:
            if "route" not in row or "variant" in row or row["route"] not in {"A", "B"}:
                raise PreviewError("WP3 route acceptance case identity is invalid")
        elif row["case_id"] in WP3_CASE_VARIANTS:
            if "variant" not in row or "route" in row or row["variant"] not in WP3_CASE_VARIANTS[row["case_id"]]:
                raise PreviewError("WP3 variant acceptance case identity is invalid")
        else:
            raise PreviewError("WP3 acceptance case is outside the fixed review matrix")
        if (
            not isinstance(row.get("outcome"), str)
            or row.get("outcome") not in outcomes
            or not isinstance(row.get("layer"), str)
            or row.get("layer") not in layers
            or not isinstance(row.get("rfc6750_challenge"), str)
            or row.get("rfc6750_challenge") not in challenge_values
        ):
            raise PreviewError("WP3 acceptance outcome, layer, or challenge is invalid")
        if row.get("phase") not in WP3_CASE_PHASES:
            raise PreviewError("WP3 acceptance phase is invalid")
        if row["case_id"] == "RS-QUERY-01":
            target_bytes = row.get("request_target_byte_count")
            argument_count = row.get("query_argument_count")
            if (type(target_bytes) is not int and target_bytes != "not_run") or (type(target_bytes) is int and not 1 <= target_bytes <= 7680):
                raise PreviewError("WP3 query request-target byte count is invalid")
            if (type(argument_count) is not int and argument_count != "not_run") or (type(argument_count) is int and not 1 <= argument_count <= 1001):
                raise PreviewError("WP3 query argument count is invalid")
        status = row.get("http_status")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise PreviewError("WP3 acceptance HTTP status is invalid")
        if row["case_id"] == "TLS-RS-01":
            tls_reasons = {
                "not_run", "client_offer_unavailable", "client_hello_missing",
                "target_cipher_not_offered", "peer_alert_protocol_version",
                "peer_alert_handshake_failure", "peer_alert_insufficient_security",
                "server_san_mismatch", "server_untrusted_ca", "client_tls_configuration",
                "transport", "other_tls_error",
            }
            if (type(row.get("client_hello_offered")) is not bool and row.get("client_hello_offered") != "not_run") or not isinstance(row.get("tls_failure_reason"), str) or row.get("tls_failure_reason") not in tls_reasons:
                raise PreviewError("WP3 TLS case offer or failure enum is invalid")
            protocols = row.get("offered_protocols")
            if protocols != "not_run" and (
                not isinstance(protocols, list)
                or len(protocols) > 3
                or any(value not in {"TLSv1.1", "TLSv1.2", "TLSv1.3"} for value in protocols)
                or len(protocols) != len(set(protocols))
            ):
                raise PreviewError("WP3 ClientHello protocol offer metadata is invalid")
            if type(row.get("tls_policy_proven")) is not bool and row.get("tls_policy_proven") != "not_run":
                raise PreviewError("WP3 TLS policy proof flag is invalid")
            if row.get("negotiated_protocol") not in {"TLSv1.3", "not_run"}:
                raise PreviewError("WP3 negotiated TLS protocol is invalid")
            if not isinstance(row.get("negotiated_cipher"), str) or row.get("negotiated_cipher") not in {
                "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256", "not_run",
            }:
                raise PreviewError("WP3 negotiated TLS cipher is invalid")
            if type(row.get("upstream_unchanged")) is not bool and row.get("upstream_unchanged") != "not_run":
                raise PreviewError("WP3 TLS upstream counter evidence is invalid")
            post_control = row.get("post_negative_valid_control")
            if type(post_control) is not bool and post_control != "not_run":
                raise PreviewError("WP3 TLS post-negative control metadata is invalid")
            verify_code = row.get("tls_verify_code")
            if verify_code is not None and (type(verify_code) is not int or verify_code not in {18, 19, 20, 21, 27, 62}):
                raise PreviewError("WP3 TLS verification code is outside the fixed enum")
            if row["outcome"] == "pass" and row["client_hello_offered"] is not True:
                raise PreviewError("WP3 TLS rejection cannot pass without a client offerability proof")
            if row["outcome"] == "pass":
                if post_control is not True:
                    raise PreviewError("WP3 TLS rejection cannot pass without its post-negative valid control")
                if row["variant"] == "tls_11" and row.get("offered_protocols") != ["TLSv1.1"]:
                    raise PreviewError("WP3 TLS 1.1 rejection lacks an exact TLS 1.1 ClientHello offer")
                acceptable_tls_reason = {
                    "tls_11": {"peer_alert_protocol_version", "peer_alert_handshake_failure", "peer_alert_insufficient_security"},
                    "tls_12_only": {"peer_alert_protocol_version"},
                    "weak_cipher": {"peer_alert_protocol_version"},
                    "server_san_mismatch": {"server_san_mismatch"},
                    "untrusted_server_ca": {"server_untrusted_ca"},
                }
                if row["tls_failure_reason"] not in acceptable_tls_reason[row["variant"]]:
                    raise PreviewError("WP3 TLS pass lacks its exact expected peer or verification error")
                if row["variant"] == "server_san_mismatch" and row.get("tls_verify_code") != 62:
                    raise PreviewError("WP3 SAN rejection lacks verification code 62")
                if row["variant"] == "untrusted_server_ca" and row.get("tls_verify_code") not in {18, 19, 20, 21, 27}:
                    raise PreviewError("WP3 untrusted CA rejection lacks a known verification code")
                if row["variant"] in {"tls_12_only", "weak_cipher"}:
                    runtime_tls = execution.get("effective_inbound_tls_policy")
                    runtime_tls_proven = (
                        isinstance(runtime_tls, dict)
                        and runtime_tls.get("metadata_source") == "validated_nginx_t_dump"
                        and runtime_tls.get("image_binding") == "pinned_gateway_image"
                        and runtime_tls.get("openresty_version") == "pinned_openresty_1_29_2_5"
                        and runtime_tls.get("cipher_suite") == "modern"
                        and runtime_tls.get("protocols") == ["TLSv1.3"]
                        and runtime_tls.get("effective_inbound_tls_proven") is True
                    )
                    if (
                        row.get("http_status") is not None
                        or
                        row.get("tls_policy_proven") is not True
                        or runtime_tls_proven is not True
                        or row.get("offered_protocols") != ["TLSv1.2"]
                        or row.get("negotiated_protocol") != "TLSv1.3"
                        or row.get("negotiated_cipher") not in {
                            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                            "TLS_CHACHA20_POLY1305_SHA256",
                        }
                        or row.get("upstream_unchanged") is not True
                    ):
                        raise PreviewError("WP3 TLS 1.2 offer rejection lacks policy, protocol, cipher, or no-upstream evidence")
                    if row["variant"] == "weak_cipher":
                        good_protocol_control = next(
                            (
                                other for other in rows
                                if isinstance(other, dict)
                                and other.get("case_id") == "TLS-RS-01"
                                and other.get("variant") == "tls_12_only"
                            ),
                            None,
                        )
                        if not isinstance(good_protocol_control, dict) or good_protocol_control.get("outcome") != "pass":
                            raise PreviewError("WP3 weak-suite TLS result lacks its independent good TLS 1.2 protocol control")
        if row["case_id"] == "HEADER-CERT-01":
            for name in ("input_wire_header_count", "upstream_header_count"):
                count = row.get(name)
                if count is not None and (type(count) is not int or not 0 <= count <= 4096):
                    raise PreviewError("WP3 header count evidence is invalid")
            if row.get("parser_source") not in {"not_run", "pinned_image_default_1000", "not_proven"}:
                raise PreviewError("WP3 parser source evidence is invalid")
            for name in ("wire_grammar_valid", "upstream_unchanged", "response_scan_clean", "post_negative_valid_control"):
                if type(row.get(name)) is not bool and row.get(name) != "not_run":
                    raise PreviewError("WP3 parser control metadata is invalid")
            if type(row.get("parser_log_scan_completed")) is not bool and row.get("parser_log_scan_completed") != "not_run":
                raise PreviewError("WP3 parser log scan completion is invalid")
            for name in ("parser_error_marker_delta", "parser_api_request_marker_delta"):
                count = row.get(name)
                if count is not None and (type(count) is not int or not 0 <= count <= 1000):
                    raise PreviewError("WP3 parser log marker count is invalid")
            if row["outcome"] == "pass":
                expected_input = {"headers_101": 101, "headers_999": 999, "headers_1000": 1000, "headers_1001": 1001}.get(row["variant"])
                if expected_input is not None and row.get("input_wire_header_count") != expected_input:
                    raise PreviewError("WP3 header boundary result lacks its exact sent wire count")
                if row["variant"] in {"headers_101", "headers_999"} and (
                    row.get("http_status") != 200 or row.get("upstream_header_count") is None
                ):
                    raise PreviewError("WP3 permitted header control lacks actual upstream evidence")
                if row["variant"] == "headers_1000" and (
                    row.get("http_status") != 431 or row.get("upstream_header_count") is not None
                ):
                    raise PreviewError("WP3 over-limit header case did not fail closed with HTTP 431")
                if row["variant"] == "headers_1001":
                    if row.get("http_status") == 431:
                        raise PreviewError("WP3 1001-header HTTP 431 lacks a measured parser or Gateway source")
                    elif row.get("http_status") == 400:
                        parser_metadata = execution.get("header_parser_metadata")
                        parser_metadata_proven = (
                            isinstance(parser_metadata, dict)
                            and parser_metadata.get("nginx_version") == "openresty/1.29.2.5"
                            and parser_metadata.get("max_headers_override_absent") is True
                            and parser_metadata.get("default_header_limit") == 1000
                            and parser_metadata.get("source") == "pinned_image_default_1000"
                        )
                        if (
                            row.get("phase") != "nginx_parser_header_limit"
                            or row.get("layer") != "nginx_parser"
                            or row.get("upstream_header_count") is not None
                            or row.get("parser_source") != "pinned_image_default_1000"
                            or parser_metadata_proven is not True
                            or row.get("wire_grammar_valid") is not True
                            or row.get("upstream_unchanged") is not True
                            or row.get("response_scan_clean") is not True
                            or row.get("post_negative_valid_control") is not True
                            or row.get("parser_log_scan_completed") is not True
                            or row.get("parser_error_marker_delta") != 1
                            or row.get("parser_api_request_marker_delta") != 1
                        ):
                            raise PreviewError("WP3 HTTP 400 parser case lacks complete provenance and controls")
                    else:
                        raise PreviewError("WP3 1001-header result is outside the fixed rejection contract")
        if row["outcome"] == "pass":
            expected_http = {
                "RS-VALID-01": (200, "not_applicable"),
                "RS-INT-AUD-02": (200, "not_applicable"),
                "RS-BODY-01": (401, "invalid_token"),
                "RS-COOKIE-01": (401, "invalid_token"),
                "RS-SCOPE-01": (403, "insufficient_scope"),
                "ERR-01": (401, "invalid_token"),
                "POP-01": (401, "invalid_token"),
                "POP-02": (401, "invalid_token"),
                "POP-03": (401, "invalid_token"),
            }
            if row["case_id"] in expected_http:
                expected_status, expected_challenge = expected_http[row["case_id"]]
                if row.get("http_status") != expected_status or row.get("rfc6750_challenge") != expected_challenge:
                    raise PreviewError("WP3 acceptance pass does not match its reviewed HTTP challenge contract")
            if row["case_id"] == "RS-QUERY-01":
                harmless = row["variant"] == "harmless_query_control"
                expected = (200, "not_applicable") if harmless else (401, "invalid_token")
                expected_arguments = {
                    "query_only_token": 1,
                    "query_encoded_name": 1,
                    "query_mixed_case_name": 1,
                    "query_dash_alias": 1,
                    "query_duplicate_name": 2,
                    "query_late_name": 999,
                    "query_arg_limit_1000": 1000,
                    "query_arg_truncated_1001": 1001,
                    "harmless_query_control": 1,
                }[row["variant"]]
                if (
                    (row.get("http_status"), row.get("rfc6750_challenge")) != expected
                    or row.get("query_argument_count") != expected_arguments
                    or row.get("request_target_byte_count") > 7680
                ):
                    raise PreviewError("WP3 query guard case does not match its fixed response and bounded request-target contract")
            if row["case_id"] == "RS-AUD-01":
                expected_audience_control = (
                    {(401, "invalid_token"), (403, "insufficient_scope")}
                    if row.get("variant") == "genuine_api_audience_absent"
                    else {(200, "not_applicable")}
                )
                if (row.get("http_status"), row.get("rfc6750_challenge")) not in expected_audience_control:
                    raise PreviewError("WP3 audience case does not match its negative or restored-positive HTTP contract")
            if row["case_id"] == "RS-ACTIVE-01" and row.get("variant") == "disabled_same_token" and (
                row.get("http_status") != 401 or row.get("rfc6750_challenge") != "invalid_token"
            ):
                raise PreviewError("WP3 inactive-token pass does not match the HTTP 401 contract")

    tls = payload.get("tls")
    tls_fields = {
        "localhost_sni_positive", "kong_api_sni_positive",
        "localhost_sni_requested_client_certificate", "kong_api_sni_requested_client_certificate",
        "no_client_certificate_handshake_rejected", "tls_11_rejected", "tls_12_only_rejected", "weak_cipher_rejected",
        "untrusted_server_certificate_rejected", "san_mismatch_rejected",
    }
    if not isinstance(tls, dict) or set(tls) != tls_fields or any(type(value) is not bool and value != "not_run" for value in tls.values()):
        raise PreviewError("WP3 TLS evidence fields are invalid")
    capture = payload.get("capture")
    capture_fields = {"request_count", "api_peer_pin_matches", "api_peer_common_name_matches", "authorization_single_bearer", "authorization_sha256_present", "forwarded_certificate_thumbprint_present", "forwarded_certificate_single_url_encoded_pem_leaf", "cookie_absent", "client_assertion_headers_absent", "client_assertion_unknown_suffix_header_count", "fixture_underscores_in_headers_on", "x_fapi_headers_absent", "x_demo_unexpected_headers_absent", "department_header_matches_expected_claim", "route_header_matches_expected_claim", "x_client_cert_like_header_count", "x_client_cert_header_count", "x_client_cert_unknown_suffix_header_count", "x_client_cert_duplicate_header_count", "x_client_cert_underscore_alias_count", "x_client_cert_stock_details_complete", "x_client_cert_stock_detail_counts", "x_client_cert_fingerprint_matches_forwarded_leaf", "caller_spoof_sentinel_match_count"}
    if not isinstance(capture, dict) or set(capture) != capture_fields:
        raise PreviewError("WP3 capture receipt fields are invalid")
    count_fields = {name for name in capture_fields if name.endswith("_count")} | {"request_count", "x_client_cert_like_header_count", "x_client_cert_header_count"}
    for name, value in capture.items():
        if name == "x_client_cert_stock_detail_counts":
            if not isinstance(value, dict) or set(value) != {"serial", "issuer_dn", "subject_dn", "fingerprint", "chain"} or any((type(count) is not int or not 0 <= count <= 4096) and count != "not_run" for count in value.values()):
                raise PreviewError("WP3 stock certificate metadata counts are invalid")
        elif name in count_fields:
            if (type(value) is not int or not 0 <= value <= 10000) and value != "not_run":
                raise PreviewError("WP3 capture counter is invalid")
        elif value not in {True, False, "not_run"}:
            raise PreviewError("WP3 capture evidence value is invalid")

    scan = payload.get("log_scan")
    scan_fields = {
        "passed", "completed", "failure_reason", "candidate_value_count", "checked_value_count",
        "secret_value_match_count", "source_category_counts", "matched_source_category_counts",
        "secret_match_category_counts", "credential_pattern_match_count", "credential_pattern_matches",
        "public_fixture_identifier_observation_count", "public_fixed_protocol_constant_observation_count",
        "service_scans",
        "api_response_completed", "api_response_failure_reason", "api_response_count",
        "api_response_scanned_byte_count", "api_response_secret_value_match_count",
        "api_response_secret_match_category_counts", "api_response_credential_pattern_matches",
    }
    categories = {"certificate", "privatekey", "license", "password", "oauth_token", "code", "assertion", "cookie", "verifier", "spoof_sentinel", "public_fixed_protocol_constant", "public_fixture_identifier", "noncredential_protocol_identifier", "unknown"}
    global_failure_reasons = WP3_LOG_FAILURE_REASONS | {"api_response_scan_incomplete"}
    if not isinstance(scan, dict) or set(scan) != scan_fields or type(scan["passed"]) is not bool or type(scan["completed"]) is not bool or scan["failure_reason"] not in global_failure_reasons:
        raise PreviewError("WP3 log scan receipt fields are invalid")
    for name in ("candidate_value_count", "checked_value_count", "secret_value_match_count", "credential_pattern_match_count", "public_fixture_identifier_observation_count", "public_fixed_protocol_constant_observation_count"):
        if type(scan[name]) is not int or not 0 <= scan[name] <= 10000:
            raise PreviewError("WP3 log scan count is invalid")
    for name in ("source_category_counts", "matched_source_category_counts", "secret_match_category_counts"):
        counts = scan[name]
        if not isinstance(counts, dict) or set(counts) != categories or any(type(value) is not int or not 0 <= value <= 10000 for value in counts.values()):
            raise PreviewError("WP3 log scan category counts are invalid")
    if scan["secret_match_category_counts"]["noncredential_protocol_identifier"] != 0:
        raise PreviewError("WP3 restricted protocol identifiers cannot be counted as credential matches")
    service_scans = scan["service_scans"]
    service_fields = {
        "completed", "passed", "failure_reason", "scanned_byte_count", "candidate_value_count",
        "checked_value_count", "matched_source_category_counts", "secret_match_category_counts",
        "credential_pattern_matches", "matched_candidate_provenance", "matched_log_context_counts",
    }
    if not isinstance(service_scans, dict) or set(service_scans) != WP3_LOG_SERVICES:
        raise PreviewError("WP3 per-service log scan inventory is invalid")
    for service, row in service_scans.items():
        if (
            not isinstance(row, dict) or set(row) != service_fields
            or type(row["completed"]) is not bool or type(row["passed"]) is not bool
            or row["failure_reason"] not in WP3_LOG_FAILURE_REASONS
        ):
            raise PreviewError("WP3 per-service log scan row is invalid")
        if (
            type(row["scanned_byte_count"]) is not int or not 0 <= row["scanned_byte_count"] <= 4 * 1024 * 1024
            or type(row["candidate_value_count"]) is not int or row["candidate_value_count"] != scan["candidate_value_count"]
            or type(row["checked_value_count"]) is not int or not 0 <= row["checked_value_count"] <= row["candidate_value_count"]
        ):
            raise PreviewError("WP3 per-service log scan counts are invalid")
        for name in ("matched_source_category_counts", "secret_match_category_counts"):
            counts = row[name]
            if not isinstance(counts, dict) or set(counts) != categories or any(type(value) is not int or not 0 <= value <= 10000 for value in counts.values()):
                raise PreviewError("WP3 per-service log scan category counts are invalid")
        if row["secret_match_category_counts"]["noncredential_protocol_identifier"] != 0:
            raise PreviewError("WP3 per-service restricted identifiers cannot be counted as credentials")
        patterns_for_service = row["credential_pattern_matches"]
        if (
            not isinstance(patterns_for_service, list)
            or len(patterns_for_service) > len(WP3_LOG_PATTERN_CATEGORIES)
            or any(value not in WP3_LOG_PATTERN_CATEGORIES for value in patterns_for_service)
            or patterns_for_service != sorted(set(patterns_for_service))
        ):
            raise PreviewError("WP3 per-service log scan pattern categories are invalid")
        provenance = row["matched_candidate_provenance"]
        if not isinstance(provenance, list) or len(provenance) > 512:
            raise PreviewError("WP3 per-service candidate provenance inventory is invalid")
        provenance_keys = []
        for item in provenance:
            if (
                not isinstance(item, dict)
                or set(item) != {"category", "source", "field", "matched_value_count"}
                or item.get("category") not in categories
                or item.get("source") not in WP3_LOG_CANDIDATE_SOURCES
                or item.get("field") not in WP3_LOG_CANDIDATE_FIELDS
                or type(item.get("matched_value_count")) is not int
                or not 1 <= item["matched_value_count"] <= 10000
                or item["matched_value_count"] > row["checked_value_count"]
            ):
                raise PreviewError("WP3 per-service candidate provenance row is invalid")
            provenance_keys.append((item["category"], item["source"], item["field"]))
            if item["matched_value_count"] > row["matched_source_category_counts"][item["category"]]:
                raise PreviewError("WP3 candidate provenance exceeds its matched category count")
        if provenance_keys != sorted(set(provenance_keys)):
            raise PreviewError("WP3 per-service candidate provenance ordering is invalid")
        contexts = row["matched_log_context_counts"]
        if (
            not isinstance(contexts, dict)
            or set(contexts) != WP3_LOG_MATCH_CONTEXTS
            or any(type(value) is not int or not 0 <= value <= row["checked_value_count"] for value in contexts.values())
            or sum(contexts.values()) > row["checked_value_count"] * len(WP3_LOG_MATCH_CONTEXTS)
        ):
            raise PreviewError("WP3 per-service matched log context counts are invalid")
        matched_total = sum(row["matched_source_category_counts"].values())
        matched_categories = {
            category for category, count in row["matched_source_category_counts"].items() if count
        }
        provenance_categories = {item["category"] for item in provenance}
        if (
            (matched_total == 0 and (provenance or any(contexts.values())))
            or (matched_total > 0 and not provenance)
            or not matched_categories.issubset(provenance_categories)
            or (row["completed"] and matched_total > 0 and not any(contexts.values()))
        ):
            raise PreviewError("WP3 per-service candidate provenance or context counts contradict matches")
        has_secret_match = any(row["secret_match_category_counts"].values())
        if row["completed"]:
            if row["failure_reason"] != "none" or row["checked_value_count"] != row["candidate_value_count"]:
                raise PreviewError("WP3 completed service scan has inconsistent status or counts")
        elif (
            row["failure_reason"] == "none" or row["checked_value_count"] != 0
            or any(row["matched_source_category_counts"].values())
            or has_secret_match or patterns_for_service or provenance
            or any(contexts.values())
        ):
            raise PreviewError("WP3 incomplete service scan cannot claim checked evidence")
        expected_service_pass = row["completed"] and not has_secret_match and not patterns_for_service
        if row["passed"] is not expected_service_pass:
            raise PreviewError("WP3 per-service log scan pass contradicts its evidence")
    all_services_completed = all(row["completed"] for row in service_scans.values())
    any_service_failure = any(not row["passed"] for row in service_scans.values())
    if scan["completed"] and not all_services_completed:
        raise PreviewError("WP3 aggregate log scan cannot complete with an incomplete service scan")
    if scan["passed"] and (not scan["completed"] or any_service_failure):
        raise PreviewError("WP3 aggregate log scan pass contradicts per-service results")
    api_failure_reasons = {"none", "not_started", "response_size_or_shape_limit"}
    if (
        type(scan["api_response_completed"]) is not bool
        or scan["api_response_failure_reason"] not in api_failure_reasons
        or (scan["api_response_completed"] is not (scan["api_response_failure_reason"] == "none"))
    ):
        raise PreviewError("WP3 API response scan completion metadata is invalid")
    for name, maximum in (
        ("api_response_count", 10000),
        ("api_response_scanned_byte_count", 33554432),
        ("api_response_secret_value_match_count", 10000),
    ):
        if type(scan[name]) is not int or not 0 <= scan[name] <= maximum:
            raise PreviewError("WP3 API response scan count is invalid")
    api_category_counts = scan["api_response_secret_match_category_counts"]
    if not isinstance(api_category_counts, dict) or set(api_category_counts) != categories or any(type(value) is not int or not 0 <= value <= 10000 for value in api_category_counts.values()):
        raise PreviewError("WP3 API response scan category counts are invalid")
    api_patterns = {"private_key_pem", "bearer_authorization", "cookie_or_forwarded_certificate", "client_assertion_form", "oauth_token_field", "jwt_shape"}
    if not isinstance(scan["api_response_credential_pattern_matches"], list) or len(scan["api_response_credential_pattern_matches"]) > len(api_patterns) or any(value not in api_patterns for value in scan["api_response_credential_pattern_matches"]):
        raise PreviewError("WP3 API response credential pattern categories are invalid")
    if scan["api_response_completed"] is False and (scan["completed"] is not False or scan["passed"] is not False):
        raise PreviewError("WP3 response scan incompleteness cannot be reported as a leak-free pass")
    if (scan["api_response_secret_value_match_count"] or scan["api_response_credential_pattern_matches"]) and scan["passed"]:
        raise PreviewError("WP3 API response secret match cannot be reported as leak-free")
    patterns = WP3_LOG_PATTERN_CATEGORIES
    log_patterns = scan["credential_pattern_matches"]
    if (
        not isinstance(log_patterns, list) or len(log_patterns) > len(patterns)
        or any(value not in patterns for value in log_patterns)
        or log_patterns != sorted(set(log_patterns))
    ):
        raise PreviewError("WP3 log scan credential pattern names are invalid")
    if (
        sum(scan["secret_match_category_counts"].values()) != scan["secret_value_match_count"]
        or ((scan["secret_value_match_count"] or log_patterns) and scan["passed"])
    ):
        raise PreviewError("WP3 aggregate log scan pass contradicts its secret evidence")


def effective_tls_matches_admin_observation(effective_tls: dict, admin_tls: dict) -> bool:
    """Bind the helper's separately labeled Admin fields to the Admin probe."""
    expected_protocol_status = (
        "reported"
        if admin_tls.get("metadata_source") == "admin_root_configuration"
        and admin_tls.get("protocols") == ["TLSv1.3"]
        else "not_proven"
    )
    return (
        effective_tls.get("cipher_suite") == admin_tls.get("cipher_suite")
        and effective_tls.get("admin_requested_protocols") == admin_tls.get("protocols")
        and effective_tls.get("admin_requested_protocols_status") == expected_protocol_status
    )


def prepare() -> dict:
    if PREVIEW.exists() or PREVIEW.is_symlink():
        raise PreviewError("refusing to reuse the WP3 isolated fixture directory")
    if (ROOT / ".generated").is_symlink():
        raise PreviewError("refusing to prepare through a .generated symlink")
    os.umask(0o077)
    require_ports_free()
    require_isolated_project_absent()
    images = inspect_images()
    preview_preparer = load_wp2_preparer()
    try:
        preview_preparer.prepare(PREVIEW)
        issue_outside_ca_client_identity()
        role_values = runtime_role_values()
        role_path = PREVIEW / "runtime-api.json"
        with role_path.open("x", encoding="utf-8") as output:
            json.dump(role_values, output, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            output.write("\n")
        os.chmod(role_path, 0o600)
        rendered_state = render_gateway_config(role_values)
        compose_config_check(role_values)
        receipt = {
            "schema_version": 1,
            "scope": "wp3-api-runtime-isolated-preview-preparation",
            "images": images,
            "host_ports": {"keycloak": 18444, "api_gateway": 18443, "oauth_callback": 8443},
            "upstream_capture": {"service_name": "pop-verifier", "container_port": 9443, "host_published": False},
            "listener_sni": ["localhost", "kong-api"],
            "oidc_public_issuer": "https://localhost:8444/realms/fapi-demo",
            "keycloak_harness_target": "https://localhost:18444",
            "keycloak_advertised_hostname": "https://localhost:8444",
            "license_present": True,
            "normal_env_loaded": False,
            "pki_and_accounts_generated_fresh": True,
            "api_runtime_config_rendered": True,
            "api_runtime_state_sha256": hashlib.sha256((ROOT / "kong/api-gateway.yaml").read_bytes()).hexdigest(),
            "runtime_role_inputs_sha256": canonical_sha256(role_values),
            "rendered_runtime_config_sha256": canonical_sha256(rendered_state),
            "rendered_runtime_file_sha256": hashlib.sha256((PREVIEW / "api-runtime.yml").read_bytes()).hexdigest(),
            "compose_file_sha256": hashlib.sha256(COMPOSE_FILE.read_bytes()).hexdigest(),
            "capture_helper_sha256": hashlib.sha256(CAPTURE_HELPER.read_bytes()).hexdigest(),
            "flow_runner_sha256": hashlib.sha256(FLOW_RUNNER.read_bytes()).hexdigest(),
            "tls_metadata_helper_sha256": hashlib.sha256(TLS_METADATA_HELPER.read_bytes()).hexdigest(),
            "tls_metadata_test_sha256": hashlib.sha256(TLS_METADATA_TESTS.read_bytes()).hexdigest(),
            "query_guard_test_sha256": hashlib.sha256(QUERY_GUARD_TESTS.read_bytes()).hexdigest(),
            "fixture_files_sha256": {},
            "compose_config_validated_quietly": True,
            "fixture_only_admin_loopback": True,
            "fixture_only_admin_gui_disabled": True,
            "outside_ca_client_certificate_prepared": True,
            "containers_started": False,
            "konnect_read_or_write_performed": False,
        }
        receipt["fixture_files_sha256"] = fixture_file_digests()
        write_private_receipt(receipt)
        return receipt
    except BaseException:
        if PREVIEW.is_dir() and not PREVIEW.is_symlink():
            shutil.rmtree(PREVIEW)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-create-isolated-preview-assets", action="store_true")
    args = parser.parse_args()
    if not args.allow_create_isolated_preview_assets:
        parser.error("pass --allow-create-isolated-preview-assets; this prepares files only and does not start containers")
    try:
        receipt = prepare()
    except (PreviewError, OSError, subprocess.CalledProcessError) as error:
        evidence = ROOT / ".generated/evidence"
        if not (ROOT / ".generated").is_symlink():
            try:
                evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(evidence, 0o700)
                failure = evidence / "wp3-prepare-failure.json"
                with failure.open("x", encoding="utf-8") as output:
                    json.dump({
                        "schema_version": 1,
                        "scope": "wp3-api-runtime-isolated-preview-preparation",
                        "result": "failed_before_runtime_start",
                        "reason_category": "preflight_or_fixture_generation",
                        "fixture_cleanup_attempted": True,
                        "containers_started": False,
                        "konnect_read_or_write_performed": False,
                    }, output, sort_keys=True, separators=(",", ":"))
                    output.write("\n")
                os.chmod(failure, 0o600)
            except (OSError, FileExistsError):
                pass
        print(f"WP3 fixture preparation failed: {error}", file=sys.stderr)
        return 1
    print("Prepared fresh WP3 fixture assets under .generated/wp3-preview; no containers were started.")
    image_summary = ", ".join(
        f"{name}={metadata['architecture']}" for name, metadata in receipt["images"].items()
    )
    print(f"Pinned images: {image_summary}")
    print("Host ports: 127.0.0.1:18443 (API), 127.0.0.1:18444 (Keycloak), 127.0.0.1:8443 (OAuth callback).")
    print("Kong license presence was checked without copying or displaying its value; receipts contain booleans and digests only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
