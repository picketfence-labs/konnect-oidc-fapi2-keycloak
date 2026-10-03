#!/usr/bin/env python3
"""Fail-closed validation for the API runtime state owned by WP3."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import textwrap
from collections import Counter
from pathlib import Path

import yaml
from yaml.constructor import ConstructorError


INTROSPECTION_CERT_ID = "44444444-4444-4444-8444-444444444444"
UPSTREAM_CERT_ID = "55555555-5555-4555-8555-555555555555"
SHARED_API_CA_ID = "33333333-3333-4333-8333-333333333333"
RUNTIME_ENTITY_IDS = {
    "fapi-api-resource-server": "a5fe77b4-93fd-4f84-bb31-71c245dedd09",
    "fapi-api-resource-server-route": "14d51ff4-613c-4769-96ce-330cd8075855",
    "pre-function": "4374b81d-77c4-4da1-9dfe-fbb0949a13ba",
    "openid-connect": "ed488e53-d29d-4db7-ba89-78b3bbf35df3",
    "tls-handshake-modifier": "6c3a195b-2fa7-4ed8-8ae4-72db3d2c537c",
    "tls-metadata-headers": "a6b8e2df-3612-47db-b863-b6dee55f2dc4",
}
RUNTIME_SERVICE_NAME = "fapi-api-resource-server"
RUNTIME_ROUTE_NAME = "fapi-api-resource-server-route"
INTERNAL_ISSUER_LOCATOR = (
    "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration"
)
PUBLIC_ISSUER = "https://localhost:8444/realms/fapi-demo"
MIGRATION_APPROVAL_RELATIVE = Path(".generated/evidence/wp3-api-runtime-migration-approval.json")
MIGRATION_APPROVAL_FIELDS = {
    "schema_version",
    "scope",
    "approved",
    "control_plane_id",
    "state_sha256",
    "role_inputs_sha256",
    "diff_sha256",
    "summary",
    "operations",
}
LEGACY_API_SERVICE_ROUTE_TAGS = {
    "fapi-mtls-service": "route-a",
    "fapi-pkj-mtls-service": "route-b",
}
LEGACY_API_ROUTE_SERVICE_TAGS = {
    "fapi-mtls-route": "route-a",
    "fapi-pkj-mtls-route": "route-b",
}
LEGACY_API_PLUGIN_ROUTE_TAGS = (
    ("cors", "route-a"),
    ("request-transformer", "route-a"),
    ("openid-connect", "route-a"),
    ("cors", "route-b"),
    ("request-transformer", "route-b"),
    ("openid-connect", "route-b"),
    ("fapi-client-auth-bridge", "route-b"),
)
EXPECTED_RUNTIME_CREATE_KINDS = {
    "fapi-api-resource-server": "service",
    "fapi-api-resource-server-route": "route",
    "pre-function": "plugin",
    "openid-connect": "plugin",
    "tls-handshake-modifier": "plugin",
    "tls-metadata-headers": "plugin",
}
EXPECTED_RUNTIME_MIGRATION_SUMMARY = {
    "creating": 6,
    "updating": 0,
    "deleting": 13,
    "total": 19,
}

HEADER_SANITIZER_LUA = textwrap.dedent(
    """
    local headers, err = kong.request.get_headers(1000)
    if not headers or err then
      return kong.response.exit(431, { message = "Request headers exceed inspection limit" })
    end

    local count = 0
    for name in pairs(headers) do
      count = count + 1
      local value = headers[name]
      if type(value) == "table" then
        count = count + #value - 1
      end
      if count >= 1000 then
        return kong.response.exit(431, { message = "Request headers exceed inspection limit" })
      end

      local normalized = string.lower(name):gsub("_", "-")
      if normalized == "cookie"
        or normalized:sub(1, 7) == "x-demo-"
        or normalized:sub(1, 7) == "x-fapi-"
        or normalized:sub(1, 13) == "x-client-cert"
        or normalized:sub(1, 16) == "client-assertion" then
        kong.service.request.clear_header(name)
      end
    end

    local function reject_query_authentication()
      kong.response.set_header("WWW-Authenticate", 'Bearer error="invalid_token"')
      return kong.response.exit(401, { message = "Invalid access token" })
    end

    local query_call_ok, query_args, query_error = pcall(kong.request.get_query, 1000)
    if not query_call_ok or type(query_args) ~= "table" or query_error ~= nil then
      return reject_query_authentication()
    end

    local argument_count = 0
    for name, value in pairs(query_args) do
      if type(name) ~= "string" then
        return reject_query_authentication()
      end

      local normalized = string.lower(name):gsub("_", "-")
      if normalized == "access-token" then
        return reject_query_authentication()
      end

      argument_count = argument_count + 1
      if type(value) == "table" then
        local occurrences = 0
        local highest_index = 0
        for index in pairs(value) do
          if type(index) ~= "number" or index < 1 or index % 1 ~= 0 then
            return reject_query_authentication()
          end
          occurrences = occurrences + 1
          if index > highest_index then
            highest_index = index
          end
        end
        if occurrences < 2 or highest_index ~= occurrences then
          return reject_query_authentication()
        end
        argument_count = argument_count + occurrences - 1
      elseif type(value) ~= "string" and type(value) ~= "boolean" then
        return reject_query_authentication()
      end

      if argument_count >= 1000 then
        return reject_query_authentication()
      end
    end
    """
).strip()


class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found a duplicate key",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _parse_state(path: Path) -> dict:
    source = path.read_text()
    rendered = re.sub(
        r'\$\{\{\s*env\s+"([A-Z0-9_]+)"\s*\}\}',
        lambda match: f"deck-template:{match.group(1)}",
        source,
    )
    if "${{" in rendered:
        raise ValueError("API runtime state contains an unsupported template expression")
    try:
        parsed = yaml.load(rendered, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ValueError("API runtime state is not valid duplicate-free decK YAML") from exc
    if not isinstance(parsed, dict):
        raise ValueError("API runtime state must be a YAML mapping")
    return parsed


def _expected_oidc_config() -> dict:
    return {
        "issuer": INTERNAL_ISSUER_LOCATOR,
        "introspection_endpoint": (
            "https://keycloak:8443/realms/fapi-demo/"
            "protocol/openid-connect/token/introspect"
        ),
        "mtls_introspection_endpoint": (
            "https://keycloak:8443/realms/fapi-demo/"
            "protocol/openid-connect/token/introspect"
        ),
        "client_id": ["api-gateway-introspection"],
        "client_auth": ["tls_client_auth"],
        "auth_methods": ["introspection"],
        "introspection_endpoint_auth_method": "tls_client_auth",
        "introspection_check_active": True,
        "cache_introspection": False,
        "cache_tokens": False,
        "bearer_token_param_type": ["header"],
        "upstream_access_token_header": "authorization:bearer",
        "tls_client_auth_cert_id": INTROSPECTION_CERT_ID,
        "tls_client_auth_ssl_verify": True,
        "ssl_verify": True,
        "issuers_allowed": [PUBLIC_ISSUER],
        "audience_required": ["fapi-demo-api"],
        "scopes_required": ["openid"],
        "proof_of_possession_mtls": "strict",
        "proof_of_possession_auth_methods_validation": True,
        "expose_error_code": True,
        "upstream_headers": [
            {
                "header": "X-Demo-Department",
                "path": ["https://fapi-demo.example.com/department"],
            },
            {
                "header": "X-Demo-Route",
                "path": ["https://fapi-demo.example.com/route"],
            },
        ],
    }


def validate_api_runtime_state(root: Path) -> dict:
    """Return parsed API state only when WP3's complete ownership contract holds."""
    state_path = root / "kong/api-gateway.yaml"
    if not state_path.is_file() or state_path.is_symlink():
        raise ValueError("API runtime state is missing or unsafe")
    state = _parse_state(state_path)
    if set(state) != {
        "_format_version",
        "_info",
        "certificates",
        "ca_certificates",
        "services",
        "plugins",
    }:
        raise ValueError("API runtime state has unexpected entities or fields")
    if state.get("_format_version") != "3.0" or state.get("_info") != {
        "select_tags": ["fapi2-demo"]
    }:
        raise ValueError("API runtime tag selection changed")

    foundation = _parse_state(root / "kong/foundation/api.yaml")
    foundation_certificates = foundation.get("certificates")
    runtime_certificates = state.get("certificates")
    if not isinstance(foundation_certificates, list) or runtime_certificates != foundation_certificates:
        raise ValueError("API runtime must include unchanged API foundation certificates")

    ca_certificates = state.get("ca_certificates")
    if (
        not isinstance(ca_certificates, list)
        or len(ca_certificates) != 1
        or ca_certificates[0]
        != {
            "id": SHARED_API_CA_ID,
            "cert": "deck-template:DECK_FAPI_CA_CERT_YAML",
            "tags": ["fapi2-demo"],
        }
    ):
        raise ValueError("API runtime must preserve the existing shared CA identity and tag")

    services = state.get("services")
    if not isinstance(services, list) or len(services) != 1:
        raise ValueError("API runtime must contain exactly one Resource Server Service")
    service = services[0]
    if set(service) != {
        "id",
        "name",
        "protocol",
        "host",
        "port",
        "path",
        "tls_verify",
        "ca_certificates",
        "client_certificate",
        "tags",
        "routes",
    } or any(
        service.get(name) != value
        for name, value in {
            "id": RUNTIME_ENTITY_IDS["fapi-api-resource-server"],
            "name": "fapi-api-resource-server",
            "protocol": "https",
            "host": "pop-verifier",
            "port": 9443,
            "path": "/evidence",
            "tls_verify": True,
            "ca_certificates": [SHARED_API_CA_ID],
            "client_certificate": UPSTREAM_CERT_ID,
            "tags": ["fapi2-demo", "api"],
        }.items()
    ):
        raise ValueError("API runtime Resource Server Service contract changed")
    routes = service.get("routes")
    if not isinstance(routes, list) or len(routes) != 1:
        raise ValueError("API runtime must contain exactly one HTTPS Route")
    route = routes[0]
    if route != {
        "id": RUNTIME_ENTITY_IDS["fapi-api-resource-server-route"],
        "name": "fapi-api-resource-server-route",
        "paths": ["/fapi-api/evidence"],
        "protocols": ["https"],
        "snis": ["kong-api", "localhost"],
        "strip_path": True,
        "tags": ["fapi2-demo", "api"],
    }:
        raise ValueError("API runtime HTTPS Route contract changed")

    plugins = state.get("plugins")
    expected_plugin_names = {
        "pre-function",
        "openid-connect",
        "tls-handshake-modifier",
        "tls-metadata-headers",
    }
    if not isinstance(plugins, list) or len(plugins) != len(expected_plugin_names):
        raise ValueError("API runtime plugin set is incomplete")
    if any(not isinstance(plugin, dict) for plugin in plugins):
        raise ValueError("API runtime plugin entity is malformed")
    by_name = {plugin.get("name"): plugin for plugin in plugins}
    if set(by_name) != expected_plugin_names:
        raise ValueError("API runtime contains an unexpected or custom plugin")
    for plugin in plugins:
        plugin_name = plugin.get("name")
        if (
            set(plugin) != {"id", "name", "route", "tags", "config"}
            or plugin.get("id") != RUNTIME_ENTITY_IDS.get(plugin_name)
            or plugin.get("route") != route["name"]
            or plugin.get("tags") != ["fapi2-demo", "api"]
        ):
            raise ValueError("API runtime plugin scope or ownership tags changed")

    sanitizer = by_name["pre-function"].get("config")
    if (
        not isinstance(sanitizer, dict)
        or set(sanitizer) != {"access"}
        or not isinstance(sanitizer.get("access"), list)
        or len(sanitizer["access"]) != 1
        or not isinstance(sanitizer["access"][0], str)
        or sanitizer["access"][0].strip() != HEADER_SANITIZER_LUA
    ):
        raise ValueError("API runtime header-boundary guard changed")
    if by_name["openid-connect"].get("config") != _expected_oidc_config():
        raise ValueError("API runtime OIDC Resource Server policy changed")
    if by_name["tls-handshake-modifier"].get("config") != {
        "tls_client_certificate": "REQUEST"
    }:
        raise ValueError("API runtime TLS handshake certificate request changed")
    if by_name["tls-metadata-headers"].get("config") != {
        "inject_client_cert_details": True,
        "client_cert_header_name": "X-Client-Cert",
    }:
        raise ValueError("API runtime verified client certificate forwarding changed")

    return state


def file_sha256(path: Path) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("file digest cannot be computed safely on this platform")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise ValueError("file to digest is missing or unsafe") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("file to digest is missing or unsafe")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def canonical_sha256(value: object) -> str:
    content = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def parse_deck_diff_report(raw_output: str) -> tuple[dict, str]:
    """Validate pinned decK JSON and hash the full, order-normalized entity changes."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate decK diff report field")
            result[key] = value
        return result

    try:
        report = json.loads(raw_output, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError("decK API runtime diff did not return a valid JSON report") from None
    if (
        not isinstance(report, dict)
        or set(report) != {"changes", "summary", "warnings", "errors"}
        or report.get("warnings") != []
        or report.get("errors") != []
    ):
        raise ValueError("decK API runtime diff report contains unexpected fields, warnings, or errors")
    changes = report["changes"]
    summary = report["summary"]
    operation_names = ("creating", "updating", "deleting")
    if (
        not isinstance(changes, dict)
        or set(changes) != set(operation_names)
        or not isinstance(summary, dict)
        or set(summary) != {*operation_names, "total"}
    ):
        raise ValueError("decK API runtime diff report operation structure changed")

    operations: dict[str, list[dict[str, str | None]]] = {}
    normalized_changes: dict[str, list[dict]] = {}
    for operation in operation_names:
        entries = changes[operation]
        if not isinstance(entries, list):
            raise ValueError("decK API runtime diff report operation list is malformed")
        identity_entries: list[tuple[dict[str, str | None], dict]] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"kind", "name", "body"}:
                raise ValueError("decK API runtime diff report entity is malformed")
            kind, name, body = entry["kind"], entry["name"], entry["body"]
            if (
                not isinstance(kind, str)
                or not kind
                or not isinstance(name, str)
                or not name
                or not isinstance(body, dict)
            ):
                raise ValueError("decK API runtime diff report entity identity is incomplete")
            if set(body) != {"old", "new"}:
                raise ValueError("decK API runtime diff entity body does not match the pinned schema")
            old_entity = body["old"]
            new_entity = body["new"]
            # decK 1.53.1's JSON report places a deletion's current entity in
            # body.new and leaves body.old null; preserve this exact behavior.
            entity = old_entity if operation == "updating" else new_entity
            if not isinstance(entity, dict):
                raise ValueError("decK API runtime diff report entity body is incomplete")
            if operation == "creating" and (old_entity is not None or not isinstance(new_entity, dict)):
                raise ValueError("decK API create body is malformed")
            if operation == "updating" and (not isinstance(old_entity, dict) or not isinstance(new_entity, dict)):
                raise ValueError("decK API update body is malformed")
            if operation == "deleting" and (not isinstance(new_entity, dict) or old_entity is not None):
                raise ValueError("decK API delete body is malformed")
            entity_id = entity.get("id")
            if entity_id is not None and (not isinstance(entity_id, str) or not entity_id):
                raise ValueError("decK API runtime diff report entity ID is malformed")
            if operation in {"updating", "deleting"} and entity_id is None:
                raise ValueError("decK API existing entity operation omitted its ID")
            if operation == "updating" and old_entity.get("id") != new_entity.get("id"):
                raise ValueError("decK API update changed an existing entity ID")
            identity_name = name
            if canonical_entity_kind(kind) == "plugin":
                identity_name = entity.get("name")
                if not isinstance(identity_name, str) or not identity_name:
                    raise ValueError("decK plugin diff body omitted its canonical entity name")
            identity = {"kind": kind, "name": identity_name, "id": entity_id}
            normalized_entry = {
                "kind": kind,
                # Preserve decK's source-derived Console() label in the full
                # report digest. Operation identities below use body.name for
                # plugins so a report descriptor cannot change an entity name.
                "name": name,
                "body": {"old": old_entity, "new": new_entity},
            }
            identity_entries.append((identity, normalized_entry))
        identity_entries.sort(key=lambda pair: (
            pair[0]["kind"], pair[0]["name"], pair[0]["id"] or "",
        ))
        identities = [identity for identity, _entry in identity_entries]
        if len({(item["kind"], item["name"], item["id"]) for item in identities}) != len(identities):
            raise ValueError("decK API runtime diff report has duplicate operation identities")
        normalized_entries = [entry for _identity, entry in identity_entries]
        if type(summary[operation]) is not int or summary[operation] != len(identities):
            raise ValueError("decK API runtime diff report summary does not match its operation identities")
        operations[operation] = identities
        normalized_changes[operation] = normalized_entries
    if type(summary["total"]) is not int or summary["total"] != sum(summary[name] for name in operation_names):
        raise ValueError("decK API runtime diff report total does not match operation counts")
    validate_runtime_diff_scope(operations, normalized_changes)
    canonical_report = {
        "changes": normalized_changes,
        "summary": summary,
        "warnings": [],
        "errors": [],
    }
    canonical = json.dumps(canonical_report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    receipt_view = {"summary": summary, "operations": operations}
    return receipt_view, digest


def canonical_entity_kind(kind: str) -> str | None:
    return {
        "service": "service", "services": "service",
        "route": "route", "routes": "route",
        "plugin": "plugin", "plugins": "plugin",
        "certificate": "certificate", "certificates": "certificate",
    }.get(kind.lower())


def _legacy_route_tag(entity: dict) -> str | None:
    tags = entity.get("tags")
    if (
        not isinstance(tags, list)
        or len(tags) != 2
        or not all(isinstance(tag, str) for tag in tags)
        or len(set(tags)) != 2
        or "fapi2-demo" not in tags
    ):
        return None
    route_tags = set(tags) - {"fapi2-demo"}
    if len(route_tags) != 1:
        return None
    value = next(iter(route_tags))
    return value if value in {"route-a", "route-b"} else None


def _relation_id(entity: dict, field: str, expected_name: str) -> str | None:
    relation = entity.get(field)
    if not isinstance(relation, dict) or set(relation) != {"id", "name"}:
        return None
    identity = relation.get("id")
    name = relation.get("name")
    if not isinstance(identity, str) or not identity or name != expected_name:
        return None
    return identity


def _certificate_relation_id(entity: dict, field: str) -> str | None:
    relation = entity.get(field)
    if not isinstance(relation, dict) or set(relation) != {"id"}:
        return None
    identity = relation.get("id")
    return identity if isinstance(identity, str) and identity else None


def validate_runtime_diff_scope(operations: dict, changes: dict) -> None:
    """Allow a structurally valid no-op or exactly the reviewed 6/0/13 migration."""
    if not any(operations[name] for name in ("creating", "updating", "deleting")):
        return

    if (
        len(changes["creating"]) != EXPECTED_RUNTIME_MIGRATION_SUMMARY["creating"]
        or len(operations["updating"]) != EXPECTED_RUNTIME_MIGRATION_SUMMARY["updating"]
        or len(changes["deleting"]) != EXPECTED_RUNTIME_MIGRATION_SUMMARY["deleting"]
    ):
        raise ValueError("API runtime migration must match the reviewed 6/0/13 operation boundary")

    expected_creates = set(RUNTIME_ENTITY_IDS.items())
    actual_creates = {(entry["name"], entry["id"]) for entry in operations["creating"]}
    if actual_creates != expected_creates or len(operations["creating"]) != len(expected_creates):
        raise ValueError("API runtime diff creates do not match its six fixed entity identities")
    for identity, entry in zip(operations["creating"], changes["creating"]):
        entity = entry["body"]["new"]
        kind = canonical_entity_kind(identity["kind"])
        if kind == "plugin":
            expected_report_name = f"{identity['name']} for route {RUNTIME_ROUTE_NAME}"
            route_relation_id = _relation_id(entity, "route", RUNTIME_ROUTE_NAME)
            if (
                entry["name"] != expected_report_name
                or "service" in entity
                or route_relation_id != RUNTIME_ENTITY_IDS[RUNTIME_ROUTE_NAME]
            ):
                raise ValueError("API runtime plugin create descriptor or Route binding changed")
        elif entry["name"] != identity["name"]:
            raise ValueError("API runtime create report name does not match its canonical entity name")
        if kind == "route" and _relation_id(
            entity, "service", RUNTIME_SERVICE_NAME,
        ) != RUNTIME_ENTITY_IDS[RUNTIME_SERVICE_NAME]:
            raise ValueError("API runtime Route create is not bound to the fixed Resource Server Service")
        if (
            kind != EXPECTED_RUNTIME_CREATE_KINDS.get(identity["name"])
            or entity.get("name") != identity["name"]
            or entity.get("tags") != ["fapi2-demo", "api"]
        ):
            raise ValueError("API runtime diff create kind, canonical name, or ownership tags changed")

    protected_ids = {
        SHARED_API_CA_ID,
        INTROSPECTION_CERT_ID,
        UPSTREAM_CERT_ID,
        *RUNTIME_ENTITY_IDS.values(),
    }
    operation_ids = [entry["id"] for name in ("creating", "deleting") for entry in operations[name]]
    if len(operation_ids) != len(set(operation_ids)):
        raise ValueError("API runtime diff report contains duplicate entity IDs")
    deletes = list(zip(operations["deleting"], changes["deleting"]))
    services_by_route: dict[str, str] = {}
    certificates_by_route: dict[str, str] = {}
    named_deletes: Counter[tuple[str, str, str]] = Counter()
    certificate_rows: list[tuple[dict, dict, str]] = []
    for identity, entry in deletes:
        entity = entry["body"]["new"]
        entity_id = identity["id"]
        kind = canonical_entity_kind(identity["kind"])
        if kind is None or entity_id in protected_ids or entity.get("id") != entity_id:
            raise ValueError("API runtime migration attempted an unknown or protected delete")
        route_tag = _legacy_route_tag(entity)
        if route_tag is None:
            raise ValueError("API runtime migration delete has tags outside the legacy Route boundary")
        if kind == "certificate":
            certificate_rows.append((identity, entry, route_tag))
            continue

        name = identity["name"]
        if entity.get("name") != name:
            raise ValueError("API runtime delete name does not match its decK identity")
        named_deletes[(kind, name, route_tag)] += 1
        if kind == "service":
            if LEGACY_API_SERVICE_ROUTE_TAGS.get(name) != route_tag or route_tag in services_by_route:
                raise ValueError("API runtime Service delete is outside the legacy Route boundary")
            services_by_route[route_tag] = entity_id
        elif kind == "route":
            if LEGACY_API_ROUTE_SERVICE_TAGS.get(name) != route_tag:
                raise ValueError("API runtime Route delete is outside the legacy Route boundary")
        elif kind == "plugin":
            if (name, route_tag) not in LEGACY_API_PLUGIN_ROUTE_TAGS:
                raise ValueError("API runtime plugin delete is outside the legacy Route boundary")
            service_name = next(
                service for service, service_route in LEGACY_API_SERVICE_ROUTE_TAGS.items()
                if service_route == route_tag
            )
            if entry["name"] != f"{name} for service {service_name}":
                raise ValueError("legacy plugin display name changed from its Service association")
        else:
            raise ValueError("API runtime delete kind is outside the legacy Route boundary")
        if kind in {"service", "route"} and entry["name"] != name:
            raise ValueError("API runtime delete report name does not match its canonical entity name")

    expected_named = Counter(
        [("service", name, tag) for name, tag in LEGACY_API_SERVICE_ROUTE_TAGS.items()]
        + [("route", name, tag) for name, tag in LEGACY_API_ROUTE_SERVICE_TAGS.items()]
        + [("plugin", name, tag) for name, tag in LEGACY_API_PLUGIN_ROUTE_TAGS]
    )
    if named_deletes != expected_named or set(services_by_route) != {"route-a", "route-b"}:
        raise ValueError("API runtime deletes do not match the 11 known legacy Services, Routes, and plugins")

    certificate_counts = Counter(tag for _identity, _entry, tag in certificate_rows)
    if certificate_counts != Counter({"route-a": 1, "route-b": 1}):
        raise ValueError("API runtime migration must delete the two Route-scoped certificates only")
    for identity, entry, route_tag in certificate_rows:
        if identity["id"] in protected_ids or entry["body"]["new"].get("id") != identity["id"]:
            raise ValueError("API runtime migration attempted to delete a protected certificate")
        certificates_by_route[route_tag] = identity["id"]

    for identity, entry in deletes:
        entity = entry["body"]["new"]
        kind = canonical_entity_kind(identity["kind"])
        route_tag = _legacy_route_tag(entity)
        if kind == "service":
            if (
                _certificate_relation_id(entity, "client_certificate") != certificates_by_route.get(route_tag)
                or entity.get("ca_certificates") != [SHARED_API_CA_ID]
            ):
                raise ValueError("legacy Service certificate relations changed from the Route-owned certificates")
        elif kind == "route":
            service_name = next(
                service for service, service_route in LEGACY_API_SERVICE_ROUTE_TAGS.items()
                if service_route == route_tag
            )
            if _relation_id(entity, "service", service_name) != services_by_route.get(route_tag):
                raise ValueError("legacy Route or plugin is not scoped to its matching legacy Service")
        elif kind == "plugin":
            service_name = next(
                service for service, service_route in LEGACY_API_SERVICE_ROUTE_TAGS.items()
                if service_route == route_tag
            )
            if _relation_id(entity, "service", service_name) != services_by_route.get(route_tag):
                raise ValueError("legacy Route or plugin is not scoped to its matching legacy Service")


def validate_migration_approval_operations(summary: dict, operations: dict) -> None:
    """Require a human approval for only the exact 6/0/13 migration, never a no-op."""
    if summary != EXPECTED_RUNTIME_MIGRATION_SUMMARY:
        raise ValueError("API runtime migration approval is not bound to the reviewed 6/0/13 change")
    if not isinstance(operations, dict) or set(operations) != {"creating", "updating", "deleting"}:
        raise ValueError("API runtime migration approval operation counts are malformed")

    expected_creates = Counter(
        (EXPECTED_RUNTIME_CREATE_KINDS[name], name, entity_id)
        for name, entity_id in RUNTIME_ENTITY_IDS.items()
    )
    actual_creates = Counter(
        (canonical_entity_kind(item["kind"]), item["name"], item["id"])
        for item in operations["creating"]
    )
    if actual_creates != expected_creates or operations["updating"]:
        raise ValueError("API runtime migration approval create/update identities changed")

    actual_named = Counter(
        (canonical_entity_kind(item["kind"]), item["name"])
        for item in operations["deleting"]
        if canonical_entity_kind(item["kind"]) != "certificate"
    )
    expected_named = Counter(
        [("service", name) for name in LEGACY_API_SERVICE_ROUTE_TAGS]
        + [("route", name) for name in LEGACY_API_ROUTE_SERVICE_TAGS]
        + [("plugin", name) for name, _tag in LEGACY_API_PLUGIN_ROUTE_TAGS]
    )
    certificate_count = sum(
        canonical_entity_kind(item["kind"]) == "certificate"
        for item in operations["deleting"]
    )
    if actual_named != expected_named or certificate_count != 2 or len(operations["deleting"]) != 13:
        raise ValueError("API runtime migration approval delete identities changed")
    operation_ids = [item["id"] for name in ("creating", "deleting") for item in operations[name]]
    if len(operation_ids) != len(set(operation_ids)):
        raise ValueError("API runtime migration approval contains duplicate entity identities")
    protected_ids = {
        SHARED_API_CA_ID,
        INTROSPECTION_CERT_ID,
        UPSTREAM_CERT_ID,
        *RUNTIME_ENTITY_IDS.values(),
    }
    if any(item["id"] in protected_ids for item in operations["deleting"]):
        raise ValueError("API runtime migration approval attempts to delete a protected entity")


def _read_private_approval_bytes(path: Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("API runtime migration approval cannot be safely opened on this platform")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16_384:
            raise ValueError("API runtime migration approval receipt must be a regular mode-0600 file under 16 KiB")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(16_385)
        if len(content) > 16_384:
            raise ValueError("API runtime migration approval receipt must be a regular mode-0600 file under 16 KiB")
        return content
    finally:
        os.close(descriptor)


def read_migration_approval(root: Path, control_plane_id: str, role_values: dict) -> dict:
    """Read a human-created, private receipt binding approval to exact API state."""
    path = root / MIGRATION_APPROVAL_RELATIVE
    for parent in (root / ".generated", path.parent):
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("API runtime migration approval receipt directory is missing or unsafe")
    try:
        raw_receipt = _read_private_approval_bytes(path)
    except FileNotFoundError:
        raise ValueError("API runtime sync requires the separately reviewed migration approval receipt") from None
    except OSError:
        raise ValueError("API runtime migration approval receipt is missing or unsafe") from None
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate receipt field")
            result[key] = value
        return result

    try:
        receipt = json.loads(raw_receipt.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("API runtime migration approval receipt is malformed") from None
    if not isinstance(receipt, dict) or set(receipt) != MIGRATION_APPROVAL_FIELDS:
        raise ValueError("API runtime migration approval receipt fields are malformed")
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["scope"] != "api-runtime-migration"
        or receipt["approved"] is not True
        or not isinstance(control_plane_id, str)
        or receipt["control_plane_id"] != control_plane_id
    ):
        raise ValueError("API runtime migration approval does not match the API target and scope")
    state_path = root / "kong/api-gateway.yaml"
    if (
        state_path.is_symlink()
        or not isinstance(receipt["state_sha256"], str)
        or receipt["state_sha256"] != file_sha256(state_path)
    ):
        raise ValueError("API runtime migration approval does not match the current runtime state")
    for name in ("state_sha256", "diff_sha256"):
        if not isinstance(receipt[name], str) or re.fullmatch(r"[0-9a-f]{64}", receipt[name]) is None:
            raise ValueError("API runtime migration approval digest is malformed")
    if (
        not isinstance(receipt["role_inputs_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt["role_inputs_sha256"]) is None
        or receipt["role_inputs_sha256"] != canonical_sha256(role_values)
    ):
        raise ValueError("API runtime migration approval does not match current certificate role inputs")
    operations = receipt["operations"]
    if not isinstance(receipt["summary"], dict) or set(receipt["summary"]) != {
        "creating", "updating", "deleting", "total"
    } or any(type(count) is not int or count < 0 for count in receipt["summary"].values()):
        raise ValueError("API runtime migration approval summary is malformed")
    if not isinstance(operations, dict) or set(operations) != {"creating", "updating", "deleting"}:
        raise ValueError("API runtime migration approval operation counts are malformed")
    for operation, entries in operations.items():
        if (
            not isinstance(entries, list)
            or receipt["summary"][operation] != len(entries)
            or any(
                not isinstance(entry, dict)
                or set(entry) != {"kind", "name", "id"}
                or not isinstance(entry["kind"], str)
                or not entry["kind"]
                or not isinstance(entry["name"], str)
                or not entry["name"]
                or not isinstance(entry["id"], str)
                or not entry["id"]
                for entry in entries
            )
        ):
            raise ValueError("API runtime migration approval operation identities are malformed")
        canonical = sorted(
            entries,
            key=lambda item: (item["kind"], item["name"], item["id"] or ""),
        )
        if entries != canonical:
            raise ValueError("API runtime migration approval operation identities are not canonical")
    if receipt["summary"]["total"] != sum(receipt["summary"][name] for name in ("creating", "updating", "deleting")):
        raise ValueError("API runtime migration approval total is malformed")
    validate_migration_approval_operations(receipt["summary"], operations)
    return receipt
