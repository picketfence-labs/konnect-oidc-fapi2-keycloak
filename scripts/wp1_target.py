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

import yaml
from yaml.constructor import ConstructorError

from wp1 import ROUTES, compare_schema_hashes, endpoint_host, validate_selector, validate_targets


PLUGIN_FILES = {
    "fapi-as-mtls-transport": Path("kong/plugins/fapi-as-mtls-transport/schema.lua"),
    "fapi-client-auth-bridge": Path("kong/plugins/fapi-client-auth-bridge/schema.lua"),
}
FOUNDATION_FILES = {
    "api": Path("kong/foundation/api.yaml"),
    "third-party": Path("kong/foundation/third-party.yaml"),
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
    state = FOUNDATION_FILES[gateway] if stage == "foundation" else None
    if operation in {"diff", "sync"}:
        if stage == "runtime":
            runtime_state = root / ("kong/api-gateway.yaml" if gateway == "api" else "kong/third-party-gateway.yaml")
            if not runtime_state.is_file():
                raise ValueError("runtime state is incomplete or unavailable to this work package")
            raise ValueError("runtime state requires its owning WP acceptance before diff/sync")
        if not (root / state).is_file():
            raise ValueError(f"foundation state is missing: {state}")

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
    ca_certificates = parsed.get("ca_certificates")
    expected_ids = {
        "api": {
            "certificates": {"44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"},
            "ca_certificates": {"77777777-7777-4777-8777-777777777777"},
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
        "api": ("77777777-7777-4777-8777-777777777777", "DECK_FAPI_CA_CERT_YAML"),
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
            elif (entity["id"], entity["cert"]) != (
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
