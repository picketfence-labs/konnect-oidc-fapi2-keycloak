#!/usr/bin/env python3
"""Pure WP1 validation helpers shared by CLI wrappers and unit tests."""

from __future__ import annotations

from hashlib import sha256
from uuid import UUID
from urllib.parse import urlsplit


ROUTES = (
    {
        "route_id": "754519ff-b0b9-5ed5-94c0-e453d260c6c4",
        "logical_route": "A",
        "client_id": "third-party-fapi-mtls",
        "certificate_file": "/etc/kong/fapi/route-a.crt",
        "key_file": "/etc/kong/fapi/route-a.key",
    },
    {
        "route_id": "0f45debe-a3a6-5207-aea3-637227fb96f2",
        "logical_route": "B",
        "client_id": "third-party-fapi-pkj-mtls",
        "certificate_file": "/etc/kong/fapi/route-b.crt",
        "key_file": "/etc/kong/fapi/route-b.key",
    },
)


def validate_selector(gateway: str, stage: str | None, operation: str) -> None:
    if gateway not in {"api", "third-party"}:
        raise ValueError("GATEWAY must be api or third-party")
    if operation in {"diff", "sync"} and stage not in {"foundation", "runtime"}:
        raise ValueError("STAGE must be foundation or runtime")
    if operation == "schema" and stage is not None:
        raise ValueError("schema operations do not accept STAGE")


def endpoint_host(value: str) -> str:
    """Return a safe hostname from a computed Konnect endpoint."""
    if not isinstance(value, str) or not value or value != value.strip() or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in value
    ):
        raise ValueError("endpoint contains whitespace or control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port  # Force malformed ports to fail here.
    except (TypeError, ValueError) as exc:
        raise ValueError("endpoint is malformed") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port not in {None, 443}
    ):
        raise ValueError("endpoint must be an unambiguous HTTPS authority")
    return parsed.hostname.lower()


def validate_targets(targets: dict, expected_names: dict[str, str] | None = None) -> dict:
    if set(targets) != {"api", "third-party"}:
        raise ValueError("gateway target manifest must contain api and third-party")
    names: set[str] = set()
    ids: set[str] = set()
    normalized: dict[str, dict] = {}
    for gateway in ("api", "third-party"):
        target = targets[gateway]
        required = {
            "control_plane_id",
            "control_plane_name",
            "control_plane_endpoint",
            "telemetry_endpoint",
        }
        if not isinstance(target, dict) or set(target) != required:
            raise ValueError(f"{gateway} target fields are incomplete or unexpected")
        cp_id = target["control_plane_id"]
        cp_name = target["control_plane_name"]
        if not all(isinstance(v, str) and v.strip() for v in (cp_id, cp_name)):
            raise ValueError(f"{gateway} control plane ID/name is empty")
        try:
            if str(UUID(cp_id)) != cp_id.lower():
                raise ValueError("non-canonical UUID")
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"{gateway} control plane ID is not a UUID") from exc
        if cp_id in ids:
            raise ValueError("API and third-party control plane IDs must differ")
        if cp_name in names:
            raise ValueError("API and third-party control plane names must differ")
        if expected_names and cp_name != expected_names[gateway]:
            raise ValueError(f"{gateway} control plane name does not match local configuration")
        cp_host = endpoint_host(target["control_plane_endpoint"])
        tp_host = endpoint_host(target["telemetry_endpoint"])
        if cp_host == tp_host:
            raise ValueError(f"{gateway} control plane and telemetry endpoints are ambiguous")
        ids.add(cp_id)
        names.add(cp_name)
        normalized[gateway] = {
            **target,
            "control_plane_host": cp_host,
            "telemetry_host": tp_host,
        }
    return normalized


def validate_route_manifest(routes: list[dict]) -> None:
    if routes != list(ROUTES):
        raise ValueError("third-party Route manifest does not match the fixed A/B identities")


def normalize_schema(source: str) -> str:
    if not isinstance(source, str) or not source:
        raise ValueError("schema Lua must be a non-empty string")
    source = source.replace("\r\n", "\n")
    return source[:-1] if source.endswith("\n") else source


def schema_hash(source: str) -> str:
    return sha256(normalize_schema(source).encode("utf-8")).hexdigest()


def collect_schema_pages(pages: list[dict], expected_names: set[str]) -> dict[str, str]:
    """Validate a complete mocked/recorded list response sequence."""
    found: dict[str, str] = {}
    expected_total: int | None = None
    seen_cursors: set[str] = set()
    for index, page in enumerate(pages):
        if not isinstance(page, dict) or not isinstance(page.get("items"), list):
            raise ValueError("schema page is missing items")
        page_meta = page.get("page")
        total = page_meta.get("total_count") if isinstance(page_meta, dict) else None
        if type(total) is not int or total < 0:
            raise ValueError("schema page is missing page.total_count")
        has_next = page_meta.get("has_next_page")
        cursor = page_meta.get("next_cursor")
        if not isinstance(has_next, bool):
            raise ValueError("schema page has_next_page is malformed")
        if has_next and (not isinstance(cursor, str) or not cursor.strip()):
            raise ValueError("schema page next_cursor is missing or malformed")
        request_cursor = page.get("request_cursor")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise ValueError("schema page total_count changed during pagination")
        for item in page["items"]:
            if not isinstance(item, dict):
                raise ValueError("schema list item is malformed")
            name = item.get("name")
            source = item.get("lua_schema")
            if not isinstance(name, str) or not name or not isinstance(source, str) or not source:
                raise ValueError("schema list item is missing name or original lua_schema")
            if name in found:
                raise ValueError(f"duplicate schema entry: {name}")
            found[name] = source
        count = sum(1 for _ in found)
        if has_next and index == len(pages) - 1:
            raise ValueError("schema pagination is incomplete")
        if not has_next and index != len(pages) - 1:
            raise ValueError("schema pages continue after total_count was reached")
        if has_next and count >= total:
            raise ValueError("schema pagination continues past page.total_count")
        if has_next and cursor in seen_cursors:
            raise ValueError("schema pagination cursor repeated")
        if has_next and request_cursor == cursor:
            raise ValueError("schema page cursor did not advance")
        if has_next:
            seen_cursors.add(cursor)
        if has_next and not page["items"]:
            raise ValueError("schema pagination made no progress")
    if expected_total != len(found):
        raise ValueError("schema pagination item count does not match page.total_count")
    missing = expected_names - set(found)
    if missing:
        raise ValueError("missing schema: " + ", ".join(sorted(missing)))
    return {name: found[name] for name in expected_names}


def compare_schema_hashes(expected: dict[str, str], observed: dict[str, str]) -> dict[str, dict[str, str]]:
    if set(expected) != set(observed):
        raise ValueError("schema inventory is incomplete or contains unexpected entries")
    result = {}
    for name in sorted(expected):
        want, got = schema_hash(expected[name]), schema_hash(observed[name])
        result[name] = {"expected_sha256": want, "observed_sha256": got}
        if want != got:
            raise ValueError(f"schema drift for {name}: expected {want}, observed {got}")
    return result
