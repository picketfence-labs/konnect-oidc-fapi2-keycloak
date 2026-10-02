#!/usr/bin/env python3
"""Reconcile the local Keycloak user profile and generated demo users."""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REALM = "fapi-demo"
BASE_URL = os.environ.get("KEYCLOAK_ADMIN_URL", "https://localhost:8444")
CLIENT_IDS = {
    "third-party-fapi-mtls",
    "third-party-fapi-pkj-mtls",
    "api-gateway-introspection",
}
CLIENT_ADMIN_FIELDS = (
    "clientId",
    "name",
    "enabled",
    "protocol",
    "publicClient",
    "consentRequired",
    "fullScopeAllowed",
    "clientAuthenticatorType",
    "standardFlowEnabled",
    "implicitFlowEnabled",
    "directAccessGrantsEnabled",
    "serviceAccountsEnabled",
    "redirectUris",
    "webOrigins",
    "attributes",
)
MAPPER_ADMIN_FIELDS = ("name", "protocol", "protocolMapper", "config")
REALM_ADMIN_FIELDS = (
    "realm",
    "enabled",
    "sslRequired",
    "defaultSignatureAlgorithm",
    "accessCodeLifespan",
    "revokeRefreshToken",
    "refreshTokenMaxReuse",
    "clientPolicies",
    "clientProfiles",
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward the admin bearer token to a redirect target."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def read_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def request(path, context, method="GET", token=None, body=None, form=None):
    headers = {"Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    elif form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode()

    target = f"{BASE_URL}{path}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirectHandler()
    )
    try:
        with opener.open(
            urllib.request.Request(target, data=data, headers=headers, method=method),
            timeout=10,
        ) as response:
            payload = response.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise RuntimeError(
            f"{method} {path} returned HTTP {status}"
        ) from None


def client_admin_payload(desired):
    """Return only the explicitly managed client fields."""
    if not isinstance(desired, dict):
        raise RuntimeError("desired Keycloak client is malformed")
    allowed = set(CLIENT_ADMIN_FIELDS) | {"protocolMappers"}
    if set(desired) - allowed or set(CLIENT_ADMIN_FIELDS) - set(desired):
        raise RuntimeError("desired Keycloak client fields are incomplete or unexpected")
    if not isinstance(desired["clientId"], str) or not desired["clientId"]:
        raise RuntimeError("desired Keycloak client ID is empty")
    if not isinstance(desired["attributes"], dict):
        raise RuntimeError("desired Keycloak client attributes are malformed")
    if any(not isinstance(desired[field], list) for field in ("redirectUris", "webOrigins")):
        raise RuntimeError("desired Keycloak client URI lists are malformed")
    mappers = desired["protocolMappers"]
    if not isinstance(mappers, list):
        raise RuntimeError("desired Keycloak protocol mappers are malformed")
    names = [mapper.get("name") for mapper in mappers if isinstance(mapper, dict)]
    if (
        len(names) != len(mappers)
        or any(not isinstance(name, str) or not name for name in names)
        or len(names) != len(set(names))
    ):
        raise RuntimeError("desired Keycloak protocol mapper names are duplicated or malformed")
    return {field: desired[field] for field in CLIENT_ADMIN_FIELDS}


def mapper_admin_payload(desired):
    if not isinstance(desired, dict) or set(desired) != set(MAPPER_ADMIN_FIELDS):
        raise RuntimeError("desired Keycloak protocol mapper fields are incomplete or unexpected")
    if not all(isinstance(desired[field], str) and desired[field] for field in MAPPER_ADMIN_FIELDS[:-1]):
        raise RuntimeError("desired Keycloak protocol mapper identity is malformed")
    if not isinstance(desired["config"], dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in desired["config"].items()
    ):
        raise RuntimeError("desired Keycloak protocol mapper config is malformed")
    return {field: desired[field] for field in MAPPER_ADMIN_FIELDS}


def plan_mapper_sync(desired_mappers, live_mappers):
    desired_payloads = [mapper_admin_payload(mapper) for mapper in desired_mappers]
    if len({mapper["name"] for mapper in desired_payloads}) != len(desired_payloads):
        raise RuntimeError("desired Keycloak protocol mapper names are duplicated")
    if not isinstance(live_mappers, list):
        raise RuntimeError("Keycloak protocol mapper list is malformed")
    live_by_name = {}
    for mapper in live_mappers:
        if not isinstance(mapper, dict) or not isinstance(mapper.get("name"), str):
            raise RuntimeError("Keycloak protocol mapper list is malformed")
        if mapper["name"] in live_by_name:
            raise RuntimeError("duplicate Keycloak protocol mapper names found")
        live_by_name[mapper["name"]] = mapper

    plan = []
    for desired in desired_payloads:
        current = live_by_name.get(desired["name"])
        if current is None:
            plan.append({"operation": "create", "payload": desired})
            continue
        current_id = current.get("id")
        if not isinstance(current_id, str) or not current_id:
            raise RuntimeError(f"Keycloak protocol mapper ID is missing for {desired['name']}")
        current_payload = {
            field: current.get(field) for field in MAPPER_ADMIN_FIELDS
        }
        if current_payload == desired:
            continue
        plan.append({
            "operation": "update",
            "mapper_id": current_id,
            "payload": desired,
        })
    return plan


def merge_named_entries(current, desired, label):
    if not isinstance(current, list) or not isinstance(desired, list):
        raise RuntimeError(f"Keycloak {label} list is malformed")
    positions = {}
    merged = list(current)
    for index, entry in enumerate(merged):
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise RuntimeError(f"Keycloak {label} entry is malformed")
        if entry["name"] in positions:
            raise RuntimeError(f"duplicate Keycloak {label} names found")
        positions[entry["name"]] = index
    desired_names = set()
    for entry in desired:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise RuntimeError(f"desired Keycloak {label} entry is malformed")
        if entry["name"] in desired_names:
            raise RuntimeError(f"duplicate desired Keycloak {label} names found")
        desired_names.add(entry["name"])
        index = positions.get(entry["name"])
        if index is None:
            positions[entry["name"]] = len(merged)
            merged.append(entry)
        else:
            merged[index] = {**merged[index], **entry}
    return merged


def realm_admin_payload(current, desired):
    if not isinstance(current, dict) or not isinstance(desired, dict):
        raise RuntimeError("Keycloak realm representation is malformed")
    if set(REALM_ADMIN_FIELDS) - set(desired):
        raise RuntimeError("desired Keycloak realm fields are incomplete")
    payload = {field: desired[field] for field in REALM_ADMIN_FIELDS if field not in {"clientPolicies", "clientProfiles"}}
    for field, collection, label in (
        ("clientPolicies", "policies", "client policy"),
        ("clientProfiles", "profiles", "client profile"),
    ):
        live_group = current.get(field, {})
        desired_group = desired[field]
        if not isinstance(live_group, dict) or not isinstance(desired_group, dict):
            raise RuntimeError(f"Keycloak {label} configuration is malformed")
        group = dict(live_group)
        group[collection] = merge_named_entries(
            live_group.get(collection, []), desired_group.get(collection, []), label
        )
        payload[field] = group
    return {
        field: value
        for field, value in payload.items()
        if current.get(field) != value
    }


def plan_client_sync(desired_clients, matches_by_client_id):
    """Build an allowlisted, non-destructive create/update plan."""
    if not isinstance(desired_clients, list):
        raise RuntimeError("desired Keycloak client list is malformed")
    desired_ids = [client.get("clientId") for client in desired_clients if isinstance(client, dict)]
    if (
        len(desired_ids) != len(desired_clients)
        or any(not isinstance(client_id, str) for client_id in desired_ids)
        or set(desired_ids) != CLIENT_IDS
        or len(desired_ids) != len(CLIENT_IDS)
    ):
        raise RuntimeError("desired Keycloak client inventory does not match WP2")

    plan = []
    for desired in desired_clients:
        payload = client_admin_payload(desired)
        client_id = payload["clientId"]
        matches = matches_by_client_id.get(client_id)
        if not isinstance(matches, list):
            raise RuntimeError(f"Keycloak client lookup is malformed for {client_id}")
        if len(matches) > 1:
            raise RuntimeError(f"duplicate Keycloak clients found for {client_id}")
        if not matches:
            plan.append({"operation": "create", "client_id": client_id, "payload": payload})
            continue
        current = matches[0]
        if not isinstance(current, dict) or current.get("clientId") != client_id:
            raise RuntimeError(f"Keycloak client lookup is inconsistent for {client_id}")
        client_uuid = current.get("id")
        if not isinstance(client_uuid, str) or not client_uuid:
            raise RuntimeError(f"Keycloak client ID is missing for {client_id}")
        current_payload = {field: current.get(field) for field in CLIENT_ADMIN_FIELDS}
        current_attributes = current_payload.get("attributes")
        desired_attributes = payload["attributes"]
        if isinstance(current_attributes, dict) and all(
            current_attributes.get(key) == value
            for key, value in desired_attributes.items()
        ):
            current_payload["attributes"] = desired_attributes
        if current_payload == payload:
            plan.append({
                "operation": "noop",
                "client_id": client_id,
                "client_uuid": client_uuid,
                "payload": payload,
                "current": current,
            })
        else:
            plan.append({
                "operation": "update",
                "client_id": client_id,
                "client_uuid": client_uuid,
                "payload": payload,
                "current": current,
            })
    return plan


def prepare_client_sync(desired_clients, context, token):
    matches_by_client_id = {}
    for client_id in sorted(CLIENT_IDS):
        query = urllib.parse.urlencode({"clientId": client_id})
        matches = request(
            f"/admin/realms/{REALM}/clients?{query}", context, token=token
        )
        if not isinstance(matches, list):
            raise RuntimeError(f"Keycloak client lookup is malformed for {client_id}")
        matches_by_client_id[client_id] = matches
    plan = plan_client_sync(desired_clients, matches_by_client_id)
    for action, desired in zip(plan, desired_clients):
        live_mappers = []
        if action["operation"] in {"update", "noop"}:
            client_uuid = action["client_uuid"]
            live_mappers = request(
                f"/admin/realms/{REALM}/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models",
                context,
                token=token,
            )
        action["mapper_plan"] = plan_mapper_sync(
            desired["protocolMappers"], live_mappers
        )
    return plan


def apply_client_sync(plan, context, token):
    client_uuids = {}
    for action in plan:
        client_id = action["client_id"]
        if action["operation"] == "update":
            client_uuid = action["client_uuid"]
            update_body = {"id": client_uuid, **action["payload"]}
            current_attributes = action["current"].get("attributes")
            if isinstance(current_attributes, dict):
                update_body["attributes"] = {
                    **current_attributes,
                    **action["payload"]["attributes"],
                }
            request(
                f"/admin/realms/{REALM}/clients/{urllib.parse.quote(client_uuid, safe='')}",
                context,
                method="PUT",
                token=token,
                body=update_body,
            )
        elif action["operation"] == "create":
            request(
                f"/admin/realms/{REALM}/clients",
                context,
                method="POST",
                token=token,
                body=action["payload"],
            )
            query = urllib.parse.urlencode({"clientId": client_id})
            created = request(
                f"/admin/realms/{REALM}/clients?{query}", context, token=token
            )
            if not isinstance(created, list) or len(created) != 1:
                raise RuntimeError(f"Keycloak did not create exactly one client for {client_id}")
            client_uuid = created[0].get("id")
            if not isinstance(client_uuid, str) or not client_uuid:
                raise RuntimeError(f"Keycloak client ID is missing for {client_id}")
        else:
            client_uuid = action["client_uuid"]
        client_uuids[client_id] = client_uuid

    mapper_count = 0
    for action in plan:
        client_uuid = client_uuids[action["client_id"]]
        mapper_collection_path = (
            f"/admin/realms/{REALM}/clients/"
            f"{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models"
        )
        for mapper_action in action["mapper_plan"]:
            payload = mapper_action["payload"]
            if mapper_action["operation"] == "create":
                request(
                    mapper_collection_path,
                    context,
                    method="POST",
                    token=token,
                    body=payload,
                )
            else:
                mapper_id = mapper_action["mapper_id"]
                request(
                    f"{mapper_collection_path}/{urllib.parse.quote(mapper_id, safe='')}",
                    context,
                    method="PUT",
                    token=token,
                    body={"id": mapper_id, **payload},
                )
            mapper_count += 1
    changed_clients = sum(action["operation"] != "noop" for action in plan)
    return changed_clients, mapper_count


def verify_client_sync(desired_clients, context, token):
    plan = prepare_client_sync(desired_clients, context, token)
    if any(
        action["operation"] != "noop" or action["mapper_plan"]
        for action in plan
    ):
        raise RuntimeError("Keycloak client configuration did not converge")


def verify_realm_sync(desired_realm, context, token):
    remaining = prepare_realm_sync(desired_realm, context, token)
    if remaining:
        raise RuntimeError("Keycloak realm configuration did not converge")


def prepare_realm_sync(desired_realm, context, token):
    current = request(f"/admin/realms/{REALM}", context, token=token)
    if not isinstance(current, dict):
        raise RuntimeError("Keycloak realm representation is malformed")
    return realm_admin_payload(current, desired_realm)


def apply_realm_sync(payload, context, token):
    if payload:
        request(
            f"/admin/realms/{REALM}",
            context,
            method="PUT",
            token=token,
            body=payload,
        )
    return bool(payload)


def admin_token(context, secrets):
    return request(
        "/realms/master/protocol/openid-connect/token",
        context,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": secrets["KEYCLOAK_ADMIN_USERNAME"],
            "password": secrets["KEYCLOAK_ADMIN_PASSWORD"],
        },
    )["access_token"]


def wait_for_keycloak(context, secrets):
    last_error = None
    for _ in range(30):
        try:
            return admin_token(context, secrets)
        except (urllib.error.URLError, RuntimeError) as error:
            last_error = error
            time.sleep(2)
    raise RuntimeError("Keycloak did not become ready within 60 seconds") from last_error


def main():
    secrets = read_env(ROOT / ".generated/secrets.env")
    desired_realm = json.loads((ROOT / ".generated/keycloak/realm.json").read_text())
    desired_profile = json.loads((ROOT / "keycloak/user-profile.json").read_text())

    context = ssl.create_default_context(cafile=ROOT / ".generated/pki/ca.crt")
    # Existing workspaces may have a development CA generated before keyUsage
    # was added. Keep CA and hostname checks while accepting that local CA.
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT

    token = wait_for_keycloak(context, secrets)
    realm_plan = prepare_realm_sync(desired_realm, context, token)
    client_plan = prepare_client_sync(desired_realm["clients"], context, token)
    synced_clients, synced_mappers = apply_client_sync(
        client_plan, context, token
    )
    realm_changed = apply_realm_sync(realm_plan, context, token)
    verify_client_sync(desired_realm["clients"], context, token)
    verify_realm_sync(desired_realm, context, token)
    live_profile = request(
        f"/admin/realms/{REALM}/users/profile", context, token=token
    )
    desired_attribute_names = {
        attribute["name"] for attribute in desired_profile["attributes"]
    }
    live_profile["attributes"] = [
        attribute
        for attribute in live_profile["attributes"]
        if attribute["name"] not in desired_attribute_names
    ] + desired_profile["attributes"]
    request(
        f"/admin/realms/{REALM}/users/profile",
        context,
        method="PUT",
        token=token,
        body=live_profile,
    )

    synced = []
    for desired_user in desired_realm["users"]:
        username = desired_user["username"]
        query = urllib.parse.urlencode({"username": username, "exact": "true"})
        matches = request(
            f"/admin/realms/{REALM}/users?{query}", context, token=token
        )
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one Keycloak user for {username}")

        user_id = matches[0]["id"]
        live_user = request(
            f"/admin/realms/{REALM}/users/{user_id}", context, token=token
        )
        for field in ("firstName", "lastName"):
            if desired_user.get(field):
                live_user[field] = desired_user[field]
        attributes = live_user.get("attributes", {})
        attributes.update(desired_user["attributes"])
        live_user["attributes"] = attributes
        request(
            f"/admin/realms/{REALM}/users/{user_id}",
            context,
            method="PUT",
            token=token,
            body=live_user,
        )
        verified = request(
            f"/admin/realms/{REALM}/users/{user_id}", context, token=token
        )
        if any(
            verified.get("attributes", {}).get(name) != value
            for name, value in desired_user["attributes"].items()
        ):
            raise RuntimeError(f"Keycloak did not retain routing attributes for {username}")
        synced.append(username)

    print(
        f"Synced {len(desired_attribute_names)} Keycloak profile attributes, "
        f"{len(synced)} demo users, {synced_clients} clients, and "
        f"{synced_mappers} protocol mappers. Realm WP2 settings "
        f"{'updated' if realm_changed else 'already matched'}. "
        "Legacy clients were left untouched."
    )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, RuntimeError) as error:
        print(f"Keycloak demo data sync failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
