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
    try:
        with urllib.request.urlopen(
            urllib.request.Request(target, data=data, headers=headers, method=method),
            context=context,
            timeout=10,
        ) as response:
            payload = response.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read())
            detail = next(
                (
                    payload[key]
                    for key in ("errorMessage", "error_description", "error")
                    if payload.get(key)
                ),
                "request rejected",
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            detail = "request rejected"
        raise RuntimeError(
            f"{method} {path} returned HTTP {error.code}: {detail}"
        ) from error


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
    desired_realm = json.loads((ROOT / "keycloak/realm-template.json").read_text())
    desired_profile = json.loads((ROOT / "keycloak/user-profile.json").read_text())

    context = ssl.create_default_context(cafile=ROOT / ".generated/pki/ca.crt")
    # Existing workspaces may have a development CA generated before keyUsage
    # was added. Keep CA and hostname checks while accepting that local CA.
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT

    token = wait_for_keycloak(context, secrets)
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

    synced_mappers = 0
    for desired_client in desired_realm["clients"]:
        client_id = desired_client["clientId"]
        query = urllib.parse.urlencode({"clientId": client_id})
        matches = request(
            f"/admin/realms/{REALM}/clients?{query}", context, token=token
        )
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one Keycloak client for {client_id}")

        client_uuid = matches[0]["id"]
        live_mappers = request(
            f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
            context,
            token=token,
        )
        live_by_name = {mapper["name"]: mapper for mapper in live_mappers}
        for desired_mapper in desired_client["protocolMappers"]:
            live_mapper = live_by_name.get(desired_mapper["name"])
            if live_mapper is None:
                request(
                    f"/admin/realms/{REALM}/clients/{client_uuid}/"
                    "protocol-mappers/models",
                    context,
                    method="POST",
                    token=token,
                    body=desired_mapper,
                )
            else:
                live_mapper["protocol"] = desired_mapper["protocol"]
                live_mapper["protocolMapper"] = desired_mapper["protocolMapper"]
                live_mapper.setdefault("config", {}).update(desired_mapper["config"])
                request(
                    f"/admin/realms/{REALM}/clients/{client_uuid}/"
                    f"protocol-mappers/models/{live_mapper['id']}",
                    context,
                    method="PUT",
                    token=token,
                    body=live_mapper,
                )
            synced_mappers += 1

    print(
        f"Synced {len(desired_attribute_names)} Keycloak profile attributes, "
        f"{len(synced)} demo users, and {synced_mappers} protocol mappers."
    )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, RuntimeError) as error:
        print(f"Keycloak demo data sync failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
