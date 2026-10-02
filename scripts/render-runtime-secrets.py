#!/usr/bin/env python3
"""Render common credentials and role-scoped decK Vault input files."""

import json
import os
import sys
import tempfile
from pathlib import Path


def read_simple_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError("invalid generated secret entry")
        values[key] = value
    return values


def escaped_pem(path):
    return json.dumps(path.read_text(), ensure_ascii=True)[1:-1]


def write_role_env(path, values):
    # Compose's dotenv parser expands escaped newlines in double-quoted values.
    safe_write(path, "".join(f"{name}={json.dumps(value, ensure_ascii=True)}\n" for name, value in values.items()))


def safe_write(path, content):
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


if len(sys.argv) != 4:
    raise SystemExit("usage: render-runtime-secrets.py SECRETS_ENV PKI_DIR OUTPUT_DIR")

os.umask(0o077)
secrets_path, pki_dir, output_dir = map(Path, sys.argv[1:])
secrets = read_simple_env(secrets_path)
missing = [
    name for name in ("KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD") if not secrets.get(name)
]
if missing:
    raise ValueError("required runtime credentials are missing")

output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(output_dir, 0o700)
runtime_env = output_dir / "runtime.env"
safe_write(
    runtime_env,
    "".join(
        f"{name}={json.dumps(secrets[name])}\n"
        for name in ("KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
    ),
)

ca = escaped_pem(pki_dir / "ca.crt")
roles = {
    "runtime-api.json": {
        "DECK_FAPI_CA_CERT_YAML": ca,
        "DECK_API_INTROSPECTION_CERT_YAML": escaped_pem(pki_dir / "api-introspection.crt"),
        "API_INTROSPECTION_KEY": (pki_dir / "api-introspection.key").read_text(),
        "DECK_API_UPSTREAM_CERT_YAML": escaped_pem(pki_dir / "api-upstream.crt"),
        "API_UPSTREAM_KEY": (pki_dir / "api-upstream.key").read_text(),
    },
    "runtime-third-party.json": {
        "DECK_FAPI_CA_CERT_YAML": ca,
        "DECK_ROUTE_A_TLS_CERT_YAML": escaped_pem(pki_dir / "route-a.crt"),
        "ROUTE_A_TLS_KEY": (pki_dir / "route-a.key").read_text(),
        "DECK_ROUTE_B_TLS_CERT_YAML": escaped_pem(pki_dir / "route-b.crt"),
        "ROUTE_B_TLS_KEY": (pki_dir / "route-b.key").read_text(),
    },
}
for filename, values in roles.items():
    path = output_dir / filename
    safe_write(path, json.dumps(values, ensure_ascii=True) + "\n")

write_role_env(output_dir / "runtime-api.env", {
    "API_INTROSPECTION_KEY": (pki_dir / "api-introspection.key").read_text(),
    "API_UPSTREAM_KEY": (pki_dir / "api-upstream.key").read_text(),
})
write_role_env(output_dir / "runtime-third-party.env", {
    "ROUTE_A_TLS_KEY": (pki_dir / "route-a.key").read_text(),
    "ROUTE_B_TLS_KEY": (pki_dir / "route-b.key").read_text(),
    "FAPI_AS_TRANSPORT_ISSUER": "https://localhost:8444/realms/fapi-demo",
    "FAPI_AS_TRANSPORT_INTERNAL_ORIGIN": "https://keycloak:8443",
})

print("Rendered role-scoped decK secret inputs under .generated/.")
