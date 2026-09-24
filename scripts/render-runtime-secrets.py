#!/usr/bin/env python3
"""Render Docker Compose runtime secrets with dotenv-safe quoting."""

import json
import os
import sys
from pathlib import Path


def read_simple_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError(f"invalid environment entry in {path}: {line!r}")
        values[key] = value
    return values


if len(sys.argv) != 5:
    raise SystemExit(
        "usage: render-runtime-secrets.py SECRETS_ENV PRIVATE_JWK PKI_DIR OUTPUT"
    )

secrets_path, jwk_path, pki_dir, output_path = map(Path, sys.argv[1:])
secrets = read_simple_env(secrets_path)
required = ("KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
missing = [name for name in required if not secrets.get(name)]
if missing:
    raise ValueError(f"missing required runtime values: {', '.join(missing)}")

values = {
    "KEYCLOAK_ADMIN_USERNAME": secrets["KEYCLOAK_ADMIN_USERNAME"],
    "KEYCLOAK_ADMIN_PASSWORD": secrets["KEYCLOAK_ADMIN_PASSWORD"],
    "ROUTE_B_JWK": jwk_path.read_text().strip(),
    "ROUTE_A_TLS_CERT": (pki_dir / "route-a.crt").read_text(),
    "ROUTE_A_TLS_KEY": (pki_dir / "route-a.key").read_text(),
    "ROUTE_B_TLS_CERT": (pki_dir / "route-b.crt").read_text(),
    "ROUTE_B_TLS_KEY": (pki_dir / "route-b.key").read_text(),
}

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(
    "".join(f"{name}={json.dumps(value)}\n" for name, value in values.items())
)
os.chmod(output_path, 0o600)
