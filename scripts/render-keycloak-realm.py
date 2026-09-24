#!/usr/bin/env python3
"""Render the gitignored Keycloak realm from a reviewable template."""

import json
import os
import sys
from pathlib import Path


def replace(value, substitutions):
    if isinstance(value, dict):
        return {key: replace(item, substitutions) for key, item in value.items()}
    if isinstance(value, list):
        return [replace(item, substitutions) for item in value]
    if isinstance(value, str):
        for marker, replacement in substitutions.items():
            value = value.replace(marker, replacement)
    return value


if len(sys.argv) != 4:
    raise SystemExit("usage: render-keycloak-realm.py TEMPLATE OUTPUT ROUTE_B_PUBLIC_KEY")

template = Path(sys.argv[1])
output = Path(sys.argv[2])
public_key = Path(sys.argv[3]).read_text()

substitutions = {
    "__SALES_PASSWORD__": os.environ["SALES_PASSWORD"],
    "__ENGINEERING_PASSWORD__": os.environ["ENGINEERING_PASSWORD"],
    "__ROUTE_B_PUBLIC_KEY__": public_key,
}

realm = replace(json.loads(template.read_text()), substitutions)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(realm, indent=2) + "\n")
output.chmod(0o600)
