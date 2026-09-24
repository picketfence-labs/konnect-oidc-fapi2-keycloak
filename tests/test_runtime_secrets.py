#!/usr/bin/env python3
import json
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    pki = temporary / "pki"
    pki.mkdir()
    secrets = temporary / "secrets.env"
    jwk = temporary / "private.jwk"
    output = temporary / "runtime.env"

    secrets.write_text(
        "KEYCLOAK_ADMIN_USERNAME=admin\n"
        "KEYCLOAK_ADMIN_PASSWORD=password-with-symbols_123\n"
    )
    jwk.write_text('{"kty":"RSA","d":"private-value"}\n')
    for route in ("route-a", "route-b"):
        (pki / f"{route}.crt").write_text(
            "-----BEGIN CERTIFICATE-----\ncertificate\n-----END CERTIFICATE-----\n"
        )
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        private_key_end = "-----END " + "PRIVATE KEY-----"
        (pki / f"{route}.key").write_text(
            f"{private_key_marker}\nprivate\n{private_key_end}\n"
        )

    subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "render-runtime-secrets.py"),
            str(secrets),
            str(jwk),
            str(pki),
            str(output),
        ],
        check=True,
    )

    rendered = {}
    for line in output.read_text().splitlines():
        name, value = line.split("=", 1)
        rendered[name] = json.loads(value)

    assert rendered["KEYCLOAK_ADMIN_USERNAME"] == "admin"
    assert json.loads(rendered["ROUTE_B_JWK"])["d"] == "private-value"
    assert rendered["ROUTE_A_TLS_CERT"].endswith("-----END CERTIFICATE-----\n")
    assert rendered["ROUTE_A_TLS_KEY"].endswith(f"{private_key_end}\n")
    assert rendered["ROUTE_B_TLS_CERT"].endswith("-----END CERTIFICATE-----\n")
    assert rendered["ROUTE_B_TLS_KEY"].endswith(f"{private_key_end}\n")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

print("runtime secret rendering checks: PASS")
