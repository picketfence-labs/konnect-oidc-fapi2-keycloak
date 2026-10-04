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
    output = temporary / "generated"
    output.mkdir()
    (output / "keycloak").mkdir()

    private_jwk = {
        "kty": "RSA", "kid": "test-kid", "use": "sig", "alg": "PS256",
        "n": "test-n", "e": "AQAB", "d": "test-d", "p": "test-p", "q": "test-q",
        "dp": "test-dp", "dq": "test-dq", "qi": "test-qi",
    }
    (output / "keycloak" / "route-b-private.jwk").write_text(json.dumps(private_jwk))

    secrets.write_text(
        "KEYCLOAK_ADMIN_USERNAME=admin\n"
        "KEYCLOAK_ADMIN_PASSWORD=password-with-symbols_123\n"
    )
    for identity in ("route-a", "route-b", "api-introspection", "api-upstream", "ca"):
        (pki / f"{identity}.crt").write_text(
            "-----BEGIN CERTIFICATE-----\ncertificate\n-----END CERTIFICATE-----\n"
        )
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        private_key_end = "-----END " + "PRIVATE KEY-----"
        (pki / f"{identity}.key").write_text(
            f"{private_key_marker}\nprivate\n{private_key_end}\n"
        )

    rendered = subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "render-runtime-secrets.py"),
            str(secrets),
            str(pki),
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.dumps(private_jwk, separators=(",", ":")) not in rendered.stdout
    assert json.dumps(private_jwk, separators=(",", ":")) not in rendered.stderr

    runtime = {}
    for line in (output / "runtime.env").read_text().splitlines():
        name, value = line.split("=", 1)
        runtime[name] = json.loads(value)
    assert runtime == {
        "KEYCLOAK_ADMIN_USERNAME": "admin",
        "KEYCLOAK_ADMIN_PASSWORD": "password-with-symbols_123",
    }

    api = json.loads((output / "runtime-api.json").read_text())
    third_party = json.loads((output / "runtime-third-party.json").read_text())
    assert api["DECK_API_INTROSPECTION_CERT_YAML"].startswith("-----BEGIN CERTIFICATE-----\\n")
    assert api["API_INTROSPECTION_KEY"].endswith(f"{private_key_end}\n")
    assert api["API_UPSTREAM_KEY"].endswith(f"{private_key_end}\n")
    assert not any("route-a" in name or "route-b" in name or "third-party" in name for name in api)
    assert third_party["ROUTE_A_TLS_KEY"].endswith(f"{private_key_end}\n")
    assert third_party["ROUTE_B_TLS_KEY"].endswith(f"{private_key_end}\n")
    assert not any("api-introspection" in name or "api-upstream" in name for name in third_party)
    api_env = {}
    for line in (output / "runtime-api.env").read_text().splitlines():
        name, value = line.split("=", 1)
        api_env[name] = json.loads(value)
    third_party_env = {}
    for line in (output / "runtime-third-party.env").read_text().splitlines():
        name, value = line.split("=", 1)
        third_party_env[name] = json.loads(value)
    assert set(api_env) == {"API_INTROSPECTION_KEY", "API_UPSTREAM_KEY"}
    assert api_env["API_INTROSPECTION_KEY"].endswith(f"{private_key_end}\n")
    assert api_env["API_UPSTREAM_KEY"].endswith(f"{private_key_end}\n")
    assert set(third_party_env) == {
        "ROUTE_A_TLS_KEY", "ROUTE_B_TLS_KEY", "ROUTE_B_JWK",
        "FAPI_AS_TRANSPORT_ISSUER", "FAPI_AS_TRANSPORT_INTERNAL_ORIGIN"
    }
    assert third_party_env["ROUTE_A_TLS_KEY"].endswith(f"{private_key_end}\n")
    assert third_party_env["ROUTE_B_TLS_KEY"].endswith(f"{private_key_end}\n")
    assert json.loads(third_party_env["ROUTE_B_JWK"]) == private_jwk
    assert "ROUTE_B_JWK" not in api_env
    assert third_party_env["FAPI_AS_TRANSPORT_ISSUER"] == "https://localhost:8444/realms/fapi-demo"
    assert all(stat.S_IMODE((output / name).stat().st_mode) == 0o600 for name in (
        "runtime.env", "runtime-api.json", "runtime-third-party.json", "runtime-api.env", "runtime-third-party.env"
    ))
    assert stat.S_IMODE(output.stat().st_mode) == 0o700

print("runtime secret rendering checks: PASS")
