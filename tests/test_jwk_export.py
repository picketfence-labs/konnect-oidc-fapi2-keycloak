#!/usr/bin/env python3
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def decode_uint(value):
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + padding), "big")


with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    private_key = temporary / "private.pem"
    jwk_path = temporary / "private.jwk"
    env_path = temporary / "jwk.env"

    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-quiet",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-out",
            str(private_key),
        ],
        check=True,
    )
    subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "export-rsa-jwk.py"),
            str(private_key),
            str(jwk_path),
            str(env_path),
        ],
        check=True,
    )

    jwk = json.loads(jwk_path.read_text())
    assert set(jwk) == {"kty", "kid", "use", "alg", "n", "e", "d", "p", "q", "dp", "dq", "qi"}
    public_der = subprocess.check_output(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"]
    )
    expected_kid = base64.urlsafe_b64encode(hashlib.sha256(public_der).digest()).rstrip(b"=").decode()
    assert (jwk["kty"], jwk["kid"], jwk["use"], jwk["alg"]) == (
        "RSA",
        expected_kid,
        "sig",
        "PS256",
    )
    assert all("=" not in jwk[field] for field in ("n", "e", "d", "p", "q", "dp", "dq", "qi"))

    n, e, d, p, q, dp, dq, qi = (
        decode_uint(jwk[field]) for field in ("n", "e", "d", "p", "q", "dp", "dq", "qi")
    )
    assert n == p * q
    assert dp == d % (p - 1)
    assert dq == d % (q - 1)
    assert qi == pow(q, -1, p)
    assert e == 65537

    env_lines = env_path.read_text().splitlines()
    assert env_lines[0] == f"DECK_ROUTE_B_JWK_KID={jwk['kid']}"
    assert env_lines[1] == f"DECK_ROUTE_B_JWK_N={jwk['n']}"
    assert env_lines[2] == f"DECK_ROUTE_B_JWK_E={jwk['e']}"
    assert json.loads(env_lines[3].removeprefix("ROUTE_B_JWK='").removesuffix("'")) == jwk
    assert stat.S_IMODE(jwk_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600

print("JWK export checks: PASS")
