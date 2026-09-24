#!/usr/bin/env python3
"""Export an RSA private key as a JWK and shell-safe generated env values."""

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def read_length(data, offset):
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4:
        raise ValueError("unsupported DER length")
    end = offset + count
    return int.from_bytes(data[offset:end], "big"), end


def read_value(data, offset, expected_tag):
    if offset >= len(data) or data[offset] != expected_tag:
        raise ValueError(f"unexpected DER tag at offset {offset}")
    length, start = read_length(data, offset + 1)
    end = start + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return data[start:end], end


def read_rsa_private_key(path):
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(path), "-traditional", "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sequence, end = read_value(result.stdout, 0, 0x30)
    if end != len(result.stdout):
        raise ValueError("unexpected trailing DER data")

    values = []
    offset = 0
    while offset < len(sequence):
        encoded, offset = read_value(sequence, offset, 0x02)
        values.append(int.from_bytes(encoded, "big"))
    if len(values) != 9 or values[0] not in (0, 1):
        raise ValueError("unsupported RSA private key")
    return values[1:]


def base64url_uint(value):
    size = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


def keycloak_key_id(path):
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return base64.urlsafe_b64encode(hashlib.sha256(result.stdout).digest()).rstrip(b"=").decode()


if len(sys.argv) != 4:
    raise SystemExit("usage: export-rsa-jwk.py PRIVATE_KEY JWK_OUTPUT ENV_OUTPUT")

private_key, jwk_output, env_output = map(Path, sys.argv[1:])
n, e, d, p, q, dp, dq, qi = read_rsa_private_key(private_key)
jwk = {
    "kty": "RSA",
    "kid": keycloak_key_id(private_key),
    "use": "sig",
    "alg": "PS256",
    "n": base64url_uint(n),
    "e": base64url_uint(e),
    "d": base64url_uint(d),
    "p": base64url_uint(p),
    "q": base64url_uint(q),
    "dp": base64url_uint(dp),
    "dq": base64url_uint(dq),
    "qi": base64url_uint(qi),
}

jwk_output.parent.mkdir(parents=True, exist_ok=True)
jwk_output.write_text(json.dumps(jwk, separators=(",", ":")) + "\n")
jwk_output.chmod(0o600)

compact = json.dumps(jwk, separators=(",", ":"))
env_output.write_text(
    f"DECK_ROUTE_B_JWK_KID={jwk['kid']}\n"
    f"DECK_ROUTE_B_JWK_N={jwk['n']}\n"
    f"DECK_ROUTE_B_JWK_E={jwk['e']}\n"
    f"ROUTE_B_JWK='{compact}'\n"
)
env_output.chmod(0o600)

# Avoid inheriting a permissive umask through callers that invoke this directly.
os.chmod(jwk_output, 0o600)
os.chmod(env_output, 0o600)
