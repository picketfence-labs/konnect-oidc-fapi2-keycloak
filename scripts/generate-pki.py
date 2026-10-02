#!/usr/bin/env python3
"""Create the isolated, short-lived development certificate identities."""

from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path


def run(args: list[str]) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ensure_ca(pki: Path) -> None:
    key, cert = pki / "ca.key", pki / "ca.crt"
    if key.exists() or cert.exists():
        if key.is_file() and cert.is_file():
            return
        raise ValueError("refusing to overwrite incomplete development CA")
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-nodes", "-days", "30",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-subj", "/CN=FAPI demo development CA",
        "-keyout", str(key), "-out", str(cert),
    ])


def issue(pki: Path, name: str, common_name: str, usage: str, san: str = "") -> None:
    cert, key = pki / f"{name}.crt", pki / f"{name}.key"
    csr, extension = pki / f"{name}.csr", pki / f"{name}.ext"
    if cert.exists() or key.exists() or csr.exists() or extension.exists():
        if cert.is_file() and key.is_file() and not csr.exists() and not extension.exists():
            return
        raise ValueError(f"refusing to overwrite incomplete certificate identity: {name}")
    run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)])
    run(["openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={common_name}", "-out", str(csr)])
    lines = [
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        f"extendedKeyUsage={usage}",
    ]
    if san:
        lines.append(f"subjectAltName={san}")
    extension.write_text("\n".join(lines) + "\n")
    run([
        "openssl", "x509", "-req", "-in", str(csr), "-CA", str(pki / "ca.crt"),
        "-CAkey", str(pki / "ca.key"), "-CAcreateserial", "-days", "30", "-sha256",
        "-extfile", str(extension), "-out", str(cert),
    ])
    csr.unlink()
    extension.unlink()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: generate-pki.py PKI_DIR", file=sys.stderr)
        return 2
    os.umask(0o077)
    pki = Path(sys.argv[1])
    pki.mkdir(mode=0o700, parents=True, exist_ok=True)
    ensure_ca(pki)
    identities = (
        ("keycloak", "keycloak", "serverAuth", "DNS:keycloak,DNS:localhost,IP:127.0.0.1"),
        ("kong-proxy", "localhost", "serverAuth", "DNS:localhost,IP:127.0.0.1"),
        ("ui", "localhost", "serverAuth", "DNS:localhost,IP:127.0.0.1"),
        ("pop-verifier", "pop-verifier", "serverAuth", "DNS:pop-verifier,DNS:localhost,IP:127.0.0.1"),
        ("route-a", "kong-fapi-mtls", "clientAuth", ""),
        ("route-b", "kong-fapi-pkj-mtls", "clientAuth", ""),
        ("third-party-metadata", "third-party-metadata", "clientAuth", ""),
        ("api-gateway", "kong-api", "serverAuth", "DNS:kong-api,DNS:localhost,IP:127.0.0.1"),
        ("api-introspection", "api-gateway-introspection", "clientAuth", ""),
        ("api-upstream", "api-gateway-upstream", "clientAuth", ""),
    )
    for name, common_name, usage, san in identities:
        issue(pki, name, common_name, usage, san)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Development PKI generation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
