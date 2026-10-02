#!/usr/bin/env python3
import hashlib
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts/generate-pki.py"


def run_openssl(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True, text=True).stdout


with tempfile.TemporaryDirectory() as directory:
    pki = Path(directory) / "pki"
    subprocess.run(["python3", str(GENERATOR), str(pki)], check=True)

    baseline = {
        name: hashlib.sha256((pki / name).read_bytes()).hexdigest()
        for name in ("route-a.crt", "route-a.key", "route-b.crt", "route-b.key")
    }
    protected = {
        name: hashlib.sha256((pki / name).read_bytes()).hexdigest()
        for name in ("route-b-pkj.key",)
        if (pki / name).exists()
    }
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(pki / "route-b-pkj.key")], check=True, capture_output=True)
    protected["route-b-pkj.key"] = hashlib.sha256((pki / "route-b-pkj.key").read_bytes()).hexdigest()
    subprocess.run(["python3", str(GENERATOR), str(pki)], check=True)
    for name, digest in {**baseline, **protected}.items():
        assert hashlib.sha256((pki / name).read_bytes()).hexdigest() == digest

    cases = {
        "third-party-metadata": ("third-party-metadata", "clientAuth", None),
        "api-gateway": ("kong-api", "serverAuth", "DNS:kong-api, DNS:localhost, IP Address:127.0.0.1"),
        "api-introspection": ("api-gateway-introspection", "clientAuth", None),
        "api-upstream": ("api-gateway-upstream", "clientAuth", None),
    }
    for name, (common_name, usage, san) in cases.items():
        cert_path, key_path = pki / f"{name}.crt", pki / f"{name}.key"
        subject = run_openssl("x509", "-in", str(cert_path), "-noout", "-nameopt", "RFC2253", "-subject")
        subject = re.sub(r"\s*=\s*", "=", subject)
        assert f"CN={common_name}" in subject
        key_details = run_openssl("x509", "-in", str(cert_path), "-noout", "-pubkey")
        temp_pub = pki / "public.pem"
        temp_pub.write_text(key_details)
        text = run_openssl("pkey", "-pubin", "-in", str(temp_pub), "-text_pub", "-noout")
        assert "Public-Key: (3072 bit)" in text
        temp_pub.unlink()
        usages = run_openssl("x509", "-in", str(cert_path), "-noout", "-ext", "extendedKeyUsage")
        expected_usage = {
            "clientAuth": "TLS Web Client Authentication",
            "serverAuth": "TLS Web Server Authentication",
        }[usage]
        assert expected_usage in usages
        start = datetime.strptime(run_openssl("x509", "-in", str(cert_path), "-noout", "-enddate").strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        assert 0 < (start - datetime.now(timezone.utc)).total_seconds() <= 30 * 24 * 60 * 60
        if san:
            sans = run_openssl("x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName")
            for expected in ("DNS:kong-api", "DNS:localhost", "IP Address:127.0.0.1"):
                assert expected in sans
        cert_public = run_openssl("x509", "-in", str(cert_path), "-noout", "-pubkey")
        pub_file = pki / "certificate-public.pem"
        pub_file.write_text(cert_public)
        key_public = run_openssl("pkey", "-in", str(key_path), "-pubout")
        assert cert_public == key_public
        pub_file.unlink()

with tempfile.TemporaryDirectory() as directory:
    partial_ca = Path(directory)
    (partial_ca / "ca.key").write_text("keep-ca-key")
    result = subprocess.run(["python3", str(GENERATOR), str(partial_ca)], capture_output=True, text=True)
    assert result.returncode != 0
    assert (partial_ca / "ca.key").read_text() == "keep-ca-key"
    assert not (partial_ca / "ca.crt").exists()

with tempfile.TemporaryDirectory() as directory:
    partial_leaf = Path(directory)
    (partial_leaf / "route-a.crt").write_text("keep-leaf")
    result = subprocess.run(["python3", str(GENERATOR), str(partial_leaf)], capture_output=True, text=True)
    assert result.returncode != 0
    assert (partial_leaf / "route-a.crt").read_text() == "keep-leaf"
    assert not (partial_leaf / "route-a.key").exists()

print("PKI generation checks: PASS")
