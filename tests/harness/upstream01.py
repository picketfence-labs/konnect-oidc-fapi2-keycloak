#!/usr/bin/env python3
"""Run UPSTREAM-01 over loopback TLS with fresh, isolated certificates."""

import argparse
import contextlib
import http.client
import io
import ipaddress
import json
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote_from_bytes

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pop-verifier"))
import app


HOST = "127.0.0.1"
PORT = 19443
LEAK_MARKERS = (
    "WP4_QUERY_TOKEN_SENTINEL",
    "WP4_HEADER_TOKEN_SENTINEL",
    "WP4_COOKIE_SENTINEL",
    "WP4_ASSERTION_SENTINEL",
    "BEGIN CERTIFICATE",
    "BEGIN PRIVATE KEY",
)


def build_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WP4 temporary test CA")])
    now = int(time.time())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.fromtimestamp(now - 60, timezone.utc).replace(tzinfo=None))
        .not_valid_after(datetime.fromtimestamp(now + 3600, timezone.utc).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def issue_leaf(common_name, ca_key, ca_certificate, *, usage, server=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = int(time.time())
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.fromtimestamp(now - 60, timezone.utc).replace(tzinfo=None))
        .not_valid_after(datetime.fromtimestamp(now + 3600, timezone.utc).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(HOST))]),
            critical=False,
        )
    return builder.sign(ca_key, hashes.SHA256()), key


def write_exclusive(path, content, mode=0o600):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def certificate_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def private_key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def reject_symlink_components(path):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise RuntimeError("receipt path contains a symlink")


def reserve_receipt(receipt_arg):
    receipt_path = Path(os.path.abspath(receipt_arg))
    reject_symlink_components(receipt_path)
    if os.path.lexists(receipt_path):
        raise RuntimeError("receipt already exists")
    receipt_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reject_symlink_components(receipt_path)
    if os.path.lexists(receipt_path):
        raise RuntimeError("receipt already exists")
    os.chmod(receipt_path.parent, 0o700)
    descriptor = os.open(
        receipt_path,
        os.O_CREAT | os.O_EXCL | os.O_RDWR,
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    return receipt_path, descriptor


def finalize_receipt(descriptor, receipt):
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    os.write(descriptor, payload)
    os.fsync(descriptor)
    os.close(descriptor)


def client_context(ca_path, certificate_path=None, key_path=None):
    context = ssl.create_default_context(cafile=str(ca_path))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if certificate_path and key_path:
        context.load_cert_chain(str(certificate_path), str(key_path))
    return context


def request(path, context, headers=None):
    connection = http.client.HTTPSConnection(HOST, PORT, context=context, timeout=5)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def require(condition, failure_stage):
    if not condition:
        raise RuntimeError(failure_stage)


def create_fixture_token(route_certificate):
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    route_der = route_certificate.public_bytes(serialization.Encoding.DER)
    claims = {
        "iss": app.ISSUER,
        "aud": [app.AUDIENCE, "api-gateway-introspection"],
        "azp": "third-party-fapi-mtls",
        "iat": now,
        "nbf": now - 1,
        "exp": now + 60,
        "scope": "openid profile",
        "cnf": {"x5t#S256": app.base64url_sha256(route_der)},
        app.DEPARTMENT_CLAIM: "engineering",
        app.ROUTE_CLAIM: "engineering-route",
    }
    token = jwt.encode(claims, signing_key, algorithm="PS256", headers={"kid": "wp4-ephemeral"})
    app.JWK_CLIENT = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key=signing_key.public_key())
    )
    return token, claims, route_der


def evidence_headers(token, route_certificate):
    route_pem = quote_from_bytes(certificate_pem(route_certificate), safe="")
    return {
        "Authorization": f"Bearer {token}",
        "X-Client-Cert": route_pem,
        "X-Demo-Department": "engineering",
        "X-Demo-Route": "engineering-route",
        "X-Fapi-Route": "route-b",
        "X-Fapi-Client-Auth": "private_key_jwt",
    }


def check_api_pin_health(context):
    status, _, body = request("/healthz", context)
    require(status == 200 and json.loads(body) == {"status": "ok"}, "api_peer_control")
    return status


def check_peer_rejected(context, headers):
    status, response_headers, body = request("/evidence", context, headers)
    parsed = json.loads(body)
    require(status == 401 and parsed.get("error") == "invalid_token", "peer_pin_rejection")
    require("invalid_token" in response_headers.get("WWW-Authenticate", ""), "bearer_error_header")
    return status


def check_port_released():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((HOST, PORT))
    finally:
        probe.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--receipt",
        default=".generated/evidence/wp4-upstream01.json",
        help="exclusive-create destination for sanitized evidence",
    )
    args = parser.parse_args()

    # Reserve the receipt before creating fixtures or starting TLS. This refuses
    # existing files and symlinked evidence directories without touching them.
    try:
        receipt_path, receipt_fd = reserve_receipt(args.receipt)
    except Exception:
        print("UPSTREAM-01 FAIL: receipt destination is unsafe or already exists")
        return 1
    receipt = {
        "scenario": "UPSTREAM-01",
        "result": "fail",
        "bind_address": f"{HOST}:{PORT}",
        "failure_stage": "setup",
        "credential_material_returned": False,
        "authorization_server_issued_token": False,
        "signing_key_source": "ephemeral test fixture",
        "jwt_signature_verification_method": "actual PyJWT PS256 verification",
        "health_endpoint_status": "not_run",
        "protected_evidence_status": "not_run",
        "protected_evidence_validation": "not_run",
        "keycloak_or_gateway_integration": "not exercised",
    }
    fixture_dir = None
    server = None
    thread = None
    captured_logs = io.StringIO()
    completed = False
    stage = "fixture_generation"
    anonymous_tls_reason = None
    try:
        fixture_dir = Path(tempfile.mkdtemp(prefix="wp4-upstream01-"))
        os.chmod(fixture_dir, 0o700)
        ca_key, ca_certificate = build_ca()
        server_certificate, server_key = issue_leaf(
            "wp4-upstream-test-server",
            ca_key,
            ca_certificate,
            usage=ExtendedKeyUsageOID.SERVER_AUTH,
            server=True,
        )
        gateway_certificate, gateway_key = issue_leaf(
            app.API_UPSTREAM_COMMON_NAME,
            ca_key,
            ca_certificate,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        same_cn_different_key_certificate, same_cn_different_key = issue_leaf(
            app.API_UPSTREAM_COMMON_NAME,
            ca_key,
            ca_certificate,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        route_certificate, route_key = issue_leaf(
            "kong-fapi-mtls",
            ca_key,
            ca_certificate,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        paths = {
            "ca": fixture_dir / "ca.crt",
            "server_cert": fixture_dir / "upstream.crt",
            "server_key": fixture_dir / "upstream.key",
            "gateway_cert": fixture_dir / "api-upstream.crt",
            "gateway_key": fixture_dir / "api-upstream.key",
            "same_cn_cert": fixture_dir / "same-cn-api-gateway.crt",
            "same_cn_key": fixture_dir / "same-cn-api-gateway.key",
            "route_cert": fixture_dir / "route-a.crt",
            "route_key": fixture_dir / "route-a.key",
        }
        for name, certificate in (
            ("ca", ca_certificate),
            ("server_cert", server_certificate),
            ("gateway_cert", gateway_certificate),
            ("same_cn_cert", same_cn_different_key_certificate),
            ("route_cert", route_certificate),
        ):
            write_exclusive(paths[name], certificate_pem(certificate))
        for name, key in (
            ("server_key", server_key),
            ("gateway_key", gateway_key),
            ("same_cn_key", same_cn_different_key),
            ("route_key", route_key),
        ):
            write_exclusive(paths[name], private_key_pem(key))
        require(all(path.stat().st_mode & 0o777 == 0o600 for path in paths.values()), "fixture_permissions")

        token, claims, route_der = create_fixture_token(route_certificate)
        evidence = evidence_headers(token, route_certificate)
        route_context = client_context(paths["ca"], paths["route_cert"], paths["route_key"])
        same_cn_context = client_context(paths["ca"], paths["same_cn_cert"], paths["same_cn_key"])
        pinned_context = client_context(paths["ca"], paths["gateway_cert"], paths["gateway_key"])

        stage = "tls_server_context"
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.verify_mode = ssl.CERT_REQUIRED
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            server_context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        stage = "tls_client_ca"
        server_context.load_verify_locations(cafile=str(paths["ca"]))
        stage = "tls_server_certificate"
        server_context.load_cert_chain(str(paths["server_cert"]), str(paths["server_key"]))
        stage = "api_pin_load"
        pinned_gateway_der = app.load_pinned_gateway_certificate(paths["gateway_cert"])
        stage = "server_bind"
        server = app.create_server(
            host=HOST,
            port=PORT,
            context=server_context,
            pinned_peer_der=pinned_gateway_der,
        )
        stage = "server_thread_start"
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
        thread.daemon = True
        thread.start()

        stage = "health_endpoint_request"
        with contextlib.redirect_stderr(captured_logs):
            health_status = check_api_pin_health(pinned_context)
            receipt["health_endpoint_status"] = health_status
            stage = "protected_endpoint_request"
            status, _, body = request("/evidence", pinned_context, evidence)
            receipt["protected_evidence_status"] = status
            stage = "protected_endpoint_response_parse"
            protected_body = json.loads(body)
            if status != 200:
                receipt["protected_evidence_validation"] = "fail"
                if protected_body.get("error") == "invalid_token":
                    receipt["protected_evidence_error"] = "invalid_token"
                    safe_reasons = {
                        "missing bearer token",
                        "JWT validation failed",
                        "required scope is missing",
                        "authorized party is invalid",
                        "certificate binding is missing",
                        "certificate binding mismatch",
                        "forwarded client certificate is missing or ambiguous",
                        "forwarded client certificate is invalid",
                        "untrusted API Gateway peer",
                        "invalid credentials",
                    }
                    reason = protected_body.get("reason")
                    if reason in safe_reasons:
                        receipt["protected_evidence_rejection_reason"] = reason
            require(status == 200, "protected_endpoint_status")
            stage = "protected_endpoint_claim_checks"
            require(
                protected_body.get("azp") == claims["azp"]
                and protected_body.get("route") == "route-a"
                and protected_body.get("client_authentication") == "tls_client_auth",
                "azp_route_mapping",
            )
            require(protected_body.get("token_signature_verified") is True, "jwt_signature_check")
            require(protected_body.get("binding_verified") is True, "certificate_binding_check")
            require(
                protected_body.get("token_certificate_thumbprint")
                == app.base64url_sha256(route_der)
                == protected_body.get("forwarded_client_certificate_thumbprint"),
                "forwarded_certificate_binding",
            )
            require(
                protected_body.get("header_claims_match") is True
                and protected_body.get("department") == "engineering"
                and protected_body.get("logical_route") == "engineering-route",
                "claim_header_evidence",
            )
            require("X-Fapi-Route" not in protected_body, "caller_route_header_influenced_evidence")
            receipt["protected_evidence_validation"] = "pass"

            # The request, token, forwarded certificate, and API peer contract
            # remain fixed while only the client TLS certificate changes.
            same_ca_route_status = check_peer_rejected(route_context, evidence)
            check_api_pin_health(pinned_context)
            same_cn_different_key_status = check_peer_rejected(same_cn_context, evidence)
            check_api_pin_health(pinned_context)

            leak_headers = dict(evidence)
            leak_headers.update(
                {
                    "Cookie": "WP4_COOKIE_SENTINEL",
                    "client_assertion": "WP4_ASSERTION_SENTINEL",
                }
            )
            query_status, _, query_body = request(
                "/evidence?access_token=WP4_QUERY_TOKEN_SENTINEL",
                pinned_context,
                leak_headers,
            )
            require(query_status == 404, "query_sentinel_status")
            require(
                not any(marker.encode() in query_body for marker in LEAK_MARKERS),
                "response_leak_check",
            )

            sentinel_headers = dict(evidence)
            sentinel_headers["Authorization"] = "Bearer WP4_HEADER_TOKEN_SENTINEL"
            sentinel_status, _, sentinel_body = request(
                "/evidence", pinned_context, sentinel_headers
            )
            require(sentinel_status == 401, "header_sentinel_status")
            require(
                not any(marker.encode() in sentinel_body for marker in LEAK_MARKERS),
                "response_leak_check",
            )

            anonymous_context = client_context(paths["ca"])
            check_api_pin_health(pinned_context)
            try:
                request("/healthz", anonymous_context)
            except ssl.SSLError as error:
                reason = getattr(error, "reason", "")
                if not isinstance(reason, str) or not (
                    "CERTIFICATE_REQUIRED" in reason or "HANDSHAKE_FAILURE" in reason
                ):
                    raise RuntimeError("anonymous_tls_unexpected_ssl_failure") from None
                anonymous_tls_reason = reason
            else:
                raise RuntimeError("anonymous_tls_accepted")
            check_api_pin_health(pinned_context)

        require(
            not any(marker in captured_logs.getvalue() for marker in LEAK_MARKERS),
            "log_leak_check",
        )
        receipt.update(
            {
                "result": "pass",
                "failure_stage": None,
                "fixture": "fresh, isolated, temporary certificates",
                "fixture_directory_mode": "0700",
                "fixture_file_mode": "0600",
                "pinned_api_gateway_certificate_cn": app.API_UPSTREAM_COMMON_NAME,
                "pinned_api_gateway_certificate_thumbprint_prefix12": app.base64url_sha256(
                    pinned_gateway_der
                )[:12],
                "health_endpoint_status": health_status,
                "protected_evidence_status": status,
                "protected_evidence_jwt_signature_verified": protected_body[
                    "token_signature_verified"
                ],
                "protected_evidence_binding_verified": protected_body["binding_verified"],
                "protected_evidence_azp": protected_body["azp"],
                "protected_evidence_derived_route": protected_body["route"],
                "protected_evidence_header_claims_match": protected_body["header_claims_match"],
                "same_ca_route_peer_tls_handshake": "accepted",
                "same_ca_route_peer_status": same_ca_route_status,
                "same_cn_different_key_peer_tls_handshake": "accepted",
                "same_cn_different_key_peer_status": same_cn_different_key_status,
                "anonymous_client_tls": "rejected",
                "anonymous_client_tls_reason": anonymous_tls_reason,
                "query_sentinel_status": query_status,
                "credential_material_returned": False,
                "credential_material_logged": False,
            }
        )
        completed = True
    except Exception as error:
        # Keep failure output and receipt free of traceback and exception data.
        failure_stage = str(error) if str(error) in {
            "fixture_generation",
            "fixture_permissions",
            "tls_startup",
            "tls_server_context",
            "tls_client_ca",
            "tls_server_certificate",
            "api_pin_load",
            "server_bind",
            "server_thread_start",
            "health_endpoint_request",
            "protected_endpoint_request",
            "protected_endpoint_response_parse",
            "protected_endpoint_claim_checks",
            "protected_endpoint_positive",
            "protected_endpoint_status",
            "azp_route_mapping",
            "jwt_signature_check",
            "certificate_binding_check",
            "forwarded_certificate_binding",
            "claim_header_evidence",
            "caller_route_header_influenced_evidence",
            "peer_pin_rejection",
            "bearer_error_header",
            "query_sentinel_status",
            "header_sentinel_status",
            "response_leak_check",
            "anonymous_tls_unexpected_ssl_failure",
            "anonymous_tls_accepted",
            "api_peer_control",
            "log_leak_check",
        } else stage
        receipt["failure_stage"] = failure_stage
        safe_exception_types = {
            "SSLError",
            "SSLCertVerificationError",
            "TimeoutError",
            "ConnectionRefusedError",
            "ConnectionResetError",
            "PermissionError",
            "OSError",
            "HTTPException",
            "RemoteDisconnected",
            "JSONDecodeError",
            "RuntimeError",
            "AssertionError",
            "ValueError",
        }
        exception_name = type(error).__name__
        receipt["failure_exception_type"] = (
            exception_name if exception_name in safe_exception_types else "other"
        )
        error_number = getattr(error, "errno", None)
        if type(error_number) is int:
            receipt["failure_errno"] = error_number
        ssl_reason = getattr(error, "reason", None)
        safe_ssl_reasons = {
            "CERTIFICATE_VERIFY_FAILED",
            "CERTIFICATE_REQUIRED",
            "TLSV13_ALERT_CERTIFICATE_REQUIRED",
            "TLSV1_ALERT_UNKNOWN_CA",
            "TLSV13_ALERT_CERTIFICATE_EXPIRED",
            "TLSV1_ALERT_BAD_CERTIFICATE",
            "SSLV3_ALERT_HANDSHAKE_FAILURE",
            "TLSV1_ALERT_HANDSHAKE_FAILURE",
            "TLSV13_ALERT_HANDSHAKE_FAILURE",
            "WRONG_VERSION_NUMBER",
            "NO_SHARED_CIPHER",
            "UNEXPECTED_EOF_WHILE_READING",
        }
        if isinstance(ssl_reason, str) and ssl_reason in safe_ssl_reasons:
            receipt["failure_tls_reason"] = ssl_reason
        verify_code = getattr(error, "verify_code", None)
        if type(verify_code) is int:
            receipt["failure_tls_verify_code"] = verify_code
    finally:
        cleanup_ok = True
        try:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=5)
                if thread.is_alive():
                    cleanup_ok = False
            if server is not None:
                check_port_released()
        except Exception:
            cleanup_ok = False
        try:
            if fixture_dir is not None:
                shutil.rmtree(fixture_dir)
                if fixture_dir.exists():
                    cleanup_ok = False
        except Exception:
            cleanup_ok = False
        receipt["cleanup"] = "pass" if cleanup_ok else "fail"
        if not cleanup_ok:
            completed = False
            receipt["result"] = "fail"
            receipt["failure_stage"] = "cleanup"
        try:
            finalize_receipt(receipt_fd, receipt)
        except Exception:
            os.close(receipt_fd)
            print("UPSTREAM-01 FAIL: sanitized receipt could not be finalized")
            raise SystemExit(1) from None

    if completed and receipt["result"] == "pass":
        print(f"UPSTREAM-01 PASS: sanitized receipt written to {receipt_path}")
        return 0
    print(f"UPSTREAM-01 FAIL: sanitized receipt written to {receipt_path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
