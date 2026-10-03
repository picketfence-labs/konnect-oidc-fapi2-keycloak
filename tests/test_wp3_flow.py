#!/usr/bin/env python3
"""Unit checks for WP3 fixture endpoint mapping and partial result recording."""

from __future__ import annotations

import sys
import json
import ast
import importlib.util
import socket
import io
import subprocess
import threading
import urllib.request
import unittest
import urllib.parse
from datetime import datetime, timezone
from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/harness"))

import wp3_flow
import cleanup_wp3_preview as wp3_cleanup
import prepare_wp3_preview as wp3_prepare

CAPTURE_SPEC = importlib.util.spec_from_file_location(
    "wp3_capture_server_test_helper", ROOT / "tests/harness/wp3-capture-server.py"
)
if CAPTURE_SPEC is None or CAPTURE_SPEC.loader is None:
    raise RuntimeError("WP3 capture helper is missing")
wp3_capture = importlib.util.module_from_spec(CAPTURE_SPEC)
sys.modules[CAPTURE_SPEC.name] = wp3_capture
CAPTURE_SPEC.loader.exec_module(wp3_capture)


def complete_service_logs(logs_by_service=None):
    logs_by_service = logs_by_service or {}
    logs = {service: logs_by_service.get(service, "") for service in wp3_flow.LOG_SERVICE_NAMES}
    statuses = {
        service: {
            "completed": True,
            "failure_reason": "none",
            "scanned_byte_count": len(logs[service].encode("utf-8")),
        }
        for service in wp3_flow.LOG_SERVICE_NAMES
    }
    return logs, statuses, "none"


def failed_service_logs(reason, partial=None, failed_service="kong-api"):
    partial = partial or {}
    logs = {service: partial.get(service, "") for service in wp3_flow.LOG_SERVICE_NAMES}
    statuses = {
        service: {
            "completed": service != failed_service,
            "failure_reason": "none" if service != failed_service else reason,
            "scanned_byte_count": len(logs[service].encode("utf-8")),
        }
        for service in wp3_flow.LOG_SERVICE_NAMES
    }
    return logs, statuses, reason


def clean_service_scan_receipt(candidate_count=0):
    categories = wp3_flow.LOG_VALUE_CATEGORIES
    return {
        service: {
            "completed": True,
            "passed": True,
            "failure_reason": "none",
            "scanned_byte_count": 0,
            "candidate_value_count": candidate_count,
            "checked_value_count": candidate_count,
            "matched_source_category_counts": {category: 0 for category in categories},
            "secret_match_category_counts": {category: 0 for category in categories},
            "credential_pattern_matches": [],
            "matched_candidate_provenance": [],
            "matched_log_context_counts": {context: 0 for context in wp3_flow.LOG_MATCH_CONTEXTS},
        }
        for service in wp3_flow.LOG_SERVICE_NAMES
    }


def failed_service_scan_receipt(candidate_count=0, reason="log_read_failed"):
    categories = wp3_flow.LOG_VALUE_CATEGORIES
    return {
        service: {
            "completed": False,
            "passed": False,
            "failure_reason": reason,
            "scanned_byte_count": 0,
            "candidate_value_count": candidate_count,
            "checked_value_count": 0,
            "matched_source_category_counts": {category: 0 for category in categories},
            "secret_match_category_counts": {category: 0 for category in categories},
            "credential_pattern_matches": [],
            "matched_candidate_provenance": [],
            "matched_log_context_counts": {context: 0 for context in wp3_flow.LOG_MATCH_CONTEXTS},
        }
        for service in wp3_flow.LOG_SERVICE_NAMES
    }


class FakeWp2:
    NAMESPACE = "https://fapi-demo.example.com"
    class JwksDocument:
        def __init__(self, document, refresh=None):
            self.document = document
            self.refresh = refresh

    def __init__(self, *, authorization_port=8444, backchannel_port=18444):
        self.authorization_port = authorization_port
        self.backchannel_port = backchannel_port
        self.requested = []

    @staticmethod
    def certificate_thumbprint(path):
        return wp3_flow.load_wp2_flow().certificate_thumbprint(path)

    def request_json(self, base_url, path_or_url, _ca_path, **_kwargs):
        self.requested.append((base_url, path_or_url))
        if ".well-known/openid-configuration" in path_or_url:
            origin = f"https://localhost:{self.backchannel_port}"
            authorization = f"https://localhost:{self.authorization_port}"
            return {
                "issuer": wp3_flow.PUBLIC_ISSUER,
                "authorization_endpoint": authorization + "/realms/fapi-demo/protocol/openid-connect/auth",
                "token_endpoint": origin + "/realms/fapi-demo/protocol/openid-connect/token",
                "pushed_authorization_request_endpoint": origin + "/realms/fapi-demo/protocol/openid-connect/ext/par/request",
                "introspection_endpoint": origin + "/realms/fapi-demo/protocol/openid-connect/token/introspect",
                "jwks_uri": origin + "/realms/fapi-demo/protocol/openid-connect/certs",
            }
        return {"keys": []}


class WP3FlowTests(unittest.TestCase):
    def test_log_level_diagnostic_change_isolated_from_normal_compose(self):
        normal_compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        isolated_compose = (ROOT / "tests/harness/docker-compose.wp3.yml").read_text(encoding="utf-8")
        normal_levels = [line.strip() for line in normal_compose.splitlines() if "KONG_LOG_LEVEL:" in line]
        self.assertEqual(normal_levels, ["KONG_LOG_LEVEL: notice", "KONG_LOG_LEVEL: notice"])
        self.assertEqual(isolated_compose.count("KONG_LOG_LEVEL: info"), 1)
        self.assertNotIn("KONG_LOG_LEVEL: info", normal_compose)
        self.assertEqual(isolated_compose.count('KONG_ADMIN_GUI_LISTEN: "off"'), 1)
        self.assertNotIn("KONG_ADMIN_GUI_LISTEN:", normal_compose)

    @staticmethod
    def make_test_identity():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wp3-capture-unit")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(123456789)
            .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )
        return cert, key

    @staticmethod
    def make_test_certificate():
        return WP3FlowTests.make_test_identity()[0]

    @staticmethod
    def capture_config(expected_route_cert_sha256):
        return SimpleNamespace(
            expected_route_cert_sha256=expected_route_cert_sha256,
            expected_token_sha256=None,
            expected_department="engineering",
            expected_route="engineering-route",
        )

    @staticmethod
    def stock_certificate_headers(cert):
        from email.message import Message

        der = cert.public_bytes(Encoding.DER)
        pem = cert.public_bytes(Encoding.PEM).decode("ascii")
        fingerprint = ":".join(f"{byte:02X}" for byte in cert.fingerprint(hashes.SHA1()))
        headers = Message()
        headers.add_header("X-Client-Cert", urllib.parse.quote(pem, safe=""))
        headers.add_header("X-Client-Cert-Serial", str(cert.serial_number))
        headers.add_header("X-Client-Cert-Issuer-DN", "CN=wp3-capture-unit")
        headers.add_header("X-Client-Cert-Subject-DN", "CN=wp3-capture-unit")
        headers.add_header("X-Client-Cert-Fingerprint", fingerprint)
        headers.add_header("X-Client-Cert-Chain", urllib.parse.quote(pem, safe=""))
        expected = wp3_capture.base64url_sha256(der)
        return headers, expected, fingerprint

    def test_stock_tls_metadata_allowlist_and_fingerprint_are_leaf_bound(self):
        cert = self.make_test_certificate()
        headers, expected_thumbprint, raw_fingerprint = self.stock_certificate_headers(cert)
        evidence = wp3_capture.summarize_request_headers(
            headers, self.capture_config(expected_thumbprint)
        )
        self.assertEqual(wp3_capture.CLIENT_CERT_SPOOF_SENTINELS, wp3_flow.CLIENT_CERT_SPOOF_HEADERS)
        self.assertEqual(evidence["x_client_cert_header_count"], 1)
        self.assertEqual(evidence["x_client_cert_unknown_suffix_header_count"], 0)
        self.assertEqual(evidence["x_client_cert_duplicate_header_count"], 0)
        self.assertEqual(evidence["x_client_cert_underscore_alias_count"], 0)
        self.assertEqual(evidence["caller_spoof_sentinel_match_count"], 0)
        self.assertTrue(evidence["x_client_cert_stock_details_complete"])
        self.assertEqual(evidence["x_client_cert_stock_detail_counts"], {
            "serial": 1, "issuer_dn": 1, "subject_dn": 1, "fingerprint": 1, "chain": 1,
        })
        self.assertTrue(evidence["x_client_cert_fingerprint_matches_forwarded_leaf"])
        self.assertTrue(evidence["forwarded_certificate_matches_expected_route"])
        serialized = json.dumps(evidence)
        self.assertNotIn("CN=wp3-capture-unit", serialized)
        self.assertNotIn(str(cert.serial_number), serialized)
        self.assertNotIn(raw_fingerprint, serialized)

    def test_memory_bio_proves_tls11_and_tls12_cipher_client_hello_protocol_offers(self):
        cert, key = self.make_test_identity()
        with TemporaryDirectory() as directory:
            pki = Path(directory)
            (pki / "ca.crt").write_bytes(cert.public_bytes(Encoding.PEM))
            (pki / "client.crt").write_bytes(cert.public_bytes(Encoding.PEM))
            (pki / "client.key").write_bytes(
                key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            offers = (
                (wp3_flow.ssl.TLSVersion.TLSv1_1, "AES128-SHA:@SECLEVEL=0", 0x002F, ["TLSv1.1"]),
                (wp3_flow.ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", 0xC02F, ["TLSv1.2"]),
                (wp3_flow.ssl.TLSVersion.TLSv1_2, "AES128-SHA:@SECLEVEL=0", 0x002F, ["TLSv1.2"]),
            )
            for version, cipher_suite, cipher_id, protocols in offers:
                offer = wp3_flow.client_hello_offerability(
                    pki, "localhost", pki / "client.crt", pki / "client.key",
                    minimum_tls=version, maximum_tls=version,
                    cipher_suite=cipher_suite, expected_cipher_id=cipher_id,
                )
                self.assertTrue(offer["client_hello_emitted"])
                self.assertTrue(offer["target_cipher_offered"])
                self.assertEqual(offer["offered_protocols"], protocols)
                self.assertEqual(offer["reason"], "none")

    def test_tls_alert_and_certificate_verification_codes_map_to_safe_enums(self):
        protocol = wp3_flow.classify_tls_exception(SimpleNamespace(reason="TLSV1_ALERT_PROTOCOL_VERSION"))
        self.assertEqual((protocol.layer, protocol.reason, protocol.verify_code), ("tls_handshake", "peer_alert_protocol_version", None))
        san = wp3_flow.classify_tls_exception(SimpleNamespace(reason="CERTIFICATE_VERIFY_FAILED", verify_code=62))
        self.assertEqual((san.layer, san.reason, san.verify_code), ("server_certificate_validation", "server_san_mismatch", 62))
        untrusted = wp3_flow.classify_tls_exception(SimpleNamespace(reason="CERTIFICATE_VERIFY_FAILED", verify_code=20))
        self.assertEqual((untrusted.layer, untrusted.reason, untrusted.verify_code), ("server_certificate_validation", "server_untrusted_ca", 20))
        unknown = wp3_flow.classify_tls_exception(SimpleNamespace(reason="RAW ERROR MUST NOT ESCAPE"))
        self.assertEqual(unknown.reason, "other_tls_error")
        self.assertNotIn("RAW ERROR", str(unknown))

    def test_inactive_introspection_minimal_document_is_a_valid_inactive_observation(self):
        self.assertTrue(wp3_flow._verify_direct_introspection(
            FakeWp2(), {"active": False}, {}, active=False,
        ))
        self.assertFalse(wp3_flow._verify_direct_introspection(
            FakeWp2(), {"active": "false"}, {}, active=False,
        ))

    def test_tls_negative_runner_uses_single_san_option_and_requires_server_errors(self):
        route = {
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "sni": "localhost",
        }
        context = {"pki": Path("pki"), "containers": {"pop-verifier": "capture"}, "tls_policy_proven": True}
        rows = wp3_flow.initial_cases()
        failures = [
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_san_mismatch", 62),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_untrusted_ca", 20),
        ]
        def offered(*_args, minimum_tls=None, **_kwargs):
            protocols = ["TLSv1.1"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_1 else ["TLSv1.2"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_2 else ["TLSv1.2", "TLSv1.3"]
            return {"client_hello_emitted": True, "target_cipher_offered": True, "offered_protocols": protocols, "reason": "none"}
        def handshake(*_args, observe=False, **_kwargs):
            return {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"} if observe else True
        with patch.object(wp3_flow, "client_hello_offerability", side_effect=offered), patch.object(
            wp3_flow, "tls_handshake_probe", side_effect=handshake
        ), patch.object(wp3_flow, "capture_request_count", side_effect=[0] * 15
        ), patch.object(wp3_flow, "request_api", side_effect=failures) as request:
            wp3_flow._run_tls_negatives(rows, context, route)
        self.assertEqual(request.call_count, 5)
        self.assertEqual(
            [row["outcome"] for row in rows if row["case_id"] == "TLS-RS-01"],
            ["pass", "pass", "pass", "pass", "pass"],
        )
        san_kwargs = request.call_args_list[3].kwargs
        self.assertIs(san_kwargs["allow_san_mismatch"], True)
        self.assertNotIn("allow_san_mismatch", {
            key for key in san_kwargs if key != "allow_san_mismatch"
        })
        tls_rows = [row for row in rows if row["case_id"] == "TLS-RS-01"]
        self.assertTrue(all(row["post_negative_valid_control"] is True for row in tls_rows))

    def test_tls12_protocol_alert_passes_only_as_version_policy_with_full_controls(self):
        route = {
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "sni": "localhost",
        }
        context = {"pki": Path("pki"), "containers": {"pop-verifier": "capture"}, "tls_policy_proven": True}
        rows = wp3_flow.initial_cases()
        failures = [
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_san_mismatch", 62),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_untrusted_ca", 20),
        ]
        def offered(*_args, minimum_tls=None, **_kwargs):
            protocols = ["TLSv1.1"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_1 else ["TLSv1.2"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_2 else ["TLSv1.2", "TLSv1.3"]
            return {"client_hello_emitted": True, "target_cipher_offered": True, "offered_protocols": protocols, "reason": "none"}
        def handshake(*_args, observe=False, **_kwargs):
            return {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"} if observe else True
        with patch.object(wp3_flow, "client_hello_offerability", side_effect=offered), patch.object(
            wp3_flow, "tls_handshake_probe", side_effect=handshake
        ), patch.object(wp3_flow, "capture_request_count", side_effect=[0] * 15
        ), patch.object(wp3_flow, "request_api", side_effect=failures):
            wp3_flow._run_tls_negatives(rows, context, route)
        tls_rows = [row for row in rows if row["case_id"] == "TLS-RS-01"]
        tls12 = next(row for row in tls_rows if row["variant"] == "tls_12_only")
        weak = next(row for row in rows if row["case_id"] == "TLS-RS-01" and row["variant"] == "weak_cipher")
        self.assertEqual(tls12["outcome"], "pass")
        self.assertEqual(tls12["offered_protocols"], ["TLSv1.2"])
        self.assertTrue(tls12["tls_policy_proven"])
        self.assertEqual(weak["outcome"], "pass")
        self.assertEqual(weak["tls_failure_reason"], "peer_alert_protocol_version")
        self.assertTrue(weak["client_hello_offered"])
        self.assertEqual(weak["offered_protocols"], ["TLSv1.2"])
        self.assertEqual(weak["negotiated_protocol"], "TLSv1.3")
        self.assertIn(weak["negotiated_cipher"], wp3_flow.TLS13_APPROVED_AEAD_CIPHERS)
        self.assertTrue(weak["upstream_unchanged"])
        self.assertTrue(weak["post_negative_valid_control"])

    def test_tls12_protocol_rejection_without_effective_modern_policy_is_needs_design(self):
        route = {
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "sni": "localhost",
        }
        context = {"pki": Path("pki"), "containers": {"pop-verifier": "capture"}, "tls_policy_proven": False}
        rows = wp3_flow.initial_cases()
        def offered(*_args, minimum_tls=None, **_kwargs):
            protocols = ["TLSv1.1"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_1 else ["TLSv1.2"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_2 else ["TLSv1.2", "TLSv1.3"]
            return {"client_hello_emitted": True, "target_cipher_offered": True, "offered_protocols": protocols, "reason": "none"}
        def handshake(*_args, observe=False, **_kwargs):
            return {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"} if observe else True
        failures = [
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_san_mismatch", 62),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_untrusted_ca", 20),
        ]
        with patch.object(wp3_flow, "client_hello_offerability", side_effect=offered), patch.object(
            wp3_flow, "tls_handshake_probe", side_effect=handshake
        ), patch.object(wp3_flow, "capture_request_count", side_effect=[0] * 15), patch.object(
            wp3_flow, "request_api", side_effect=failures
        ):
            wp3_flow._run_tls_negatives(rows, context, route)
        weak = next(row for row in rows if row.get("variant") == "weak_cipher")
        self.assertEqual(weak["outcome"], "needs_design")

    def test_weak_cipher_cannot_pass_when_good_tls12_protocol_control_fails(self):
        route = {
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "sni": "localhost",
        }
        context = {"pki": Path("pki"), "containers": {"pop-verifier": "capture"}, "tls_policy_proven": True}
        rows = wp3_flow.initial_cases()
        failures = [
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            # The good TLS 1.2 suite must establish the protocol-level control.
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_handshake_failure"),
            # The weak-suite probe has otherwise complete, independent evidence.
            wp3_flow.ApiTlsFailure("tls_handshake", "peer_alert_protocol_version"),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_san_mismatch", 62),
            wp3_flow.ApiTlsFailure("server_certificate_validation", "server_untrusted_ca", 20),
        ]

        def offered(*_args, minimum_tls=None, **_kwargs):
            protocols = ["TLSv1.1"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_1 else ["TLSv1.2"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_2 else ["TLSv1.2", "TLSv1.3"]
            return {"client_hello_emitted": True, "target_cipher_offered": True, "offered_protocols": protocols, "reason": "none"}

        def handshake(*_args, observe=False, **_kwargs):
            return {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"} if observe else True

        with patch.object(wp3_flow, "client_hello_offerability", side_effect=offered), patch.object(
            wp3_flow, "tls_handshake_probe", side_effect=handshake
        ), patch.object(wp3_flow, "capture_request_count", side_effect=[0] * 15), patch.object(
            wp3_flow, "request_api", side_effect=failures
        ):
            wp3_flow._run_tls_negatives(rows, context, route)

        good_control = next(row for row in rows if row.get("variant") == "tls_12_only")
        weak = next(row for row in rows if row.get("variant") == "weak_cipher")
        self.assertEqual(good_control["outcome"], "fail")
        self.assertEqual(weak["tls_failure_reason"], "peer_alert_protocol_version")
        self.assertEqual(weak["offered_protocols"], ["TLSv1.2"])
        self.assertTrue(weak["tls_policy_proven"])
        self.assertTrue(weak["upstream_unchanged"])
        self.assertTrue(weak["post_negative_valid_control"])
        self.assertEqual(weak["outcome"], "needs_design")

    def test_tls_http_response_still_requires_post_negative_valid_control(self):
        route = {
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "sni": "localhost",
        }
        context = {"pki": Path("pki"), "containers": {"pop-verifier": "capture"}, "tls_policy_proven": True}
        rows = wp3_flow.initial_cases()
        def offered(*_args, minimum_tls=None, **_kwargs):
            protocols = ["TLSv1.1"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_1 else ["TLSv1.2"] if minimum_tls == wp3_flow.ssl.TLSVersion.TLSv1_2 else ["TLSv1.2", "TLSv1.3"]
            return {"client_hello_emitted": True, "target_cipher_offered": True, "offered_protocols": protocols, "reason": "none"}
        with patch.object(wp3_flow, "client_hello_offerability", side_effect=offered), patch.object(
            wp3_flow, "tls_handshake_probe", return_value={"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"}
        ) as handshake, patch.object(wp3_flow, "capture_request_count", side_effect=[0] * 15
        ), patch.object(wp3_flow, "request_api", return_value=(400, [], {})):
            wp3_flow._run_tls_negatives(rows, context, route)
        tls_rows = [row for row in rows if row["case_id"] == "TLS-RS-01"]
        self.assertTrue(all(row["outcome"] == "fail" for row in tls_rows))
        self.assertTrue(all(row["post_negative_valid_control"] is True for row in tls_rows))
        self.assertEqual(handshake.call_count, 10)

    def test_api_error_response_secret_echo_fails_closed_without_persisting_body(self):
        sentinel = "WP3-API-RESPONSE-SECRET-SENTINEL-001"
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.reset_api_response_scan()

        class FakeSocket:
            def settimeout(self, _timeout):
                pass

            def sendall(self, _request):
                pass

            def close(self):
                pass

        class FakeContext:
            def wrap_socket(self, _socket, server_hostname=None):
                return FakeSocket()

        class FakeResponse:
            status = 401

            def __init__(self, _socket):
                pass

            def begin(self):
                pass

            def read(self, _limit):
                return json.dumps({"error": sentinel}).encode()

            def getheaders(self):
                return [("Content-Type", "application/json")]

        with patch.object(wp3_flow.ssl, "create_default_context", return_value=FakeContext()), patch.object(
            wp3_flow.socket, "create_connection", return_value=FakeSocket()
        ), patch.object(wp3_flow.http.client, "HTTPResponse", FakeResponse):
            with self.assertRaisesRegex(wp3_flow.FlowError, "sensitive-material scan") as caught:
                wp3_flow.request_api(Path("pki"), "localhost", headers=[("Authorization", "Bearer " + sentinel)])
        self.assertNotIn(sentinel, str(caught.exception))
        receipt = wp3_flow.api_response_scan_receipt()
        self.assertEqual(receipt["api_response_count"], 1)
        self.assertEqual(receipt["api_response_secret_value_match_count"], 1)
        self.assertEqual(receipt["api_response_secret_match_category_counts"]["oauth_token"], 1)
        self.assertNotIn(sentinel, json.dumps(receipt))

    def test_capture_response_exact_schema_is_required_for_positive_evidence(self):
        cert = self.make_test_certificate()
        with TemporaryDirectory() as directory:
            cert_path = Path(directory) / "route.crt"
            cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
            headers, _unused_thumbprint, _fingerprint = self.stock_certificate_headers(cert)
            thumbprint = FakeWp2.certificate_thumbprint(cert_path)
            token = "eyJfixture.header.signature"
            headers.add_header("Authorization", f"Bearer {token}")
            headers.add_header("X-Demo-Department", "engineering")
            headers.add_header("X-Demo-Route", "engineering-route")
            evidence = wp3_capture.summarize_request_headers(headers, self.capture_config(None))
            evidence.update({
                "status": "captured", "api_peer_pin_matches": True,
                "api_peer_common_name_matches": True, "request_count": 1,
            })
            support = wp3_flow.load_wp2_flow()
            claims = {
                "cnf": {"x5t#S256": thumbprint},
                f"{support.NAMESPACE}/department": "engineering",
                f"{support.NAMESPACE}/route": "engineering-route",
            }
            wp3_flow.verify_capture(FakeWp2(), evidence, token, claims, cert_path)
            extra = dict(evidence, unexpected="value")
            with self.assertRaisesRegex(wp3_flow.FlowError, "sanitized evidence"):
                wp3_flow.verify_capture(FakeWp2(), extra, token, claims, cert_path)

    def test_combined_stock_dn_and_serial_sentinels_are_detected(self):
        cert = self.make_test_certificate()
        headers, expected_thumbprint, _fingerprint = self.stock_certificate_headers(cert)
        headers.replace_header(
            "X-Client-Cert-Serial",
            f"{cert.serial_number};{wp3_capture.CLIENT_CERT_SPOOF_SENTINELS['X-Client-Cert-Serial']}",
        )
        headers.replace_header(
            "X-Client-Cert-Issuer-DN",
            f"CN=wp3-capture-unit,{wp3_capture.CLIENT_CERT_SPOOF_SENTINELS['X-Client-Cert-Issuer-DN']}",
        )
        evidence = wp3_capture.summarize_request_headers(
            headers, self.capture_config(expected_thumbprint)
        )
        self.assertEqual(evidence["caller_spoof_sentinel_match_count"], 2)
        self.assertEqual(evidence["x_client_cert_duplicate_header_count"], 0)
        self.assertTrue(evidence["x_client_cert_stock_details_complete"])
        self.assertNotIn("WP3-SPOOF-CERT-SERIAL", json.dumps(evidence))

    def test_unknown_underscore_client_cert_alias_is_not_in_stock_allowlist(self):
        cert = self.make_test_certificate()
        headers, expected_thumbprint, _fingerprint = self.stock_certificate_headers(cert)
        headers.add_header(
            "x_client_cert_UnknownAlias",
            wp3_capture.CLIENT_CERT_SPOOF_SENTINELS["x_client_cert_UnknownAlias"],
        )
        evidence = wp3_capture.summarize_request_headers(
            headers, self.capture_config(expected_thumbprint)
        )
        self.assertEqual(evidence["x_client_cert_unknown_suffix_header_count"], 1)
        self.assertEqual(evidence["x_client_cert_underscore_alias_count"], 1)
        self.assertEqual(evidence["caller_spoof_sentinel_match_count"], 1)

    def test_duplicate_or_missing_stock_detail_fails_completeness(self):
        cert = self.make_test_certificate()
        headers, expected_thumbprint, _fingerprint = self.stock_certificate_headers(cert)
        from email.message import Message

        headers.add_header("X-Client-Cert-Serial", "duplicate")
        incomplete = Message()
        for name, value in headers.raw_items():
            if name.lower() != "x-client-cert-chain":
                incomplete.add_header(name, value)
        evidence = wp3_capture.summarize_request_headers(
            incomplete, self.capture_config(expected_thumbprint)
        )
        self.assertEqual(evidence["x_client_cert_duplicate_header_count"], 1)
        self.assertEqual(evidence["x_client_cert_stock_detail_counts"]["serial"], 2)
        self.assertEqual(evidence["x_client_cert_stock_detail_counts"]["chain"], 0)
        self.assertFalse(evidence["x_client_cert_stock_details_complete"])

    def test_combined_caller_sentinel_moved_to_unrelated_header_is_detected(self):
        cert = self.make_test_certificate()
        headers, expected_thumbprint, _fingerprint = self.stock_certificate_headers(cert)
        moved_sentinel = wp3_capture.CLIENT_CERT_SPOOF_SENTINELS["X-Client-Cert-Serial"]
        headers.add_header("X-Other-Forwarded-Data", f"unrelated,{moved_sentinel},suffix")
        evidence = wp3_capture.summarize_request_headers(
            headers, self.capture_config(expected_thumbprint)
        )
        self.assertEqual(evidence["caller_spoof_sentinel_match_count"], 1)
        self.assertEqual(evidence["x_client_cert_unknown_suffix_header_count"], 0)
        self.assertNotIn(moved_sentinel, json.dumps(evidence))

    def test_public_issuer_stays_8444_while_transport_maps_to_18444(self):
        wp2 = FakeWp2()
        issuer, metadata, _jwks = wp3_flow.load_fixture_metadata(wp2, Path("/unused"))
        self.assertEqual(issuer, "https://localhost:8444/realms/fapi-demo")
        self.assertEqual(metadata["issuer"], issuer)
        self.assertEqual(metadata["authorization_endpoint"].split("/")[2], "localhost:18444")
        for name in ("token_endpoint", "pushed_authorization_request_endpoint", "introspection_endpoint", "jwks_uri"):
            self.assertEqual(metadata[name].split("/")[2], "localhost:18444")
        self.assertEqual(wp2.requested[-1][1], metadata["jwks_uri"])

    def test_public_backchannel_urls_map_to_the_fixture_listener(self):
        wp2 = FakeWp2(authorization_port=8444, backchannel_port=8444)
        _issuer, metadata, _jwks = wp3_flow.load_fixture_metadata(wp2, Path("/unused"))
        self.assertEqual(metadata["token_endpoint"].split("/")[2], "localhost:18444")

    def test_non_public_authorization_origin_is_rejected(self):
        with self.assertRaisesRegex(wp3_flow.FlowError, "approved TLS loopback origin"):
            wp3_flow.load_fixture_metadata(FakeWp2(authorization_port=18444), Path("/unused"))

    def test_partial_recorder_preserves_a_pass_when_b_fails(self):
        rows = wp3_flow.initial_cases()
        wp3_flow.mark_route_case(
            rows, "RS-VALID-01", "A", "pass", "upstream_mtls_and_header_evidence",
            "gateway+upstream_capture", 200, False,
        )
        wp3_flow.mark_route_case(
            rows, "RS-VALID-01", "B", "fail", "api_tls_and_authorization",
            "api_gateway_tls_or_harness",
        )
        route_a = next(row for row in rows if row["case_id"] == "RS-VALID-01" and row.get("route") == "A")
        route_b = next(row for row in rows if row["case_id"] == "RS-VALID-01" and row.get("route") == "B")
        self.assertEqual(route_a["outcome"], "pass")
        self.assertEqual(route_a["http_status"], 200)
        self.assertEqual(route_b["outcome"], "fail")
        self.assertEqual(route_b["phase"], "api_tls_and_authorization")
        self.assertTrue(all(row["outcome"] == "not_run" for row in rows if row["case_id"].startswith("POP-") or row["case_id"] == "TLS-RS-01"))

    def test_introspection_case_stays_not_run_until_its_request_starts(self):
        rows = wp3_flow.initial_cases()
        wp3_flow.mark_route_pipeline_started(rows, "A")
        validation = next(row for row in rows if row["case_id"] == "RS-VALID-01" and row.get("route") == "A")
        introspection = next(row for row in rows if row["case_id"] == "RS-INT-AUD-02" and row.get("route") == "A")
        self.assertEqual(validation["outcome"], "running")
        self.assertEqual(introspection["outcome"], "not_run")
        wp3_flow.mark_route_case(rows, "RS-VALID-01", "A", "fail", "token_signature_and_claim_validation", "token_validation")
        self.assertEqual(introspection["outcome"], "not_run")

        wp3_flow.mark_route_introspection_started(rows, "A")
        self.assertEqual(introspection["outcome"], "running")
        self.assertEqual(introspection["phase"], "dedicated_mtls_introspection")
        wp3_flow.mark_route_case(rows, "RS-INT-AUD-02", "A", "fail", "dedicated_mtls_introspection", "keycloak")
        self.assertEqual(introspection["outcome"], "fail")

    def test_route_execution_receipt_tracks_api_and_capture_phases(self):
        execution = {"phase": "fixture_preflight"}
        wp3_flow.record_route_execution_phase(execution, "A", "api_tls_and_authorization")
        self.assertEqual(execution["phase"], "route_A_api_tls_and_authorization")
        wp3_flow.record_route_execution_phase(execution, "A", "upstream_mtls_and_header_evidence")
        self.assertEqual(execution["phase"], "route_A_upstream_mtls_and_header_evidence")
        with self.assertRaisesRegex(wp3_flow.FlowError, "unknown fixed phase"):
            wp3_flow.record_route_execution_phase(execution, "A", "unclassified")

    def test_readiness_uses_kong_prefix_and_requires_fixture_underscore_mode(self):
        wp2 = FakeWp2()
        wp2.request_json = lambda *_args, **_kwargs: {"issuer": wp3_flow.PUBLIC_ISSUER}
        outputs = [
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"http {\n  underscores_in_headers on;\n}\n", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"nginx version: openresty/1.29.2.5\n"),
        ]
        with patch.object(wp3_flow.subprocess, "run", side_effect=outputs) as run:
            result = wp3_flow.wait_for_runtime_ready(wp2, Path("/unused"), {"kong-api": "container-id"})
        self.assertEqual(result, {
            "fixture_underscores_in_headers_on": True,
            "nginx_config_dump": b"http {\n  underscores_in_headers on;\n}\n",
            "nginx_version": "openresty/1.29.2.5",
            "header_parser_metadata": {
                "nginx_version": "openresty/1.29.2.5",
                "max_headers_override_absent": True,
                "default_header_limit": 1000,
                "source": "pinned_image_default_1000",
            },
        })
        command = run.call_args_list[1].args[0]
        self.assertEqual(command[-6:], ["nginx", "-p", "/usr/local/kong", "-c", "nginx.conf", "-T"])
        self.assertEqual(run.call_args_list[2].args[0][-1], "-v")

    def test_readiness_fails_closed_when_exact_kong_config_lacks_alias_mode(self):
        wp2 = FakeWp2()
        wp2.request_json = lambda *_args, **_kwargs: {"issuer": wp3_flow.PUBLIC_ISSUER}
        outputs = [
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"http {\n  underscores_in_headers off;\n}\n", stderr=b""),
        ]
        with patch.object(wp3_flow.subprocess, "run", side_effect=outputs):
            with self.assertRaisesRegex(wp3_flow.FlowError, "underscore header mode"):
                wp3_flow.wait_for_runtime_ready(wp2, Path("/unused"), {"kong-api": "container-id"})

    def test_readiness_does_not_claim_default_header_limit_when_config_overrides_it(self):
        wp2 = FakeWp2()
        wp2.request_json = lambda *_args, **_kwargs: {"issuer": wp3_flow.PUBLIC_ISSUER}
        outputs = [
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"http {\n underscores_in_headers on;\n max_headers 900;\n}\n", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"nginx version: openresty/1.29.2.5\n"),
        ]
        with patch.object(wp3_flow.subprocess, "run", side_effect=outputs):
            result = wp3_flow.wait_for_runtime_ready(wp2, Path("/unused"), {"kong-api": "container-id"})
        self.assertEqual(result["header_parser_metadata"], {
            "nginx_version": "openresty/1.29.2.5",
            "max_headers_override_absent": False,
            "default_header_limit": None,
            "source": "not_proven",
        })

    def test_full_log_scan_detects_direct_values_and_bearer_patterns(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": "startup ok"})):
            result = wp3_flow.scan_logs_for_sensitive_values(["private-fixture-password"])
        self.assertTrue(result["passed"])
        self.assertTrue(result["completed"])
        self.assertEqual(result["secret_value_match_count"], 0)
        self.assertEqual(
            result["checked_value_count"],
            len(wp3_flow.normalize_log_candidates(["private-fixture-password"])),
        )
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"kong-api": "client_secret=private-fixture-password"})):
            result = wp3_flow.scan_logs_for_sensitive_values(["private-fixture-password"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_value_match_count"], 1)
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"kong-api": "Authorization: Bearer eyJabcdefgh.eyJabcdefgh.sigabcdef"})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["credential_pattern_matches"], ["bearer_authorization", "jwt_shape"])

    def test_service_log_scans_locate_matches_without_emitting_values_or_summing_duplicates(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.reset_api_response_scan()
        token = "TEST-OAUTH-TOKEN-MARKER-001"
        candidates = [("oauth_token", token)]
        logs = complete_service_logs({
            "keycloak": f"sensitive token {token}",
            "kong-api": f"access_token={token}",
        })
        with patch.object(wp3_flow, "compose_service_logs", return_value=logs):
            result = wp3_flow.scan_logs_for_sensitive_values(candidates)
        self.assertFalse(result["passed"])
        self.assertTrue(result["completed"])
        self.assertEqual(result["secret_value_match_count"], 1)
        self.assertEqual(result["secret_match_category_counts"]["oauth_token"], 1)
        per_service = result["service_scans"]
        self.assertEqual(set(per_service), set(wp3_flow.LOG_SERVICE_NAMES))
        self.assertFalse(per_service["keycloak"]["passed"])
        self.assertFalse(per_service["kong-api"]["passed"])
        self.assertTrue(per_service["pop-verifier"]["passed"])
        self.assertEqual(per_service["keycloak"]["secret_match_category_counts"]["oauth_token"], 1)
        self.assertEqual(per_service["kong-api"]["secret_match_category_counts"]["oauth_token"], 1)
        self.assertEqual(per_service["kong-api"]["credential_pattern_matches"], ["oauth_token_field"])
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(token, encoded)
        wp3_prepare.validate_runtime_receipt(self._runtime_receipt_with_log_scan(result))
        for service in ("keycloak", "kong-api"):
            tampered = json.loads(json.dumps(result))
            tampered["service_scans"][service]["passed"] = True
            with self.assertRaisesRegex(Exception, "pass contradicts"):
                wp3_prepare.validate_runtime_receipt(self._runtime_receipt_with_log_scan(tampered))

    def test_log_diagnostics_retain_only_finite_candidate_provenance_and_context_counts(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        token = "TEST-OAUTH-TOKEN-PROVENANCE-001"
        wp3_flow.remember_sensitive(
            token, "oauth_token", source="oauth_verified_access_token", field="access_token",
        )
        wp3_flow.remember_sensitive(
            token, "oauth_token", source="api_request_target", field="api_query",
        )
        logs = complete_service_logs({
            "keycloak": f"POST /realms/fapi-demo/protocol/openid-connect/token {token}",
            "kong-api": f"GET {wp3_flow.API_PATH}?access_token={token}",
        })
        with patch.object(wp3_flow, "compose_service_logs", return_value=logs):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_value_match_count"], 1)
        self.assertEqual(result["secret_match_category_counts"]["oauth_token"], 1)
        kc = result["service_scans"]["keycloak"]
        kong = result["service_scans"]["kong-api"]
        self.assertEqual(kc["matched_log_context_counts"]["oauth_token_endpoint_request"], 1)
        self.assertEqual(kong["matched_log_context_counts"]["api_query_access_token_request"], 2)
        self.assertEqual(
            kc["matched_candidate_provenance"],
            [{"category": "oauth_token", "source": "api_request_target", "field": "api_query", "matched_value_count": 1},
             {"category": "oauth_token", "source": "oauth_verified_access_token", "field": "access_token", "matched_value_count": 1}],
        )
        self.assertEqual(
            kong["matched_candidate_provenance"],
            kc["matched_candidate_provenance"]
            + [{"category": "public_fixed_protocol_constant", "source": "public_protocol_inventory", "field": "other", "matched_value_count": 1}],
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(token, serialized)
        self.assertNotIn("openid-connect/token", serialized)
        wp3_prepare.validate_runtime_receipt(self._runtime_receipt_with_log_scan(result))

    def test_introspection_and_login_form_field_labels_are_finite_and_category_stable(self):
        self.assertEqual(wp3_flow.LOG_CANDIDATE_FIELDS, wp3_prepare.WP3_LOG_CANDIDATE_FIELDS)
        self.assertEqual(wp3_flow.LOG_MATCH_CONTEXTS, wp3_prepare.WP3_LOG_MATCH_CONTEXTS)
        wp3_flow.SENSITIVE_VALUES.clear()
        introspection = {
            "azp": "third-party-client-name",
            "preferred_username": "fixture-user-name",
            "username": "another-fixture-user",
            "name": "Fixture Display Name",
            "email": "fixture-user@example.test",
            "auth_time": "fixture-auth-time-001",
            "session_state": "fixture-session-state-001",
            "sid": "fixture-session-id-001",
            "sub": "fixture-subject-id-001",
            "jti": "fixture-jti-identifier-001",
            "client_id": "fixture-client-identifier",
        }
        verified_token = "verified-token-for-introspection-001"
        intro_collection = wp3_flow.remember_sensitive(
            introspection, source="oauth_introspection_response", token_binding=verified_token,
        )
        expected_fields = {name: name for name in introspection}
        for name, value in introspection.items():
            if name in {"azp", "jti", "sid", "sub"}:
                self.assertNotIn(("unknown", value), wp3_flow.SENSITIVE_VALUES)
                self.assertIn(("unknown", value), wp3_flow.normalize_log_candidates([]))
                continue
            candidates = [item for item in wp3_flow.SENSITIVE_VALUES if item[1] == value]
            self.assertEqual(len(candidates), 1, name)
            category, _ = candidates[0]
            self.assertEqual(category, "cookie" if name == "session_state" else "unknown", name)
            self.assertEqual(
                wp3_flow.SENSITIVE_VALUE_PROVENANCE[(category, value)],
                {("oauth_introspection_response", expected_fields[name])},
            )
        verified_claims = {name: value for name, value in introspection.items() if name in {"azp", "jti", "sid", "sub"}}
        grant = {"client": {"client_id": introspection["azp"]}}
        wp3_flow.resolve_verified_introspection_identifiers(
            intro_collection, verified_claims, grant, verified_token, active=True,
        )
        for name, value in verified_claims.items():
            self.assertIn(("noncredential_protocol_identifier", value), wp3_flow.SENSITIVE_VALUES)
            self.assertEqual(
                wp3_flow.SENSITIVE_VALUE_PROVENANCE[("noncredential_protocol_identifier", value)],
                {("oauth_introspection_response", name)},
            )

        wp3_flow.SENSITIVE_VALUES.clear()
        form_fields = [
            {"name": "username", "value": "fixture-login-user", "type": "text"},
            {"name": "password", "value": "fixture-login-password", "type": "password"},
            {"name": "session_code", "value": "fixture-session-code", "type": "hidden"},
        ]
        wp3_flow.remember_sensitive(form_fields, source="oauth_form_submission")
        for value, label in (
            ("fixture-login-user", "username"),
            ("fixture-login-password", "password"),
            ("fixture-session-code", "session_code"),
        ):
            self.assertIn(("unknown", value), wp3_flow.SENSITIVE_VALUES)
            self.assertEqual(
                wp3_flow.SENSITIVE_VALUE_PROVENANCE[("unknown", value)],
                {("oauth_form_submission", label)},
            )
        self.assertIn(("public_fixed_protocol_constant", "username"), wp3_flow.SENSITIVE_VALUES)
        self.assertEqual(
            wp3_flow.SENSITIVE_VALUE_PROVENANCE[("public_fixed_protocol_constant", "username")],
            {("oauth_form_submission", "form_field_name")},
        )

    def test_protocol_identifiers_require_same_response_verified_claims_and_keep_collisions(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.reset_api_response_scan()
        grant = {"client": {"client_id": "route-client-a"}}
        token_a = "verified-route-a-token-001"
        response_a = {"access_token": token_a, "session_state": "route-a-session-identifier-001"}
        collection_a = wp3_flow.remember_sensitive(response_a, source="oauth_token_response")
        self.assertIn(("cookie", response_a["session_state"]), wp3_flow.normalize_log_candidates([]))
        self.assertFalse(wp3_flow.scan_api_response(
            response_a["session_state"].encode("ascii"), [],
        ), "pending candidates remain visible to API response scans before verification")
        token_b = "verified-route-b-token-002"
        response_b = {"access_token": token_b, "session_state": "route-b-session-identifier-002"}
        collection_b = wp3_flow.remember_sensitive(response_b, source="oauth_token_response")
        wp3_flow.resolve_verified_token_response_identifiers(
            collection_a,
            {"sid": response_a["session_state"], "azp": "route-client-a"},
            grant, token_a,
        )
        self.assertIn(
            ("noncredential_protocol_identifier", response_a["session_state"]),
            wp3_flow.SENSITIVE_VALUES,
        )
        self.assertNotIn(
            ("noncredential_protocol_identifier", response_b["session_state"]),
            wp3_flow.SENSITIVE_VALUES,
        )
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({
            "keycloak": response_a["session_state"] + " " + response_b["session_state"],
        })):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"], "unresolved same-field value remains a cookie candidate")
        self.assertEqual(result["secret_match_category_counts"]["cookie"], 1)
        self.assertEqual(result["matched_source_category_counts"]["noncredential_protocol_identifier"], 1)
        wp3_flow.reset_api_response_scan()

        wp3_flow.SENSITIVE_VALUES.clear()
        response = {"access_token": "verified-token-mismatch-003", "session_state": "mismatch-session-identifier-003"}
        collection = wp3_flow.remember_sensitive(response, source="oauth_token_response")
        wp3_flow.resolve_verified_token_response_identifiers(
            collection,
            {"sid": "different-session-identifier-004", "azp": "route-client-a"},
            grant, response["access_token"],
        )
        self.assertIn(("cookie", response["session_state"]), wp3_flow.SENSITIVE_VALUES)
        self.assertNotIn(("noncredential_protocol_identifier", response["session_state"]), wp3_flow.SENSITIVE_VALUES)

        wp3_flow.SENSITIVE_VALUES.clear()
        token = "verified-token-collision-005"
        response = {"active": True, "azp": "route-client-a", "jti": "credential-collision-value-005"}
        collection = wp3_flow.remember_sensitive(
            response, source="oauth_introspection_response", token_binding=token,
        )
        claims = {"azp": "route-client-a", "jti": response["jti"]}
        wp3_flow.resolve_verified_introspection_identifiers(collection, claims, grant, token, active=True)
        wp3_flow.remember_sensitive(response["jti"], "oauth_token", source="explicit_candidate_input", field="access_token")
        wp3_flow.remember_sensitive(response["jti"], "cookie", source="oauth_browser_cookie_jar", field="cookie_value")
        wp3_flow.remember_sensitive(response["jti"], "unknown", source="explicit_candidate_input", field="other")
        self.assertIn(("oauth_token", response["jti"]), wp3_flow.SENSITIVE_VALUES)
        self.assertIn(("cookie", response["jti"]), wp3_flow.SENSITIVE_VALUES)
        self.assertIn(("unknown", response["jti"]), wp3_flow.SENSITIVE_VALUES)
        self.assertIn(("noncredential_protocol_identifier", response["jti"]), wp3_flow.SENSITIVE_VALUES)
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({
            "keycloak": response["jti"],
        })):
            collision_result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(collision_result["passed"], "credential-category collision must remain a failure")
        self.assertEqual(collision_result["secret_match_category_counts"]["oauth_token"], 1)
        self.assertEqual(collision_result["secret_match_category_counts"]["cookie"], 1)
        self.assertEqual(collision_result["secret_match_category_counts"]["unknown"], 1)

    def test_unverified_or_inactive_identifiers_flush_as_original_candidates(self):
        grant = {"client": {"client_id": "route-client-a"}}
        wp3_flow.SENSITIVE_VALUES.clear()
        token_response = {"session_state": "unverified-session-identifier-006"}
        wp3_flow.remember_sensitive(token_response, source="oauth_token_response")
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({
            "keycloak": token_response["session_state"],
        })):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_match_category_counts"]["cookie"], 1)
        self.assertEqual(wp3_flow.PENDING_PROTOCOL_IDENTIFIERS, {})

        wp3_flow.SENSITIVE_VALUES.clear()
        token = "verified-token-inactive-007"
        response = {"active": False, "azp": "route-client-a", "jti": "inactive-jti-identifier-007"}
        collection = wp3_flow.remember_sensitive(
            response, source="oauth_introspection_response", token_binding=token,
        )
        wp3_flow.resolve_verified_introspection_identifiers(
            collection, {"azp": response["azp"], "jti": response["jti"]}, grant, token, active=False,
        )
        self.assertIn(("unknown", response["azp"]), wp3_flow.SENSITIVE_VALUES)
        self.assertIn(("unknown", response["jti"]), wp3_flow.SENSITIVE_VALUES)

        wp3_flow.SENSITIVE_VALUES.clear()
        token_response = {
            "access_token": "response-bound-access-token-012",
            "session_state": "response-bound-session-identifier-013",
        }
        token_collection = wp3_flow.remember_sensitive(token_response, source="oauth_token_response")
        wp3_flow.resolve_verified_token_response_identifiers(
            token_collection,
            {"azp": "route-client-a", "sid": token_response["session_state"]},
            grant,
            "different-verified-token-014",
        )
        self.assertIn(("cookie", token_response["session_state"]), wp3_flow.SENSITIVE_VALUES)
        self.assertNotIn(
            ("noncredential_protocol_identifier", token_response["session_state"]),
            wp3_flow.SENSITIVE_VALUES,
        )

        wp3_flow.SENSITIVE_VALUES.clear()
        token = "introspection-bound-token-015"
        introspection = {"active": True, "azp": "route-client-a", "sid": "introspection-sid-identifier-016"}
        collection = wp3_flow.remember_sensitive(
            introspection, source="oauth_introspection_response", token_binding=token,
        )
        wp3_flow.resolve_verified_introspection_identifiers(
            collection, {"azp": "route-client-a", "sid": introspection["sid"]},
            grant, "different-introspection-token-017", active=True,
        )
        self.assertIn(("unknown", introspection["sid"]), wp3_flow.SENSITIVE_VALUES)

    def test_only_exact_harmless_query_targets_and_form_username_name_are_public(self):
        harmless_small = f"{wp3_flow.API_PATH}?probe=small"
        harmless_full = f"{wp3_flow.API_PATH}?" + "&".join(["x=1"] * 1000)
        for path in (harmless_small, harmless_full):
            self.assertEqual(wp3_flow.api_request_target_log_category(path), "public_fixed_protocol_constant")
        for path in (
            harmless_small + "&extra=1",
            f"{wp3_flow.API_PATH}?probe=%73mall",
            f"{wp3_flow.API_PATH}?access_token=real-token-sentinel-008",
        ):
            self.assertEqual(wp3_flow.api_request_target_log_category(path), "oauth_token")
        self.assertEqual(len(harmless_full), len(wp3_flow.API_PATH) + 1 + len("&".join(["x=1"] * 1000)))

        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.remember_sensitive("username", "password", source="explicit_candidate_input", field="password")
        wp3_flow.remember_sensitive(
            [{"name": "username", "value": "fixture-user-value-009", "type": "text"}],
            source="oauth_form_submission",
        )
        self.assertIn(("public_fixed_protocol_constant", "username"), wp3_flow.SENSITIVE_VALUES)
        self.assertIn(("password", "username"), wp3_flow.SENSITIVE_VALUES)
        self.assertIn(("unknown", "fixture-user-value-009"), wp3_flow.SENSITIVE_VALUES)
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({
            "keycloak": "username fixture-user-value-009",
        })):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"], "form values and an explicit credential collision are still sensitive")

    def test_identifier_promotion_requires_literal_top_level_key_and_expected_source(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        token = "verified-alias-token-018"
        grant = {"client": {"client_id": "route-client-a"}}
        for response, source, expected_category, candidate in (
            ({"SESSION_STATE": "upper-session-identifier-019"}, "oauth_token_response", "cookie", "upper-session-identifier-019"),
            ({"session-state": "dash-session-identifier-020"}, "oauth_token_response", "cookie", "dash-session-identifier-020"),
            ({"SID": "upper-sid-identifier-021"}, "oauth_introspection_response", "unknown", "upper-sid-identifier-021"),
            ({"nested": {"sid": "nested-sid-identifier-022"}}, "oauth_introspection_response", "unknown", "nested-sid-identifier-022"),
        ):
            with self.subTest(source=source, response_key=next(iter(response))):
                collection = wp3_flow.remember_sensitive(
                    {"access_token": token, **response} if source == "oauth_token_response" else {"active": True, **response},
                    source=source, token_binding=token if source == "oauth_introspection_response" else None,
                )
                claims = {"azp": "route-client-a", "sid": candidate}
                if source == "oauth_token_response":
                    wp3_flow.resolve_verified_token_response_identifiers(collection, claims, grant, token)
                else:
                    wp3_flow.resolve_verified_introspection_identifiers(
                        collection, claims, grant, token, active=True,
                    )
                self.assertIn((expected_category, candidate), wp3_flow.SENSITIVE_VALUES)
                self.assertNotIn(("noncredential_protocol_identifier", candidate), wp3_flow.SENSITIVE_VALUES)

        wp3_flow.SENSITIVE_VALUES.clear()
        untrusted_collection = wp3_flow.remember_sensitive(
            {"active": True, "sid": "wrong-source-sid-identifier-023"},
            source="oauth_admin_bearer", token_binding=token,
        )
        self.assertIsNone(untrusted_collection)
        self.assertIn(("unknown", "wrong-source-sid-identifier-023"), wp3_flow.SENSITIVE_VALUES)

    def test_pending_identifier_capacity_overflow_keeps_the_original_candidate(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        with patch.object(wp3_flow, "MAX_PENDING_PROTOCOL_IDENTIFIERS", 0):
            collection = wp3_flow.remember_sensitive(
                {"access_token": "bounded-overflow-access-token-024", "session_state": "bounded-overflow-session-025"},
                source="oauth_token_response",
            )
        self.assertIsNotNone(collection)
        self.assertIn(("cookie", "bounded-overflow-session-025"), wp3_flow.SENSITIVE_VALUES)
        self.assertEqual(wp3_flow.PENDING_PROTOCOL_IDENTIFIERS[collection], [])

    def test_noncredential_identifiers_are_counted_but_not_secret_matches_and_receipt_is_strict(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        identifier = "verified-jti-identifier-010"
        credential = "separate-cookie-secret-011"
        token = "verified-token-receipt-010"
        collection = wp3_flow.remember_sensitive(
            {"active": True, "jti": identifier},
            source="oauth_introspection_response", token_binding=token,
        )
        grant = {"client": {"client_id": "route-client-a"}}
        wp3_flow.resolve_verified_introspection_identifiers(
            collection, {"azp": "route-client-a", "jti": identifier}, grant, token, active=True,
        )
        wp3_flow.remember_sensitive(credential, "cookie", source="oauth_browser_cookie_jar", field="cookie_value")
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({
            "keycloak": identifier + " " + credential,
        })):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["matched_source_category_counts"]["noncredential_protocol_identifier"], 1)
        self.assertEqual(result["secret_match_category_counts"]["noncredential_protocol_identifier"], 0)
        self.assertEqual(result["secret_value_match_count"], 1)
        self.assertNotIn(identifier, json.dumps(result))
        receipt = self._runtime_receipt_with_log_scan(result)
        wp3_prepare.validate_runtime_receipt(receipt)
        tampered = json.loads(json.dumps(receipt))
        tampered["log_scan"]["secret_match_category_counts"]["noncredential_protocol_identifier"] = 1
        tampered["log_scan"]["secret_value_match_count"] += 1
        with self.assertRaisesRegex(Exception, "restricted protocol identifiers"):
            wp3_prepare.validate_runtime_receipt(tampered)

    def test_keycloak_disabled_introspection_event_context_is_only_a_fixed_observation(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        candidate = "FIXTURE-UNKNOWN-FIELD-VALUE-001"
        wp3_flow.remember_sensitive(
            candidate, "unknown", source="oauth_introspection_response", field="sid",
        )
        logs = complete_service_logs({
            "keycloak": (
                "org.keycloak.events type=INTROSPECT_TOKEN_ERROR error=user_disabled "
                + candidate
            ),
        })
        with patch.object(wp3_flow, "compose_service_logs", return_value=logs):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_value_match_count"], 1)
        self.assertEqual(
            result["service_scans"]["keycloak"]["matched_log_context_counts"]["keycloak_introspection_token_error"],
            1,
        )
        for error_shape in ('error="user_disabled"', "error='user_disabled'"):
            self.assertEqual(
                wp3_flow._log_context_for_line(
                    "keycloak", f"org.keycloak.events type=INTROSPECT_TOKEN_ERROR {error_shape}"
                ),
                "keycloak_introspection_token_error",
            )
        self.assertEqual(
            wp3_flow._log_context_for_line(
                "keycloak", "org.keycloak.events type=INTROSPECT_TOKEN_ERROR error=other"
            ),
            "other_service_log_context",
        )
        wp3_prepare.validate_runtime_receipt(self._runtime_receipt_with_log_scan(result))

    def test_log_diagnostic_receipt_rejects_unbounded_provenance_and_context_labels(self):
        self.assertEqual(wp3_flow.LOG_CANDIDATE_SOURCES, wp3_prepare.WP3_LOG_CANDIDATE_SOURCES)
        self.assertEqual(wp3_flow.LOG_CANDIDATE_FIELDS, wp3_prepare.WP3_LOG_CANDIDATE_FIELDS)
        self.assertEqual(wp3_flow.LOG_MATCH_CONTEXTS, wp3_prepare.WP3_LOG_MATCH_CONTEXTS)
        wp3_flow.SENSITIVE_VALUES.clear()
        token = "TEST-OAUTH-TOKEN-PROVENANCE-002"
        wp3_flow.remember_sensitive(
            token, "oauth_token", source="oauth_verified_access_token", field="access_token",
        )
        logs = complete_service_logs({"keycloak": f"POST /protocol/openid-connect/token {token}"})
        with patch.object(wp3_flow, "compose_service_logs", return_value=logs):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        receipt = self._runtime_receipt_with_log_scan(result)
        receipt["result"] = "fail"
        tampered = json.loads(json.dumps(receipt))
        tampered["log_scan"]["service_scans"]["keycloak"]["matched_candidate_provenance"][0]["value"] = token
        with self.assertRaises(Exception):
            wp3_prepare.validate_runtime_receipt(tampered)
        tampered = json.loads(json.dumps(receipt))
        tampered["log_scan"]["service_scans"]["keycloak"]["matched_log_context_counts"]["arbitrary_context"] = 1
        with self.assertRaises(Exception):
            wp3_prepare.validate_runtime_receipt(tampered)
        tampered = json.loads(json.dumps(receipt))
        tampered["log_scan"]["service_scans"]["keycloak"]["matched_candidate_provenance"] = []
        with self.assertRaises(Exception):
            wp3_prepare.validate_runtime_receipt(tampered)
        tampered = json.loads(json.dumps(receipt))
        for context in tampered["log_scan"]["service_scans"]["keycloak"]["matched_log_context_counts"]:
            tampered["log_scan"]["service_scans"]["keycloak"]["matched_log_context_counts"][context] = 0
        with self.assertRaises(Exception):
            wp3_prepare.validate_runtime_receipt(tampered)

    def _runtime_receipt_with_log_scan(self, log_scan):
        image_contract = {
            name: {"digest": digest, "architecture": "arm64"}
            for name, (_reference, digest) in wp3_flow.IMAGES.items()
        }
        return {
            "schema_version": 1, "scope": "wp3-api-runtime-isolated-validation", "result": "fail",
            "host_ports": {"keycloak": 18444, "api_gateway": 18443, "oauth_callback": 8443},
            "images": image_contract,
            "cases": {
                "scope": "wp3_positive_and_required_negative_matrix",
                "execution": {
                    "scope": "wp3_positive_and_required_negative_matrix", "outcome": "fail",
                    "phase": "whole_runtime_log_scan", "layer": "harness_or_transport", "http_status": None,
                    "host_runtime": None, "schema_probe": None,
                    "schema_probe_diagnostic": {"stage": "not_started", "reason": "not_started", "plugin": "none"},
                    "state_contract": None, "header_parser_metadata": None,
                    "effective_inbound_tls_policy": None, "negative_group_failures": [],
                },
                "acceptance": [{
                    "case_id": "LEAK-01", "variant": "whole_runtime_lifecycle", "outcome": "fail",
                    "phase": "whole_runtime_log_scan", "layer": "harness", "http_status": None,
                    "rfc6750_challenge": "not_applicable",
                }],
                "full_wp3_acceptance": "fail",
            },
            "tls": {name: "not_run" for name in (
                "localhost_sni_positive", "kong_api_sni_positive",
                "localhost_sni_requested_client_certificate", "kong_api_sni_requested_client_certificate",
                "no_client_certificate_handshake_rejected", "tls_11_rejected", "tls_12_only_rejected", "weak_cipher_rejected",
                "untrusted_server_certificate_rejected", "san_mismatch_rejected",
            )},
            "capture": {
                "request_count": 0, "api_peer_pin_matches": "not_run", "api_peer_common_name_matches": "not_run",
                "authorization_single_bearer": "not_run", "authorization_sha256_present": "not_run",
                "forwarded_certificate_thumbprint_present": "not_run", "forwarded_certificate_single_url_encoded_pem_leaf": "not_run",
                "cookie_absent": "not_run", "client_assertion_headers_absent": "not_run",
                "client_assertion_unknown_suffix_header_count": "not_run", "fixture_underscores_in_headers_on": "not_run",
                "x_fapi_headers_absent": "not_run", "x_demo_unexpected_headers_absent": "not_run",
                "department_header_matches_expected_claim": "not_run", "route_header_matches_expected_claim": "not_run",
                "x_client_cert_like_header_count": "not_run", "x_client_cert_header_count": "not_run",
                "x_client_cert_unknown_suffix_header_count": "not_run", "x_client_cert_duplicate_header_count": "not_run",
                "x_client_cert_underscore_alias_count": "not_run", "x_client_cert_stock_details_complete": "not_run",
                "x_client_cert_stock_detail_counts": {name: "not_run" for name in ("serial", "issuer_dn", "subject_dn", "fingerprint", "chain")},
                "x_client_cert_fingerprint_matches_forwarded_leaf": "not_run", "caller_spoof_sentinel_match_count": "not_run",
            },
            "log_scan": log_scan, "containers_started": True, "konnect_read_or_write_performed": False,
        }

    def test_partial_service_log_capture_is_never_an_aggregate_pass(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        secret = "TEST-PARTIAL-OAUTH-SECRET-001"
        partial = failed_service_logs(
            "log_read_failed", {"keycloak": "clean complete log", "kong-api": secret}, failed_service="kong-api"
        )
        with patch.object(wp3_flow, "compose_service_logs", return_value=partial):
            result = wp3_flow.scan_logs_for_sensitive_values([("oauth_token", secret)])
        self.assertFalse(result["passed"])
        self.assertFalse(result["completed"])
        self.assertEqual(result["failure_reason"], "log_read_failed")
        self.assertEqual(result["checked_value_count"], 0)
        self.assertTrue(result["service_scans"]["keycloak"]["passed"])
        self.assertFalse(result["service_scans"]["kong-api"]["completed"])
        self.assertEqual(result["service_scans"]["kong-api"]["checked_value_count"], 0)
        self.assertEqual(result["service_scans"]["kong-api"]["secret_match_category_counts"]["oauth_token"], 0)
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret, encoded)

    def test_service_scan_inventory_failure_marks_every_fixed_service_incomplete(self):
        foreign = {"keycloak": "owned-id", "kong-api": "owned-api", "unexpected": "foreign-id"}
        with patch.object(wp3_flow, "verify_owned_project_containers", return_value=foreign), patch.object(
            wp3_flow.subprocess, "Popen", side_effect=AssertionError("unknown service must not be read")
        ):
            logs, statuses, failure = wp3_flow.compose_service_logs()
        self.assertEqual(logs, {})
        self.assertEqual(failure, "container_inventory_unavailable")
        self.assertEqual(set(statuses), set(wp3_flow.LOG_SERVICE_NAMES))
        self.assertTrue(all(row["completed"] is False for row in statuses.values()))
        self.assertTrue(all(row["failure_reason"] == "container_inventory_unavailable" for row in statuses.values()))

    def test_service_log_collector_bounds_total_bytes_and_keeps_stdout_stderr_in_memory(self):
        container_ids = {service: f"container-{service}" for service in wp3_flow.LOG_SERVICE_NAMES}
        real_popen = subprocess.Popen

        def launch_child(command, **kwargs):
            service = next(name for name, container_id in container_ids.items() if command[-1] == container_id)
            script = (
                "import sys; print('stdout-" + service + "'); "
                "print('stderr-" + service + "', file=sys.stderr)"
            )
            return real_popen([sys.executable, "-c", script], **kwargs)

        with patch.object(wp3_flow, "verify_owned_project_containers", return_value=container_ids), patch.object(
            wp3_flow.subprocess, "Popen", side_effect=launch_child
        ):
            logs, statuses, failure = wp3_flow.compose_service_logs()
        self.assertEqual(failure, "none")
        self.assertEqual(set(logs), set(wp3_flow.LOG_SERVICE_NAMES))
        self.assertTrue(all(row["completed"] for row in statuses.values()))
        self.assertTrue(all("stdout-" in logs[service] and "stderr-" in logs[service] for service in logs))
        self.assertEqual(
            {service: statuses[service]["scanned_byte_count"] for service in statuses},
            {service: len(logs[service].encode("utf-8")) for service in logs},
        )

        with patch.object(wp3_flow, "MAX_SERVICE_LOG_BYTES", 128), patch.object(
            wp3_flow, "MAX_LOG_BYTES", 1024
        ), patch.object(wp3_flow, "verify_owned_project_containers", return_value=container_ids), patch.object(
            wp3_flow.subprocess, "Popen", side_effect=lambda _command, **kwargs: real_popen(
                [sys.executable, "-c", "print('x' * 256)"], **kwargs
            )
        ):
            logs, statuses, failure = wp3_flow.compose_service_logs()
        self.assertEqual(failure, "byte_limit_exceeded")
        self.assertFalse(all(row["completed"] for row in statuses.values()))
        self.assertTrue(all(row["scanned_byte_count"] <= 128 for row in statuses.values()))
        self.assertEqual(set(logs), {service for service, row in statuses.items() if row["completed"]})

        with patch.object(wp3_flow, "MAX_SERVICE_LOG_BYTES", 1024), patch.object(
            wp3_flow, "MAX_LOG_BYTES", 128
        ), patch.object(wp3_flow, "verify_owned_project_containers", return_value=container_ids), patch.object(
            wp3_flow.subprocess, "Popen", side_effect=lambda _command, **kwargs: real_popen(
                [sys.executable, "-c", "print('y' * 80)"], **kwargs
            )
        ):
            logs, statuses, failure = wp3_flow.compose_service_logs()
        self.assertEqual(failure, "byte_limit_exceeded")
        self.assertFalse(all(row["completed"] for row in statuses.values()))
        self.assertEqual(set(logs), {service for service, row in statuses.items() if row["completed"]})

        with patch.object(wp3_flow, "MAX_LOG_SCAN_SECONDS", 0.05), patch.object(
            wp3_flow, "verify_owned_project_containers", return_value=container_ids
        ), patch.object(
            wp3_flow.subprocess, "Popen", side_effect=lambda _command, **kwargs: real_popen(
                [sys.executable, "-c", "import time; time.sleep(2)"] if kwargs.get("cwd") is not None else [sys.executable],
                **kwargs,
            )
        ):
            logs, statuses, failure = wp3_flow.compose_service_logs()
        self.assertEqual(failure, "time_limit_exceeded")
        self.assertFalse(any(row["completed"] for row in statuses.values()))
        self.assertTrue(all(row["failure_reason"] == "time_limit_exceeded" for row in statuses.values()))
        self.assertEqual(logs, {})

    def test_log_scan_reports_fixed_source_categories_without_values(self):
        candidates = [
            ("certificate", "TEST-CERTIFICATE-MARKER-01"),
            ("privatekey", "TEST-PRIVATEKEY-MARKER-01"),
            ("license", "TEST-LICENSE-MARKER-0001"),
            ("password", "TEST-PASSWORD-MARKER-0001"),
            ("oauth_token", "TEST-OAUTH-TOKEN-MARKER-01"),
            ("code", "TEST-AUTH-CODE-MARKER-0001"),
            ("assertion", "TEST-ASSERTION-MARKER-0001"),
            ("cookie", "TEST-COOKIE-MARKER-00001"),
            ("verifier", "TEST-PKCE-VERIFIER-MARKER-1"),
            ("spoof_sentinel", "TEST-SPOOF-SENTINEL-MARKER"),
            ("unknown", "TEST-UNKNOWN-SECRET-MARKER"),
            ("public_fixed_protocol_constant", wp3_flow.PUBLIC_ORIGIN),
            ("public_fixture_identifier", "engineering.user@fapi-demo.invalid"),
        ]
        log_text = " ".join(value for _category, value in candidates)
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": log_text})):
            result = wp3_flow.scan_logs_for_sensitive_values(candidates)
        self.assertFalse(result["passed"])
        self.assertTrue(result["completed"])
        self.assertEqual(result["secret_value_match_count"], 11)
        self.assertEqual(result["secret_match_category_counts"]["unknown"], 1)
        self.assertGreaterEqual(result["matched_source_category_counts"]["public_fixed_protocol_constant"], 1)
        self.assertGreaterEqual(result["public_fixed_protocol_constant_observation_count"], 1)
        self.assertEqual(result["public_fixture_identifier_observation_count"], 1)
        encoded = json.dumps(result, sort_keys=True)
        for _category, value in candidates:
            self.assertNotIn(value, encoded)

    def test_public_protocol_constant_observation_does_not_hide_unknown_secret(self):
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": wp3_flow.PUBLIC_ORIGIN})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertTrue(result["passed"])
        self.assertEqual(result["secret_value_match_count"], 0)
        self.assertEqual(result["public_fixed_protocol_constant_observation_count"], 1)
        with patch.object(
            wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": f"{wp3_flow.PUBLIC_ORIGIN} TEST-UNCLASSIFIED-SECRET"})
        ):
            result = wp3_flow.scan_logs_for_sensitive_values([("unknown", "TEST-UNCLASSIFIED-SECRET")])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_match_category_counts"]["unknown"], 1)

    def test_public_fixture_username_observation_is_not_a_credential_match(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        logs = "login wp2-preview-admin engineering.user@fapi-demo.invalid sales.user@fapi-demo.invalid"
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": logs})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertTrue(result["passed"])
        self.assertTrue(result["completed"])
        self.assertEqual(result["secret_value_match_count"], 0)
        self.assertEqual(result["public_fixture_identifier_observation_count"], 3)

    def test_public_username_is_still_sensitive_when_used_as_password(self):
        with TemporaryDirectory() as directory:
            preview = Path(directory)
            (preview / "pki").mkdir(mode=0o700)
            (preview / "bootstrap.env").write_text(
                "KC_BOOTSTRAP_ADMIN_USERNAME=wp2-preview-admin\n"
                "KC_BOOTSTRAP_ADMIN_PASSWORD=engineering.user@fapi-demo.invalid\n"
            )
            (preview / "accounts.env").write_text(
                "WP2_ENGINEERING_USERNAME=engineering.user@fapi-demo.invalid\n"
                "WP2_ENGINEERING_PASSWORD=fixture-engineering-password\n"
                "WP2_SALES_USERNAME=sales.user@fapi-demo.invalid\n"
                "WP2_SALES_PASSWORD=fixture-sales-password\n"
            )
            for path in (preview / "bootstrap.env", preview / "accounts.env"):
                path.chmod(0o600)
            with patch.object(wp3_flow, "PREVIEW", preview), patch.object(
                wp3_flow, "load_runtime_role_values", return_value={}
            ):
                sensitive_values = wp3_flow.collect_fixture_sensitive_values()
            self.assertIn(("password", "engineering.user@fapi-demo.invalid"), sensitive_values)
            self.assertNotIn(("unknown", "wp2-preview-admin"), sensitive_values)
            logs = "password=engineering.user@fapi-demo.invalid"
            with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": logs})):
                result = wp3_flow.scan_logs_for_sensitive_values(sensitive_values)
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_value_match_count"], 1)

    def test_public_identifier_explicitly_marked_sensitive_still_fails(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        value = "sales.user@fapi-demo.invalid"
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": f"username={value}"})):
            result = wp3_flow.scan_logs_for_sensitive_values([value])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_value_match_count"], 1)
        self.assertEqual(result["public_fixture_identifier_observation_count"], 1)

    def test_grant_nonce_state_jti_par_challenge_and_unknown_list_stay_tracked(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        values = {
            "nonce": "TEST-NONCE-SECRET-MARKER",
            "state": "TEST-STATE-SECRET-MARKER",
            "jti": "TEST-JTI-SECRET-MARKER-01",
            "request_uri": "TEST-PAR-REQUEST-URI-0001",
            "code_challenge": "TEST-CODE-CHALLENGE-MARKER",
        }
        wp3_flow.remember_sensitive({"grant": values})
        wp3_flow.remember_sensitive(["TEST-UNKNOWN-LIST-SECRET-MARKER"])
        logs = " ".join(values.values()) + " TEST-UNKNOWN-LIST-SECRET-MARKER"
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": logs})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_match_category_counts"]["unknown"], 5)
        self.assertEqual(result["secret_match_category_counts"]["verifier"], 1)
        self.assertNotIn("TEST-NONCE-SECRET-MARKER", json.dumps(result))
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_public_certificate_filenames_are_not_material_but_explicit_password_is(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.remember_sensitive({"client": {"certificate": "route-a.crt", "key": "route-a.key"}})
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": "route-a.crt route-a.key"})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertTrue(result["passed"])
        self.assertEqual(result["secret_value_match_count"], 0)
        self.assertGreaterEqual(result["public_fixture_identifier_observation_count"], 2)

        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.remember_sensitive({"password": "route-a.crt"})
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": "password=route-a.crt"})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_match_category_counts"]["password"], 1)
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_public_literal_in_arbitrary_unknown_list_remains_sensitive(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.remember_sensitive([wp3_flow.PUBLIC_ISSUER])
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": wp3_flow.PUBLIC_ISSUER})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_match_category_counts"]["unknown"], 1)
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_public_audience_scope_and_client_metadata_need_exact_field_matches(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.remember_sensitive({
            "issuer": wp3_flow.PUBLIC_ISSUER,
            "aud": ["fapi-demo-api", "api-gateway-introspection"],
            "scope": "openid profile",
            "client_id": "third-party-fapi-mtls",
        })
        self.assertTrue(all(category in wp3_flow.PUBLIC_LOG_CATEGORIES for category, _value in wp3_flow.SENSITIVE_VALUES))
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.remember_sensitive({"arbitrary": wp3_flow.PUBLIC_ISSUER})
        self.assertIn(("unknown", wp3_flow.PUBLIC_ISSUER), wp3_flow.SENSITIVE_VALUES)
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_fresh_route_cnf_thumbprints_are_public_only_at_exact_bound_field(self):
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.PUBLIC_ROUTE_CERT_THUMBPRINTS.clear()
        wp3_flow.reset_api_response_scan()
        with TemporaryDirectory() as directory:
            pki = Path(directory)
            for filename in ("route-a.crt", "route-b.crt"):
                cert = self.make_test_certificate()
                (pki / filename).write_bytes(cert.public_bytes(Encoding.PEM))

            wp3_flow.register_public_route_certificate_thumbprints(FakeWp2(), pki)
            self.assertEqual(len(wp3_flow.PUBLIC_ROUTE_CERT_THUMBPRINTS), 2)
            thumbprint = next(iter(wp3_flow.PUBLIC_ROUTE_CERT_THUMBPRINTS))
            introspection = {
                "active": True,
                "aud": ["fapi-demo-api", "api-gateway-introspection"],
                "cnf": {"x5t#S256": thumbprint},
            }
            wp3_flow.remember_sensitive(introspection)
            self.assertIn(("public_fixture_identifier", thumbprint), wp3_flow.SENSITIVE_VALUES)
            capture_body = json.dumps({"forwarded_certificate_thumbprint": thumbprint}).encode()
            self.assertTrue(wp3_flow.scan_api_response(capture_body, []))
            receipt = wp3_flow.api_response_scan_receipt()
            self.assertEqual(receipt["api_response_secret_value_match_count"], 0)
            self.assertNotIn(thumbprint, json.dumps(receipt))

            wp3_flow.SENSITIVE_VALUES.clear()
            wp3_flow.reset_api_response_scan()
            wp3_flow.remember_sensitive({"password": {"cnf": {"x5t#S256": thumbprint}}})
            self.assertFalse(wp3_flow.scan_api_response(capture_body, []))
            self.assertEqual(
                wp3_flow.api_response_scan_receipt()["api_response_secret_match_category_counts"]["password"],
                1,
            )

            wp3_flow.SENSITIVE_VALUES.clear()
            wp3_flow.reset_api_response_scan()
            wp3_flow.remember_sensitive([thumbprint])
            self.assertFalse(wp3_flow.scan_api_response(capture_body, []))
            self.assertEqual(
                wp3_flow.api_response_scan_receipt()["api_response_secret_match_category_counts"]["unknown"],
                1,
            )

            wp3_flow.SENSITIVE_VALUES.clear()
            wp3_flow.PUBLIC_ROUTE_CERT_THUMBPRINTS.clear()
            wp3_flow.reset_api_response_scan()
            wp3_flow.remember_sensitive({"cnf": {"x5t#S256": thumbprint}})
            self.assertFalse(wp3_flow.scan_api_response(capture_body, []))
            self.assertEqual(
                wp3_flow.api_response_scan_receipt()["api_response_secret_match_category_counts"]["unknown"],
                1,
            )
        wp3_flow.SENSITIVE_VALUES.clear()
        wp3_flow.PUBLIC_ROUTE_CERT_THUMBPRINTS.clear()
        wp3_flow.reset_api_response_scan()

    def test_explicit_sensitive_container_overrides_nested_public_metadata(self):
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_audience_fixture_toggles_both_api_mapper_claims_and_restores_full_config(self):
        api_mapper = {
            "id": "api-mapper-id", "name": "pop-verifier-audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": "fapi-demo-api", "access.token.claim": "true",
                "introspection.token.claim": "true", "userinfo.token.claim": "false",
            },
        }
        intro_mapper = {
            "id": "intro-mapper-id", "name": "api-gateway-introspection-audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": "api-gateway-introspection", "access.token.claim": "true",
                "introspection.token.claim": "true", "userinfo.token.claim": "false",
            },
        }
        original_api = json.loads(json.dumps(api_mapper))
        original_intro = json.loads(json.dumps(intro_mapper))
        state = {"api": api_mapper, "intro": intro_mapper}

        class FakeAdmin:
            CLIENTS = {"a": {"client_id": "third-party-fapi-mtls"}}

            @staticmethod
            def request_json(_base, path, _ca, **kwargs):
                if path.startswith("/admin/realms/fapi-demo/clients?"):
                    return [{"clientId": "third-party-fapi-mtls", "id": "fresh-client-id"}]
                if path.endswith("/protocol-mappers/models"):
                    return [state["api"], state["intro"]]
                if kwargs.get("method") == "PUT":
                    updated = kwargs["json_body"]
                    if updated["id"] == "api-mapper-id":
                        state["api"] = json.loads(json.dumps(updated))
                    elif updated["id"] == "intro-mapper-id":
                        state["intro"] = json.loads(json.dumps(updated))
                    return {}
                raise AssertionError("unexpected fixture mapper request")

        admin = FakeAdmin()
        _client_uuid, mapper = wp3_flow._client_and_mapper(FakeAdmin, "fixture-admin", "third-party-fapi-mtls")
        wp3_flow.set_api_audience_mapper(FakeAdmin, "fixture-admin", "third-party-fapi-mtls", mapper, False)
        self.assertEqual(state["api"]["config"]["access.token.claim"], "false")
        self.assertEqual(state["api"]["config"]["introspection.token.claim"], "false")
        self.assertEqual(state["intro"], original_intro)
        wp3_flow.restore_api_audience_mapper(FakeAdmin, "fixture-admin", mapper)
        self.assertEqual(state["api"], original_api)
        self.assertEqual(state["intro"], original_intro)
        values = {"password": {"iss": wp3_flow.PUBLIC_ISSUER}, "token": {"aud": ["fapi-demo-api"]}}
        wp3_flow.remember_sensitive(values)
        for candidate in (wp3_flow.PUBLIC_ISSUER, "fapi-demo-api"):
            with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": f"sensitive={candidate}"})):
                result = wp3_flow.scan_logs_for_sensitive_values([])
            self.assertFalse(result["passed"])
            self.assertEqual(result["secret_value_match_count"], 1)
            self.assertGreaterEqual(result["secret_match_category_counts"]["password"] + result["secret_match_category_counts"]["oauth_token"], 1)
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_ordered_request_serializer_preserves_duplicate_headers(self):
        encoded = wp3_flow.serialize_api_request(
            "GET", "/fapi-api/evidence", [("Authorization", "Bearer first"), ("Authorization", "Bearer second")]
        )
        self.assertEqual(encoded.count(b"Authorization:"), 2)
        self.assertLess(encoded.index(b"Bearer first"), encoded.index(b"Bearer second"))

    def test_header_matrix_builder_counts_the_complete_http_envelope(self):
        for expected in (101, 999, 1000, 1001):
            pairs = wp3_flow._header_pairs_for_total(expected, "fixture-token")
            self.assertEqual(3 + len(pairs), expected)
        pairs = wp3_flow._header_pairs_for_total(101, "fixture-token", [("x_fapi_Arbitrary", "sentinel")])
        self.assertEqual(3 + len(pairs), 101)
        self.assertEqual(pairs[-1], ("x_fapi_Arbitrary", "sentinel"))
        pairs_1001 = wp3_flow._header_pairs_for_total(1001, "fixture-token", [("x_fapi_Arbitrary", "sentinel")])
        self.assertTrue(wp3_flow._valid_wire_header_pairs(
            pairs_1001, 1001, required_last=("x_fapi_Arbitrary", "sentinel"),
        ))
        self.assertFalse(wp3_flow._valid_wire_header_pairs(
            pairs_1001[:-1] + [("invalid header", "sentinel")], 1001,
            required_last=("invalid header", "sentinel"),
        ))

    def test_header_boundary_records_wire_and_upstream_counts_independently(self):
        rows = wp3_flow.initial_cases()
        token = "test-token"
        headers = wp3_flow._header_pairs_for_total(101, token, [("x_fapi_Arbitrary", "attack-sentinel")])
        context = {
            "pki": Path("pki"),
            "wp2": object(),
            "containers": {"pop-verifier": "capture"},
            "capture": {},
        }
        route = {
            "token": token,
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "claims": {}, "sni": "localhost",
        }
        evidence = {"request_header_count": 117}
        with patch.object(wp3_flow, "capture_request_count", side_effect=[2, 3]), patch.object(
            wp3_flow, "request_api", return_value=(200, [], evidence)
        ), patch.object(wp3_flow, "verify_capture"), patch.object(wp3_flow, "record_capture_observation"):
            wp3_flow._check_capture_positive(rows, "HEADER-CERT-01", "headers_101", context, route, headers, 101)
        row = next(row for row in rows if row.get("variant") == "headers_101")
        self.assertEqual(row["outcome"], "pass")
        self.assertEqual(row["input_wire_header_count"], 101)
        self.assertEqual(row["upstream_header_count"], 117)

    def test_header_1000_lua_limit_requires_431_and_unproven_1001_parser_400_stays_needs_design(self):
        rows = wp3_flow.initial_cases()
        route = {
            "token": "test-token",
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "claims": {}, "sni": "localhost",
        }
        context = {"pki": Path("pki"), "containers": {"pop-verifier": "capture"}}
        def record_positive(rows, _case_id, variant, _context, _route, _headers=None, expected_total=None):
            wp3_flow.mark_variant_case(
                rows, "HEADER-CERT-01", variant, "pass", "api_header_boundary", "gateway+upstream_capture",
                200, "not_applicable", input_wire_header_count=expected_total or 20,
                upstream_header_count=(expected_total or 20) + 16,
            )
        with patch.object(wp3_flow, "_check_capture_positive", side_effect=record_positive), patch.object(
            wp3_flow, "capture_request_count", side_effect=[0, 0, 0, 0]
        ), patch.object(wp3_flow, "_nginx_header_rejection_observation", return_value={
            "completed": False, "error_marker_count": None, "api_request_marker_count": None,
        }), patch.object(wp3_flow, "_api_response_scan_delta_is_clean", return_value=True), patch.object(wp3_flow, "request_api", side_effect=[
            (431, [], {}), (400, [], {}),
        ]):
            wp3_flow._run_header_matrix(rows, context, route)
        observed = {row["variant"]: row for row in rows if row.get("case_id") == "HEADER-CERT-01"}
        self.assertEqual((observed["headers_1000"]["outcome"], observed["headers_1000"]["http_status"]), ("pass", 431))
        self.assertEqual((observed["headers_1000"]["input_wire_header_count"], observed["headers_1000"]["upstream_header_count"]), (1000, None))
        self.assertEqual((observed["headers_1001"]["outcome"], observed["headers_1001"]["http_status"]), ("needs_design", 400))
        self.assertEqual(observed["headers_1001"]["input_wire_header_count"], 1001)
        self.assertIsNone(observed["headers_1001"]["upstream_header_count"])
        self.assertEqual(observed["headers_1001"]["parser_source"], "not_proven")

    def test_header_1001_parser_pass_requires_all_exact_image_log_and_control_proofs(self):
        rows = wp3_flow.initial_cases()
        route = {
            "token": "test-token",
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "claims": {}, "sni": "localhost",
        }
        context = {
            "pki": Path("pki"), "containers": {"pop-verifier": "capture"},
            "header_parser_metadata": {
                "nginx_version": "openresty/1.29.2.5", "max_headers_override_absent": True,
                "default_header_limit": 1000, "source": "pinned_image_default_1000",
            },
        }
        def record_positive(rows, _case_id, variant, _context, _route, _headers=None, expected_total=None):
            wp3_flow.mark_variant_case(
                rows, "HEADER-CERT-01", variant, "pass", "api_header_boundary", "gateway+upstream_capture",
                200, "not_applicable", input_wire_header_count=expected_total or 20,
                upstream_header_count=(expected_total or 20) + 16,
            )
        logs = [
            {"completed": True, "error_marker_count": 0, "api_request_marker_count": 0},
            {"completed": True, "error_marker_count": 1, "api_request_marker_count": 1},
        ]
        with patch.object(wp3_flow, "_check_capture_positive", side_effect=record_positive), patch.object(
            wp3_flow, "capture_request_count", side_effect=[0, 0, 0, 0]
        ), patch.object(wp3_flow, "_nginx_header_rejection_observation", side_effect=logs), patch.object(
            wp3_flow, "_api_response_scan_delta_is_clean", return_value=True
        ), patch.object(wp3_flow, "request_api", side_effect=[(431, [], {}), (400, [], {})]) as request:
            wp3_flow._run_header_matrix(rows, context, route)
        row = next(row for row in rows if row.get("variant") == "headers_1001")
        self.assertEqual((row["outcome"], row["http_status"], row["layer"]), ("pass", 400, "nginx_parser"))
        self.assertEqual(row["parser_source"], "pinned_image_default_1000")
        self.assertEqual((row["parser_error_marker_delta"], row["parser_api_request_marker_delta"]), (1, 1))
        self.assertTrue(row["wire_grammar_valid"] and row["upstream_unchanged"])
        self.assertTrue(row["response_scan_clean"] and row["post_negative_valid_control"])
        self.assertEqual(request.call_args_list[1].kwargs["headers"][-1], ("x_fapi_Arbitrary", "WP3-SPOOF-1001-PARSER-BOUNDARY"))

    def test_header_1001_http431_is_not_mislabeled_without_layer_proof(self):
        rows = wp3_flow.initial_cases()
        route = {
            "token": "test-token",
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "claims": {}, "sni": "localhost",
        }
        context = {"pki": Path("pki"), "containers": {"pop-verifier": "capture"}}
        def record_positive(rows, _case_id, variant, _context, _route, _headers=None, expected_total=None):
            wp3_flow.mark_variant_case(
                rows, "HEADER-CERT-01", variant, "pass", "api_header_boundary", "gateway+upstream_capture",
                200, "not_applicable", input_wire_header_count=expected_total or 20,
                upstream_header_count=(expected_total or 20) + 16,
            )
        with patch.object(wp3_flow, "_check_capture_positive", side_effect=record_positive), patch.object(
            wp3_flow, "capture_request_count", side_effect=[0, 0, 0, 0]
        ), patch.object(wp3_flow, "_nginx_header_rejection_observation", return_value={
            "completed": False, "error_marker_count": None, "api_request_marker_count": None,
        }), patch.object(wp3_flow, "_api_response_scan_delta_is_clean", return_value=True), patch.object(
            wp3_flow, "request_api", side_effect=[(431, [], {}), (431, [], {})]
        ):
            wp3_flow._run_header_matrix(rows, context, route)
        row = next(row for row in rows if row.get("variant") == "headers_1001")
        self.assertEqual(row["outcome"], "needs_design")

    def test_rfc6750_parser_accepts_bws_and_ows_around_auth_parameters(self):
        self.assertEqual(
            wp3_flow.rfc6750_error([("www-authenticate", 'Bearer realm \t= \t"api" \t,\terror\t=\t"invalid_token"')], "invalid_token"),
            "invalid_token",
        )
        self.assertEqual(
            wp3_flow.rfc6750_error([("www-authenticate", 'Bearer error=insufficient_scope , scope = "openid profile"')], "insufficient_scope"),
            "insufficient_scope",
        )

    def test_rfc6750_parser_preserves_duplicates_and_rejects_ambiguity(self):
        self.assertEqual(wp3_flow.rfc6750_error([
            ("www-authenticate", 'Bearer realm="api", error="invalid_token"'),
        ], "invalid_token"), "invalid_token")
        self.assertEqual(wp3_flow.rfc6750_error([
            ("www-authenticate", 'Bearer error="invalid_token"'),
            ("www-authenticate", 'Bearer error="insufficient_scope"'),
        ]), "malformed")
        for value in (
            'Bearer error="invalid_token", error="insufficient_scope"',
            'Bearer error="invalid_token", ERROR="invalid_token"',
            'Basic realm="api"',
            'Bearer error="invalid_token", Basic realm="api"',
            'Bearer\terror="invalid_token"',
            'Bearer error =',
        ):
            self.assertEqual(wp3_flow.rfc6750_error([("www-authenticate", value)]), "malformed")

    def test_challenge_observation_distinguishes_absent_from_malformed(self):
        self.assertEqual(wp3_flow.challenge_for_status(401, []), "missing_header")
        self.assertEqual(wp3_flow.challenge_for_status(401, [("www-authenticate", "Bearer error=invalid_token")]), "invalid_token")
        self.assertEqual(wp3_flow.challenge_for_status(401, {"WWW-Authenticate": "Bearer error=invalid_token"}), "invalid_token")
        self.assertEqual(wp3_flow.challenge_for_status(401, [("www-authenticate", "Bearer error=unknown")]), "malformed")
        self.assertEqual(wp3_flow.challenge_for_status(401, [("www-authenticate", "Bearer")]), "error_absent")
        self.assertEqual(wp3_flow.challenge_for_status(401, [("www-authenticate", 'Bearer realm="kong"')]), "error_absent")
        self.assertEqual(wp3_flow.challenge_for_status(401, [
            ("www-authenticate", "Bearer"), ("www-authenticate", 'Bearer realm="kong"'),
        ]), "malformed")

    def test_query_matrix_builds_bounded_targets_and_authorized_negative_controls(self):
        rows = wp3_flow.initial_cases()
        requests = []

        def capture_request(*args, **kwargs):
            requests.append((args[2], kwargs))

        route = {
            "grant": {"certificate": Path("route.crt"), "private_key": Path("route.key")},
            "token": "fixture-access-token",
            "claims": {},
        }
        context = {"containers": {"pop-verifier": "capture"}}
        with patch.object(wp3_flow, "check_api_expectation", side_effect=capture_request):
            wp3_flow._run_query_guard_cases(rows, context, route)

        expected = {
            "query_only_token": (1, 401, False),
            "query_encoded_name": (1, 401, True),
            "query_mixed_case_name": (1, 401, True),
            "query_dash_alias": (1, 401, True),
            "query_duplicate_name": (2, 401, True),
            "query_late_name": (999, 401, True),
            "query_arg_limit_1000": (1000, 401, True),
            "query_arg_truncated_1001": (1001, 401, True),
            "harmless_query_control": (1, 200, True),
        }
        self.assertEqual([variant for variant, _kwargs in requests], list(expected))
        for variant, kwargs in requests:
            with self.subTest(variant=variant):
                argument_count, status, authorized = expected[variant]
                self.assertEqual(kwargs["expected_status"], status)
                self.assertEqual(kwargs["path"].count("&") + 1, argument_count)
                self.assertLessEqual(len(kwargs["path"].encode("ascii")), wp3_flow.MAX_REQUEST_TARGET_BYTES)
                auth_headers = [
                    value for name, value in kwargs["headers"]
                    if name.lower() == "authorization"
                ]
                self.assertEqual(len(auth_headers), 1 if authorized else 0)
                if authorized:
                    self.assertEqual(auth_headers[0], "Bearer " + route["token"])

    def test_auth_info_absence_is_preserved_as_needs_design_without_relaxing_contract(self):
        rows = wp3_flow.initial_cases()
        with patch.object(wp3_flow, "capture_request_count", side_effect=[7, 7]), patch.object(
            wp3_flow, "request_api", return_value=(401, [("www-authenticate", 'Bearer realm="kong"')], {})
        ):
            wp3_flow.check_api_expectation(
                rows, "RS-QUERY-01", "query_only_token", {"pki": Path("/unused")}, "capture",
                token="fixture-token", claims={}, cert_path=Path("cert"), key_path=Path("key"),
                expected_status=401, expected_error="invalid_token", headers=[],
                allow_absent_challenge_needs_design=True,
            )
        row = next(row for row in rows if row["case_id"] == "RS-QUERY-01")
        self.assertEqual((row["outcome"], row["http_status"], row["rfc6750_challenge"]), ("needs_design", 401, "error_absent"))

        rows = wp3_flow.initial_cases()
        with patch.object(wp3_flow, "capture_request_count", side_effect=[7, 7]), patch.object(
            wp3_flow, "request_api", return_value=(401, [], {})
        ):
            with self.assertRaisesRegex(wp3_flow.FlowError, "did not match"):
                wp3_flow.check_api_expectation(
                    rows, "RS-QUERY-01", "query_only_token", {"pki": Path("/unused")}, "capture",
                    token="fixture-token", claims={}, cert_path=Path("cert"), key_path=Path("key"),
                    expected_status=401, expected_error="invalid_token", headers=[],
                    allow_absent_challenge_needs_design=True,
                )
        row = next(row for row in rows if row["case_id"] == "RS-QUERY-01")
        self.assertEqual((row["outcome"], row["http_status"], row["rfc6750_challenge"]), ("fail", 401, "missing_header"))

    def test_schema_probe_emits_only_allowlisted_runtime_metadata(self):
        plugin_root = {
            "version": "3.16.0.0",
            "plugins": {"available_on_server": {
                name: {"priority": priority, "version": "3.16.0.0" if name == "openid-connect" else "3.16.0", "secret": "MUST-NOT-ESCAPE"}
                for name, priority in wp3_flow.ADMIN_PLUGIN_NAMES.items()
            }},
            "configuration": {"secret": "MUST-NOT-ESCAPE"},
        }
        schema_docs = {}
        for plugin, names in wp3_flow.ADMIN_FIELD_ALLOWLIST.items():
            fields = []
            for name in names:
                kind = "string" if name in {"tls_client_certificate", "client_cert_header_name"} else "boolean"
                node = {"type": kind}
                if name == "tls_client_certificate":
                    node["enum"] = ["REQUEST", "FORBIDDEN-ENUM"]
                fields.append({name: node})
                if plugin == "openid-connect" and name == "issuer":
                    fields.append({"unrelated_record": {
                        "type": "record",
                        "fields": [
                            {"issuer": {"type": "string"}},
                            {"nested_record": {"type": "record", "fields": [{"issuer": {"type": "string"}}]}},
                        ],
                    }})
            schema_docs[plugin] = {"fields": [{"config": {"type": "record", "fields": fields}}]}

        def run(args, **_kwargs):
            if args[:3] == ["docker", "exec", "container"] and args[3:] == ["/bin/sh", "-c", 'test "$KONG_ADMIN_LISTEN" = "127.0.0.1:8001" && test "$KONG_ADMIN_GUI_LISTEN" = "off"']:
                return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
            if args[:4] == ["docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}"]:
                return subprocess.CompletedProcess(args, 0, stdout=b'{"8443/tcp":[{"HostIp":"127.0.0.1"}]}', stderr=b"")
            if args[:4] == ["docker", "exec", "container", wp3_flow.RESTY_EXECUTABLE] and args[4] == "-e":
                script = args[5]
                if script == wp3_flow.RESTY_HTTP_PREFLIGHT_LUA:
                    return subprocess.CompletedProcess(args, 0, stdout=b"WP3_RESTY_HTTP_READY", stderr=b"")
                matching_path = next(
                    path for path in ["/"] + ["/schemas/plugins/" + plugin for plugin in schema_docs]
                    if f"path = {json.dumps(path)}" in script
                )
                body = plugin_root if matching_path == "/" else schema_docs[matching_path.rsplit("/", 1)[-1]]
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(body).encode(), stderr=b"")
            raise AssertionError("unexpected subprocess in Admin metadata probe")

        diagnostic = {"stage": "not_started", "reason": "not_started", "plugin": "none"}
        with patch.object(wp3_flow.subprocess, "run", side_effect=run):
            output = wp3_flow.probe_loaded_schema_priorities("container", diagnostic)
        self.assertEqual(output["gateway_version"], "3.16.0.0")
        self.assertEqual(output["plugins"]["openid-connect"]["priority"], 1050)
        self.assertEqual(output["fields"]["tls-handshake-modifier"]["tls_client_certificate"]["enum"], ["REQUEST"])
        self.assertEqual(output["tls_policy"], {
            "metadata_source": "admin_root_configuration", "cipher_suite": "not_proven", "protocols": [],
        })
        self.assertNotIn("MUST-NOT-ESCAPE", json.dumps(output))
        self.assertEqual(set(output), {"gateway_version", "plugins", "fields", "admin_host_published", "tls_policy"})
        self.assertEqual(diagnostic, {"stage": "complete", "reason": "none", "plugin": "none"})

    def test_schema_field_observations_ignore_nested_names_but_reject_direct_duplicates(self):
        wanted = {"issuer"}
        valid_with_unrelated_nested_fields = {
            "fields": [{"config": {"type": "record", "fields": [
                {"issuer": {"type": "string"}},
                {"other": {"type": "record", "fields": [{"issuer": {"type": "string"}}]}},
            ]}}]
        }
        observed = wp3_flow._schema_field_observations(valid_with_unrelated_nested_fields, wanted)
        self.assertEqual(observed["issuer"], [{"type": "string", "enum": []}])

        duplicate_direct_fields = {
            "fields": [{"config": {"type": "record", "fields": [
                {"issuer": {"type": "string"}},
                {"issuer": {"type": "string"}},
            ]}}]
        }
        observed = wp3_flow._schema_field_observations(duplicate_direct_fields, wanted)
        self.assertEqual(len(observed["issuer"]), 2)

        duplicate_config_records = {
            "fields": [
                {"config": {"type": "record", "fields": [{"issuer": {"type": "string"}}]}},
                {"config": {"type": "record", "fields": []}},
            ]
        }
        observed = wp3_flow._schema_field_observations(duplicate_config_records, wanted)
        self.assertEqual(observed["issuer"], [])

    def test_tls_policy_metadata_requires_exact_modern_and_tls13_only_values(self):
        self.assertEqual(wp3_flow.extract_tls_policy_metadata({
            "ssl_cipher_suite": "modern", "ssl_protocols": ["TLSv1.3"],
            "unrelated_secret": "MUST-NOT-ESCAPE",
        }), {
            "metadata_source": "admin_root_configuration", "cipher_suite": "modern", "protocols": ["TLSv1.3"],
        })
        self.assertEqual(wp3_flow.extract_tls_policy_metadata({
            "ssl_cipher_suite": "modern", "ssl_protocols": "TLSv1.3",
        })["protocols"], ["TLSv1.3"])
        for configuration in (
            {"ssl_cipher_suite": "custom", "ssl_protocols": ["TLSv1.3"]},
            {"ssl_cipher_suite": "modern", "ssl_protocols": ["TLSv1.2", "TLSv1.3"]},
            {"ssl_cipher_suite": "modern", "ssl_protocols": {"TLSv1.3": True}},
            None,
        ):
            metadata = wp3_flow.extract_tls_policy_metadata(configuration)
            self.assertTrue(metadata["cipher_suite"] == "not_proven" or not metadata["protocols"])
            self.assertNotIn("MUST-NOT-ESCAPE", json.dumps(metadata))

    def test_schema_probe_rejects_duplicate_direct_config_issuer(self):
        root = {
            "version": "3.16.0.0",
            "plugins": {"available_on_server": {
                name: {"priority": priority, "version": "3.16.0"}
                for name, priority in wp3_flow.ADMIN_PLUGIN_NAMES.items()
            }},
        }
        schema_fields = []
        for field in wp3_flow.ADMIN_FIELD_ALLOWLIST["openid-connect"]:
            node = {"type": "string" if field == "issuer" else "boolean"}
            if field == "proof_of_possession_mtls":
                node["enum"] = ["strict"]
            schema_fields.append({field: node})
        schema_fields.extend([
            {"issuer": {"type": "string"}},
            {"nested": {"type": "record", "fields": [{"issuer": {"type": "string"}}]}},
        ])
        schema = {"fields": [{"config": {"type": "record", "fields": schema_fields}}]}
        responses = [root, schema]
        diagnostic = {"stage": "not_started", "reason": "not_started", "plugin": "none"}
        with patch.object(wp3_flow, "assert_fixture_admin_isolation"), patch.object(
            wp3_flow, "_admin_client_preflight"
        ), patch.object(wp3_flow, "_admin_json", side_effect=responses):
            with self.assertRaisesRegex(wp3_flow.FlowError, "omitted or duplicated"):
                wp3_flow.probe_loaded_schema_priorities("container", diagnostic)
        self.assertEqual(diagnostic, {
            "stage": "plugin_schema", "reason": "plugin_schema_fields_incomplete", "plugin": "openid-connect",
        })

    def test_schema_probe_rejects_single_malformed_direct_field(self):
        root = {
            "version": "3.16.0.0",
            "plugins": {"available_on_server": {
                name: {"priority": priority, "version": "3.16.0"}
                for name, priority in wp3_flow.ADMIN_PLUGIN_NAMES.items()
            }},
        }
        schema_fields = []
        for field in wp3_flow.ADMIN_FIELD_ALLOWLIST["openid-connect"]:
            descriptor = "malformed" if field == "issuer" else {"type": "boolean"}
            schema_fields.append({field: descriptor})
        schema = {"fields": [{"config": {"type": "record", "fields": schema_fields}}]}
        diagnostic = {"stage": "not_started", "reason": "not_started", "plugin": "none"}
        with patch.object(wp3_flow, "assert_fixture_admin_isolation"), patch.object(
            wp3_flow, "_admin_client_preflight"
        ), patch.object(wp3_flow, "_admin_json", side_effect=[root, schema]):
            with self.assertRaisesRegex(wp3_flow.FlowError, "omitted or duplicated"):
                wp3_flow.probe_loaded_schema_priorities("container", diagnostic)
        self.assertEqual(diagnostic, {
            "stage": "plugin_schema", "reason": "plugin_schema_fields_incomplete", "plugin": "openid-connect",
        })

    def test_admin_metadata_uses_bounded_resty_get_without_curl(self):
        payload = {"version": "3.16.0.0"}
        output = json.dumps(payload).encode()
        with patch.object(
            wp3_flow.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=output, stderr=b""),
        ) as run:
            self.assertEqual(wp3_flow._admin_json("container", "/"), payload)
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["docker", "exec", "container", wp3_flow.RESTY_EXECUTABLE, "-e"])
        self.assertIn("set_timeouts(2000, 2000, 3000)", command[-1])
        self.assertIn('method = "GET"', command[-1])
        self.assertIn("response.body_reader(8192)", command[-1])
        self.assertIn(str(wp3_flow.MAX_ADMIN_RESPONSE_BYTES), command[-1])
        self.assertNotIn("curl", command[-1])

    def test_admin_metadata_fixed_diagnostic_categorizes_missing_resty_binary(self):
        outputs = [
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b'{"8443/tcp":[]}', stderr=b""),
            subprocess.CompletedProcess([], 127, stdout=b"PRIVATE-DETAIL", stderr=b"PRIVATE-ERROR"),
        ]
        diagnostic = {"stage": "not_started", "reason": "not_started", "plugin": "none"}
        with patch.object(wp3_flow.subprocess, "run", side_effect=outputs):
            with self.assertRaisesRegex(wp3_flow.FlowError, "HTTP client preflight failed"):
                wp3_flow.probe_loaded_schema_priorities("container", diagnostic)
        self.assertEqual(diagnostic, {
            "stage": "resty_client_preflight", "reason": "resty_binary_missing", "plugin": "none",
        })
        self.assertNotIn("PRIVATE", str(diagnostic))

    def test_admin_metadata_rejects_redirect_and_oversized_body(self):
        for code, expected in ((73, "admin_redirect_rejected"), (76, "admin_body_too_large")):
            with self.subTest(code=code):
                with patch.object(
                    wp3_flow,
                    "_run_resty",
                    return_value=subprocess.CompletedProcess([], code, stdout=b"PRIVATE-DETAIL", stderr=b"PRIVATE-ERROR"),
                ):
                    with self.assertRaises(wp3_flow.AdminProbeError) as raised:
                        wp3_flow._admin_json("container", "/")
                self.assertEqual(raised.exception.category, expected)
                self.assertNotIn("PRIVATE", str(raised.exception))

    @staticmethod
    def rendered_runtime_state():
        tags = ["fapi2-demo", "api"]
        state_source = (ROOT / "kong/api-gateway.yaml").read_text(encoding="utf-8")
        rendered_source = wp3_flow.re.sub(
            r'\$\{\{\s*env\s+"([A-Z0-9_]+)"\s*\}\}',
            lambda match: f"deck-template:{match.group(1)}",
            state_source,
        )
        api_state = wp3_flow.yaml.safe_load(rendered_source)
        pre_function_source = next(
            plugin["config"]["access"][0]
            for plugin in api_state["plugins"]
            if plugin.get("name") == "pre-function"
        )
        return {
            "services": [{
                "name": "fapi-api-resource-server", "tags": tags,
                "protocol": "https", "host": "pop-verifier", "port": 9443, "path": "/evidence",
                "tls_verify": True, "client_certificate": "55555555-5555-4555-8555-555555555555",
                "ca_certificates": ["33333333-3333-4333-8333-333333333333"],
                "routes": [{
                    "name": "fapi-api-resource-server-route", "tags": tags,
                    "paths": [wp3_flow.API_PATH], "protocols": ["https"],
                    "snis": ["kong-api", "localhost"], "strip_path": True,
                    "plugins": [
                        {"name": "pre-function", "tags": tags, "config": {"access": [pre_function_source]}},
                        {"name": "openid-connect", "tags": tags, "config": {
                            "issuer": "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration",
                            "introspection_endpoint": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token/introspect",
                            "mtls_introspection_endpoint": "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token/introspect",
                            "client_id": ["api-gateway-introspection"], "client_auth": ["tls_client_auth"],
                            "auth_methods": ["introspection"], "introspection_endpoint_auth_method": "tls_client_auth",
                            "tls_client_auth_cert_id": "44444444-4444-4444-8444-444444444444",
                            "ssl_verify": True, "tls_client_auth_ssl_verify": True,
                            "introspection_check_active": True, "cache_introspection": False, "cache_tokens": False,
                            "bearer_token_param_type": ["header"], "audience_required": ["fapi-demo-api"],
                            "scopes_required": ["openid"], "issuers_allowed": [wp3_flow.PUBLIC_ISSUER],
                            "upstream_access_token_header": "authorization:bearer",
                        }},
                        {"name": "tls-handshake-modifier", "tags": tags, "config": {"tls_client_certificate": "REQUEST"}},
                        {"name": "tls-metadata-headers", "tags": tags, "config": {
                            "inject_client_cert_details": True, "client_cert_header_name": "X-Client-Cert",
                        }},
                    ],
                }],
            }],
        }

    def test_state_contract_accepts_exact_deck_rendered_route_plugins(self):
        state = self.rendered_runtime_state()
        with TemporaryDirectory() as directory:
            state_path = Path(directory) / "api-runtime.yml"
            state_path.write_text(wp3_flow.yaml.safe_dump(state))
            with patch.object(wp3_flow, "PREVIEW", Path(directory)):
                contract = wp3_flow.validate_runtime_state_contract()
            self.assertTrue(all(contract.values()))
            self.assertTrue(contract["route_plugin_inventory_exact"])
            self.assertTrue(contract["query_auth_guard_bound"])
            state["services"][0]["routes"][0]["plugins"][1]["config"]["cache_tokens"] = True
            state_path.write_text(wp3_flow.yaml.safe_dump(state))
            with patch.object(wp3_flow, "PREVIEW", Path(directory)):
                with self.assertRaisesRegex(wp3_flow.FlowError, "violated"):
                    wp3_flow.validate_runtime_state_contract()

        broken_state = self.rendered_runtime_state()
        broken_state["services"][0]["routes"][0]["plugins"][0]["config"]["access"] = ["return"]
        with TemporaryDirectory() as directory:
            (Path(directory) / "api-runtime.yml").write_text(wp3_flow.yaml.safe_dump(broken_state))
            with patch.object(wp3_flow, "PREVIEW", Path(directory)):
                with self.assertRaisesRegex(wp3_flow.FlowError, "violated"):
                    wp3_flow.validate_runtime_state_contract()

    def test_state_contract_rejects_extra_service_and_conflicting_plugin_scope(self):
        state = self.rendered_runtime_state()
        mutations = []
        extra_service = json.loads(json.dumps(state))
        extra_service["services"].append({"name": "foreign-service", "tags": ["fapi2-demo"]})
        mutations.append(extra_service)
        conflict_service = json.loads(json.dumps(state))
        conflict_service["services"][0]["routes"][0]["plugins"][0]["service"] = "foreign-service"
        mutations.append(conflict_service)
        conflict_consumer = json.loads(json.dumps(state))
        conflict_consumer["services"][0]["routes"][0]["plugins"][0]["consumer"] = {"username": "foreign"}
        mutations.append(conflict_consumer)
        conflict_route = json.loads(json.dumps(state))
        conflict_route["services"][0]["routes"][0]["service"] = "foreign-service"
        mutations.append(conflict_route)
        conflict_plugin_route = json.loads(json.dumps(state))
        conflict_plugin_route["services"][0]["routes"][0]["plugins"][0]["route"] = "foreign-route"
        mutations.append(conflict_plugin_route)
        for state in mutations:
            with self.subTest(mutation=state):
                with TemporaryDirectory() as directory:
                    (Path(directory) / "api-runtime.yml").write_text(wp3_flow.yaml.safe_dump(state))
                    with patch.object(wp3_flow, "PREVIEW", Path(directory)):
                        with self.assertRaises(wp3_flow.FlowError):
                            wp3_flow.validate_runtime_state_contract()

    def test_positive_preflight_preserves_rendered_contract_failure_phase(self):
        execution = {
            "phase": "preflight", "host_runtime": None,
        }
        valid_runtime = {
            "python_version": "3.11.0", "pyjwt_version": "2.14.0", "pyjwt_importable": True,
            "cryptography_version": "50.0.2", "cryptography_importable": True,
        }
        with patch.object(wp3_flow, "host_crypto_diagnostics", return_value=valid_runtime), patch.dict(
            wp3_flow.os.environ, {"KONG_LICENSE_DATA": "fixture-license-presence-only"}
        ), patch.object(wp3_flow, "verify_preparation_receipt", return_value={"images": {}}), patch.object(
            wp3_flow, "validate_runtime_state_contract", side_effect=wp3_flow.FlowError("contract rejected")
        ), patch.object(wp3_flow, "verify_running_project") as running_project:
            with self.assertRaisesRegex(wp3_flow.FlowError, "contract rejected"):
                wp3_flow.run_positive_flows([], {}, {}, [], execution)
        self.assertEqual(execution["phase"], "rendered_state_contract_validation")
        running_project.assert_not_called()

    def test_main_retains_failed_phase_and_does_not_claim_startup_only_leak_pass(self):
        saved = {}

        def fail_at_contract(_cases, _capture, _tls, _sensitive, execution):
            execution["phase"] = "rendered_state_contract_validation"
            raise wp3_flow.FlowError("contract rejected")

        clean_scan = {
            "passed": True, "completed": True, "failure_reason": "none",
            "candidate_value_count": 0, "checked_value_count": 0, "secret_value_match_count": 0,
            "source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "matched_source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "credential_pattern_match_count": 0, "credential_pattern_matches": [],
            "public_fixture_identifier_observation_count": 0,
            "public_fixed_protocol_constant_observation_count": 0,
        }
        api_scan = {
            "api_response_completed": True, "api_response_failure_reason": "none",
            "api_response_count": 0, "api_response_scanned_byte_count": 0,
            "api_response_secret_value_match_count": 0,
            "api_response_secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "api_response_credential_pattern_matches": [],
        }
        clean_scan.update(api_scan)
        clean_scan["service_scans"] = clean_service_scan_receipt()
        from contextlib import redirect_stdout

        with patch.object(wp3_flow.sys, "argv", ["wp3_flow.py", "--allow-run-wp3-api-probes"]), patch.object(
            wp3_flow, "verify_owned_project_containers", return_value=False
        ), patch.object(wp3_flow, "collect_fixture_sensitive_values", return_value=[]), patch.object(
            wp3_flow, "run_positive_flows", side_effect=fail_at_contract
        ), patch.object(wp3_flow, "verify_preparation_receipt", return_value={"images": {}}), patch.object(
            wp3_flow, "scan_logs_for_sensitive_values", return_value=clean_scan
        ), patch.object(wp3_flow, "api_response_scan_receipt", return_value=api_scan), patch.object(
            wp3_flow, "write_runtime_receipt", side_effect=lambda payload: saved.setdefault("payload", payload)
        ), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
            result = wp3_flow.main()
        self.assertEqual(result, 1)
        payload = saved["payload"]
        execution = payload["cases"]["execution"]
        self.assertEqual(execution["phase"], "rendered_state_contract_validation")
        leak = next(row for row in payload["cases"]["acceptance"] if row["case_id"] == "LEAK-01")
        self.assertEqual(leak["outcome"], "not_run")
        self.assertEqual(leak["phase"], "startup_logs_only_no_api_traffic")
        self.assertEqual(payload["log_scan"]["api_response_count"], 0)

    def test_main_persists_header_capture_failure_with_fixed_phase_and_preserves_matrix_stage(self):
        image_contract = {
            name: {"digest": digest, "architecture": "arm64"}
            for name, (_reference, digest) in wp3_flow.IMAGES.items()
        }
        clean_scan = {
            "passed": True, "completed": True, "failure_reason": "none",
            "candidate_value_count": 0, "checked_value_count": 0, "secret_value_match_count": 0,
            "source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "matched_source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "credential_pattern_match_count": 0, "credential_pattern_matches": [],
            "public_fixture_identifier_observation_count": 0,
            "public_fixed_protocol_constant_observation_count": 0,
        }
        api_scan = {
            "api_response_completed": True, "api_response_failure_reason": "none",
            "api_response_count": 0, "api_response_scanned_byte_count": 0,
            "api_response_secret_value_match_count": 0,
            "api_response_secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "api_response_credential_pattern_matches": [],
        }
        clean_scan.update(api_scan)
        clean_scan["service_scans"] = clean_service_scan_receipt()

        def fail_header_capture(cases, _context, execution):
            wp3_flow.mark_variant_case(
                cases, "HEADER-CERT-01", "spoof_alias_duplicates", "fail",
                "upstream_capture_evidence", "upstream_capture", 200,
            )
            execution["negative_group_failures"] = ["header_boundary"]
            execution["phase"] = "negative_matrix_complete"
            return {"completed": False, "failed_groups": ["header_boundary"]}

        with TemporaryDirectory() as directory:
            preview = Path(directory)
            evidence = preview / "evidence"
            evidence.mkdir(mode=0o700)
            evidence.chmod(0o700)
            with patch.object(wp3_flow, "PREVIEW", preview), patch.object(
                wp3_flow.sys, "argv", ["wp3_flow.py", "--allow-run-wp3-api-probes"]
            ), patch.object(wp3_flow, "verify_owned_project_containers", return_value=False), patch.object(
                wp3_flow, "collect_fixture_sensitive_values", return_value=[]
            ), patch.object(wp3_flow, "run_positive_flows", return_value={"images": image_contract}), patch.object(
                wp3_flow, "run_negative_matrix", side_effect=fail_header_capture
            ), patch.object(wp3_flow, "scan_logs_for_sensitive_values", return_value=clean_scan), patch.object(
                wp3_flow, "api_response_scan_receipt", return_value=api_scan
            ), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
                result = wp3_flow.main()

            self.assertEqual(result, 1)
            receipt_path = evidence / "wp3-runtime-receipt.json"
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
            payload = json.loads(receipt_path.read_text())
            wp3_prepare.validate_runtime_receipt(payload)
            execution = payload["cases"]["execution"]
            self.assertEqual(execution["phase"], "negative_header_boundary")
            self.assertEqual(execution["negative_group_failures"], ["header_boundary"])
            header_case = next(
                row for row in payload["cases"]["acceptance"]
                if row["case_id"] == "HEADER-CERT-01" and row["variant"] == "spoof_alias_duplicates"
            )
            self.assertEqual(header_case["outcome"], "fail")
            self.assertEqual(header_case["phase"], "upstream_capture_evidence")
            self.assertEqual(payload["cases"]["full_wp3_acceptance"], "fail")
            leak = next(row for row in payload["cases"]["acceptance"] if row["case_id"] == "LEAK-01")
            self.assertEqual(leak["outcome"], "not_run")

    def test_acceptance_recorders_reject_unknown_phase_before_mutating_rows(self):
        rows = wp3_flow.initial_cases()
        with self.assertRaisesRegex(wp3_flow.FlowError, "unknown safe outcome, layer, or fixed phase"):
            wp3_flow.mark_variant_case(
                rows, "HEADER-CERT-01", "headers_101", "fail",
                "upstream_capture_secretvalue", "upstream_capture",
            )
        with self.assertRaisesRegex(wp3_flow.FlowError, "unknown fixed phase"):
            wp3_flow.mark_route_case(rows, "RS-VALID-01", "A", "fail", "secretvalue", "harness")
        self.assertTrue(all(row["outcome"] == "not_run" for row in rows))

    def test_literal_acceptance_phase_producers_are_in_the_fixed_receipt_enum(self):
        source = ast.parse((ROOT / "tests/harness/wp3_flow.py").read_text())
        produced = set()
        for node in ast.walk(source):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in {"mark_route_case", "mark_variant_case"} or len(node.args) < 5:
                continue
            phase = node.args[4]
            if isinstance(phase, ast.Constant) and isinstance(phase.value, str):
                produced.add(phase.value)
        self.assertTrue(produced)
        self.assertEqual(produced - wp3_prepare.WP3_CASE_PHASES, set())

    def test_main_emits_only_fixed_phase_and_receipt_rejection_diagnostic(self):
        image_contract = {
            name: {"digest": digest, "architecture": "arm64"}
            for name, (_reference, digest) in wp3_flow.IMAGES.items()
        }
        clean_scan = {
            "passed": True, "completed": True, "failure_reason": "none",
            "candidate_value_count": 0, "checked_value_count": 0, "secret_value_match_count": 0,
            "source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "matched_source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "credential_pattern_match_count": 0, "credential_pattern_matches": [],
            "public_fixture_identifier_observation_count": 0,
            "public_fixed_protocol_constant_observation_count": 0,
        }
        api_scan = {
            "api_response_completed": True, "api_response_failure_reason": "none",
            "api_response_count": 0, "api_response_scanned_byte_count": 0,
            "api_response_secret_value_match_count": 0,
            "api_response_secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "api_response_credential_pattern_matches": [],
        }
        clean_scan.update(api_scan)
        clean_scan["service_scans"] = clean_service_scan_receipt()

        def fail_at_tls_probe(_cases, _capture, _tls, _sensitive, execution):
            execution["phase"] = "tls_client_certificate_request_sni_probe"
            raise wp3_flow.FlowError("DETAIL-SENTINEL-MUST-NOT-PRINT")

        with TemporaryDirectory() as directory:
            preview = Path(directory)
            evidence = preview / "evidence"
            evidence.mkdir(mode=0o700)
            evidence.chmod(0o700)
            stderr = io.StringIO()
            with patch.object(wp3_flow, "PREVIEW", preview), patch.object(
                wp3_flow.sys, "argv", ["wp3_flow.py", "--allow-run-wp3-api-probes"]
            ), patch.object(wp3_flow, "verify_owned_project_containers", return_value=False), patch.object(
                wp3_flow, "collect_fixture_sensitive_values", return_value=[]
            ), patch.object(wp3_flow, "run_positive_flows", side_effect=fail_at_tls_probe), patch.object(
                wp3_flow, "verify_preparation_receipt", return_value={"images": image_contract}
            ), patch.object(wp3_flow, "scan_logs_for_sensitive_values", return_value=clean_scan), patch.object(
                wp3_flow, "api_response_scan_receipt", return_value=api_scan
            ), patch.object(
                wp3_flow, "validate_runtime_receipt",
                side_effect=wp3_prepare.PreviewError("SCHEMA-DETAIL-SENTINEL-MUST-NOT-PRINT"),
            ), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", stderr):
                result = wp3_flow.main()

            self.assertEqual(result, 1)
            self.assertFalse((evidence / "wp3-runtime-receipt.json").exists())
            diagnostic = stderr.getvalue()
            self.assertIn(
                "WP3_RUNTIME_FAILURE phase=tls_client_certificate_request_sni_probe reason=probe_failed",
                diagnostic,
            )
            self.assertIn(
                "WP3_RUNTIME_RECEIPT_FAILURE phase=tls_client_certificate_request_sni_probe reason=schema_rejected",
                diagnostic,
            )
            self.assertNotIn("DETAIL-SENTINEL", diagnostic)
            self.assertNotIn("SCHEMA-DETAIL", diagnostic)

    def test_main_preserves_log_scan_failure_phase_in_strict_receipts(self):
        image_contract = {
            name: {"digest": digest, "architecture": "arm64"}
            for name, (_reference, digest) in wp3_flow.IMAGES.items()
        }
        api_scan = {
            "api_response_completed": True, "api_response_failure_reason": "none",
            "api_response_count": 0, "api_response_scanned_byte_count": 0,
            "api_response_secret_value_match_count": 0,
            "api_response_secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "api_response_credential_pattern_matches": [],
        }

        def clean_matrix(_cases, _context, execution):
            execution["phase"] = "negative_matrix_complete"
            return {"completed": True, "failed_groups": []}

        for mode in ("matched_secret", "scan_exception"):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                preview = Path(directory)
                evidence = preview / "evidence"
                evidence.mkdir(mode=0o700)
                evidence.chmod(0o700)
                if mode == "matched_secret":
                    scan = {
                        "passed": False, "completed": True, "failure_reason": "none",
                        "candidate_value_count": 1, "checked_value_count": 1, "secret_value_match_count": 1,
                        "source_category_counts": {name: int(name == "oauth_token") for name in wp3_flow.LOG_VALUE_CATEGORIES},
                        "matched_source_category_counts": {name: int(name == "oauth_token") for name in wp3_flow.LOG_VALUE_CATEGORIES},
                        "secret_match_category_counts": {name: int(name == "oauth_token") for name in wp3_flow.LOG_VALUE_CATEGORIES},
                        "credential_pattern_match_count": 0, "credential_pattern_matches": [],
                        "public_fixture_identifier_observation_count": 0,
                        "public_fixed_protocol_constant_observation_count": 0,
                    }
                    scan.update(api_scan)
                    scan["service_scans"] = clean_service_scan_receipt(1)
                    matched_service = scan["service_scans"]["keycloak"]
                    matched_service["passed"] = False
                    matched_service["matched_source_category_counts"]["oauth_token"] = 1
                    matched_service["secret_match_category_counts"]["oauth_token"] = 1
                    matched_service["matched_candidate_provenance"] = [{
                        "category": "oauth_token", "source": "explicit_candidate_input",
                        "field": "unkeyed_value", "matched_value_count": 1,
                    }]
                    matched_service["matched_log_context_counts"]["unclassified_log_context"] = 1
                    scanner = patch.object(wp3_flow, "scan_logs_for_sensitive_values", return_value=scan)
                    expected_leak_outcome = "fail"
                else:
                    scan = None
                    scanner = patch.object(
                        wp3_flow, "scan_logs_for_sensitive_values",
                        side_effect=wp3_flow.LogScanError("log_read_failed"),
                    )
                    expected_leak_outcome = "needs_design"

                with patch.object(wp3_flow, "PREVIEW", preview), patch.object(
                    wp3_flow.sys, "argv", ["wp3_flow.py", "--allow-run-wp3-api-probes"]
                ), patch.object(wp3_flow, "verify_owned_project_containers", return_value=False), patch.object(
                    wp3_flow, "collect_fixture_sensitive_values", return_value=[]
                ), patch.object(wp3_flow, "run_positive_flows", return_value={"images": image_contract}), patch.object(
                    wp3_flow, "run_negative_matrix", side_effect=clean_matrix
                ), scanner, patch.object(
                    wp3_flow, "api_response_scan_receipt", return_value=api_scan
                ), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
                    result = wp3_flow.main()

                self.assertEqual(result, 1)
                payload = json.loads((evidence / "wp3-runtime-receipt.json").read_text())
                wp3_prepare.validate_runtime_receipt(payload)
                self.assertEqual(payload["cases"]["execution"]["phase"], "whole_runtime_log_scan")
                leak = next(row for row in payload["cases"]["acceptance"] if row["case_id"] == "LEAK-01")
                self.assertEqual(leak["outcome"], expected_leak_outcome)
                self.assertEqual(leak["phase"], "whole_runtime_log_scan")

    def test_route_failure_phases_are_receipt_allowlisted_for_both_routes(self):
        clean_scan = {
            "passed": True, "completed": True, "failure_reason": "none",
            "candidate_value_count": 0, "checked_value_count": 0, "secret_value_match_count": 0,
            "source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "matched_source_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "credential_pattern_match_count": 0, "credential_pattern_matches": [],
            "public_fixture_identifier_observation_count": 0,
            "public_fixed_protocol_constant_observation_count": 0,
        }
        api_scan = {
            "api_response_completed": True, "api_response_failure_reason": "none",
            "api_response_count": 0, "api_response_scanned_byte_count": 0,
            "api_response_secret_value_match_count": 0,
            "api_response_secret_match_category_counts": {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES},
            "api_response_credential_pattern_matches": [],
        }
        clean_scan.update(api_scan)
        clean_scan["service_scans"] = clean_service_scan_receipt()
        image_contract = {
            name: {"digest": digest, "architecture": "arm64"}
            for name, (_reference, digest) in wp3_flow.IMAGES.items()
        }
        for route in ("A", "B"):
            for route_phase in wp3_flow.ROUTE_EXECUTION_PHASES:
                with self.subTest(route=route, route_phase=route_phase):
                    saved = {}
                    execution_phase = f"route_{route}_{route_phase}"

                    def fail_at_route_phase(_cases, _capture, _tls, _sensitive, execution):
                        execution["phase"] = execution_phase
                        raise wp3_flow.FlowError("route probe failed")

                    with patch.object(wp3_flow.sys, "argv", ["wp3_flow.py", "--allow-run-wp3-api-probes"]), patch.object(
                        wp3_flow, "verify_owned_project_containers", return_value=False
                    ), patch.object(wp3_flow, "collect_fixture_sensitive_values", return_value=[]), patch.object(
                        wp3_flow, "run_positive_flows", side_effect=fail_at_route_phase
                    ), patch.object(wp3_flow, "verify_preparation_receipt", return_value={"images": image_contract}), patch.object(
                        wp3_flow, "scan_logs_for_sensitive_values", return_value=clean_scan
                    ), patch.object(wp3_flow, "api_response_scan_receipt", return_value=api_scan), patch.object(
                        wp3_flow, "write_runtime_receipt", side_effect=lambda payload: saved.setdefault("payload", payload)
                    ), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
                        result = wp3_flow.main()

                    self.assertEqual(result, 1)
                    payload = saved["payload"]
                    wp3_prepare.validate_runtime_receipt(payload)
                    self.assertEqual(payload["cases"]["execution"]["phase"], execution_phase)
                    leak = next(row for row in payload["cases"]["acceptance"] if row["case_id"] == "LEAK-01")
                    self.assertEqual(leak["outcome"], "not_run")

        invalid = {"route_C_authorization", "route_A_unclassified", "route_B_secretvalue"}
        for phase in invalid:
            with self.subTest(invalid_phase=phase):
                payload = {
                    "schema_version": 1, "scope": "wp3-api-runtime-isolated-validation", "result": "fail",
                    "host_ports": {"keycloak": 18444, "api_gateway": 18443, "oauth_callback": 8443},
                    "images": image_contract,
                    "cases": {
                        "scope": "wp3_positive_and_required_negative_matrix",
                        "execution": {
                            "scope": "wp3_positive_and_required_negative_matrix", "outcome": "fail",
                            "phase": phase, "layer": "harness_or_transport", "http_status": None,
                            "host_runtime": None, "schema_probe": None,
                            "schema_probe_diagnostic": {"stage": "not_started", "reason": "not_started", "plugin": "none"},
                            "state_contract": None,
                            "header_parser_metadata": None,
                            "effective_inbound_tls_policy": None,
                            "negative_group_failures": [],
                        },
                        "acceptance": [{
                            "case_id": "LEAK-01", "variant": "whole_runtime_lifecycle", "outcome": "not_run",
                            "phase": "startup_logs_only_no_api_traffic", "layer": "harness", "http_status": None,
                            "rfc6750_challenge": "not_applicable",
                        }],
                        "full_wp3_acceptance": "fail",
                    },
                    "tls": {name: "not_run" for name in (
                        "localhost_sni_positive", "kong_api_sni_positive",
                        "localhost_sni_requested_client_certificate", "kong_api_sni_requested_client_certificate",
                        "no_client_certificate_handshake_rejected", "tls_11_rejected", "tls_12_only_rejected", "weak_cipher_rejected",
                        "untrusted_server_certificate_rejected", "san_mismatch_rejected",
                    )},
                    "capture": {}, "log_scan": {}, "containers_started": False,
                    "konnect_read_or_write_performed": False,
                }
                with self.assertRaisesRegex(wp3_prepare.PreviewError, "phase metadata"):
                    wp3_prepare.validate_runtime_receipt(payload)

    def test_admin_probe_rejects_host_published_loopback_listener(self):
        outputs = [
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b'{"8001/tcp":[{"HostIp":"0.0.0.0"}]}', stderr=b""),
        ]
        with patch.object(wp3_flow.subprocess, "run", side_effect=outputs):
            with self.assertRaisesRegex(wp3_flow.FlowError, "unexpectedly published"):
                wp3_flow.assert_fixture_admin_isolation("container")

    def test_capture_counter_is_container_loopback_only_and_strictly_parsed(self):
        with patch.object(
            wp3_flow.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=b'{"request_count":7}\n', stderr=b""),
        ) as run:
            self.assertEqual(wp3_flow.capture_request_count("capture-id"), 7)
        self.assertEqual(run.call_args.args[0][2:4], ["capture-id", "python"])
        with patch.object(
            wp3_flow.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=b'{"request_count":7,"token":"bad"}', stderr=b""),
        ):
            with self.assertRaisesRegex(wp3_flow.FlowError, "strict one-field schema"):
                wp3_flow.capture_request_count("capture-id")

    def test_runtime_receipt_strictly_whitelists_nested_case_capture_and_log_shapes(self):
        categories = {name: 0 for name in wp3_flow.LOG_VALUE_CATEGORIES}
        receipt = {
            "schema_version": 1,
            "scope": "wp3-api-runtime-isolated-validation",
            "result": "partial",
            "host_ports": {"keycloak": 18444, "api_gateway": 18443, "oauth_callback": 8443},
            "images": {name: {"digest": digest, "architecture": "arm64"} for name, (_reference, digest) in wp3_flow.IMAGES.items()},
            "cases": {
                "scope": "wp3_positive_and_required_negative_matrix",
                "execution": {
                    "scope": "wp3_positive_and_required_negative_matrix", "outcome": "partial",
                    "phase": "runtime_complete", "layer": "isolated_runtime_partial", "http_status": None,
                    "host_runtime": None, "schema_probe": None,
                    "schema_probe_diagnostic": {"stage": "not_started", "reason": "not_started", "plugin": "none"},
                    "state_contract": None,
                    "header_parser_metadata": None,
                    "effective_inbound_tls_policy": None,
                    "negative_group_failures": [],
                },
                "acceptance": [{
                    "case_id": "SCHEMA-PRIORITY-01", "variant": "exact_3_16_metadata",
                    "outcome": "not_run", "phase": "separate_runtime_phase", "layer": "not_run",
                    "http_status": None, "rfc6750_challenge": "not_run",
                }],
                "full_wp3_acceptance": "not_run",
            },
            "tls": {name: "not_run" for name in (
                "localhost_sni_positive", "kong_api_sni_positive",
                "localhost_sni_requested_client_certificate", "kong_api_sni_requested_client_certificate",
                "no_client_certificate_handshake_rejected",
                "tls_11_rejected", "tls_12_only_rejected", "weak_cipher_rejected", "untrusted_server_certificate_rejected", "san_mismatch_rejected",
            )},
            "capture": {
                "request_count": 0, "api_peer_pin_matches": "not_run", "api_peer_common_name_matches": "not_run",
                "authorization_single_bearer": "not_run", "authorization_sha256_present": "not_run",
                "forwarded_certificate_thumbprint_present": "not_run", "forwarded_certificate_single_url_encoded_pem_leaf": "not_run",
                "cookie_absent": "not_run", "client_assertion_headers_absent": "not_run",
                "client_assertion_unknown_suffix_header_count": "not_run", "fixture_underscores_in_headers_on": "not_run",
                "x_fapi_headers_absent": "not_run", "x_demo_unexpected_headers_absent": "not_run",
                "department_header_matches_expected_claim": "not_run", "route_header_matches_expected_claim": "not_run",
                "x_client_cert_like_header_count": "not_run", "x_client_cert_header_count": "not_run",
                "x_client_cert_unknown_suffix_header_count": "not_run", "x_client_cert_duplicate_header_count": "not_run",
                "x_client_cert_underscore_alias_count": "not_run", "x_client_cert_stock_details_complete": "not_run",
                "x_client_cert_stock_detail_counts": {name: "not_run" for name in ("serial", "issuer_dn", "subject_dn", "fingerprint", "chain")},
                "x_client_cert_fingerprint_matches_forwarded_leaf": "not_run", "caller_spoof_sentinel_match_count": "not_run",
            },
            "log_scan": {
                "passed": False, "completed": False, "failure_reason": "log_read_failed",
                "candidate_value_count": 0, "checked_value_count": 0, "secret_value_match_count": 0,
                "source_category_counts": dict(categories), "matched_source_category_counts": dict(categories),
                "secret_match_category_counts": dict(categories), "credential_pattern_match_count": 0,
                "credential_pattern_matches": [], "public_fixture_identifier_observation_count": 0,
                "public_fixed_protocol_constant_observation_count": 0,
                "service_scans": failed_service_scan_receipt(),
                "api_response_completed": True, "api_response_failure_reason": "none",
                "api_response_count": 0, "api_response_scanned_byte_count": 0,
                "api_response_secret_value_match_count": 0,
                "api_response_secret_match_category_counts": dict(categories),
                "api_response_credential_pattern_matches": [],
            },
            "containers_started": True, "konnect_read_or_write_performed": False,
        }
        from prepare_wp3_preview import validate_runtime_receipt

        validate_runtime_receipt(receipt)
        valid_receipt = json.loads(json.dumps(receipt))
        receipt["cases"]["acceptance"][0]["raw_token"] = "MUST-NOT-PERSIST"
        with self.assertRaisesRegex(Exception, "case fields"):
            validate_runtime_receipt(receipt)

        for location in ("execution_phase", "case_id", "case_phase", "case_variant"):
            candidate = json.loads(json.dumps(valid_receipt))
            if location == "execution_phase":
                candidate["cases"]["execution"]["phase"] = "secretvalue"
            elif location == "case_id":
                candidate["cases"]["acceptance"][0]["case_id"] = "SECRETVALUE"
            elif location == "case_phase":
                candidate["cases"]["acceptance"][0]["phase"] = "secretvalue"
            else:
                candidate["cases"]["acceptance"][0]["variant"] = "secretvalue"
            with self.assertRaises(Exception):
                validate_runtime_receipt(candidate)

        tls_receipt = json.loads(json.dumps(valid_receipt))
        tls_receipt["cases"]["acceptance"] = [{
            "case_id": "TLS-RS-01", "variant": "tls_11", "outcome": "pass",
            "phase": "tls_negative", "layer": "tls_handshake", "http_status": None,
            "rfc6750_challenge": "not_applicable", "client_hello_offered": True,
            "offered_protocols": ["TLSv1.1"], "tls_policy_proven": False,
            "negotiated_protocol": "not_run", "negotiated_cipher": "not_run",
            "upstream_unchanged": True,
            "tls_failure_reason": "peer_alert_protocol_version", "tls_verify_code": None,
            "post_negative_valid_control": True,
        }]
        validate_runtime_receipt(tls_receipt)
        tls_receipt["cases"]["acceptance"][0]["tls_failure_reason"] = "other_tls_error"
        with self.assertRaises(Exception):
            validate_runtime_receipt(tls_receipt)

        tls12_receipt = json.loads(json.dumps(valid_receipt))
        tls12_receipt["cases"]["acceptance"] = [{
            "case_id": "TLS-RS-01", "variant": "tls_12_only", "outcome": "pass",
            "phase": "tls_negative", "layer": "tls_handshake", "http_status": None,
            "rfc6750_challenge": "not_applicable", "client_hello_offered": True,
            "offered_protocols": ["TLSv1.2"], "tls_policy_proven": True,
            "negotiated_protocol": "TLSv1.3", "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
            "upstream_unchanged": True, "tls_failure_reason": "peer_alert_protocol_version",
            "tls_verify_code": None, "post_negative_valid_control": True,
        }]
        with self.assertRaisesRegex(Exception, "lacks policy"):
            validate_runtime_receipt(tls12_receipt)

        header_receipt = json.loads(json.dumps(valid_receipt))
        header_receipt["cases"]["acceptance"] = [{
            "case_id": "HEADER-CERT-01", "variant": "headers_101", "outcome": "pass",
            "phase": "api_header_boundary", "layer": "gateway+upstream_capture", "http_status": 200,
            "rfc6750_challenge": "not_applicable", "input_wire_header_count": 101,
            "upstream_header_count": 117,
            "parser_source": "not_run", "wire_grammar_valid": "not_run",
            "upstream_unchanged": True, "response_scan_clean": "not_run",
            "post_negative_valid_control": "not_run", "parser_log_scan_completed": "not_run",
            "parser_error_marker_delta": None, "parser_api_request_marker_delta": None,
        }]
        validate_runtime_receipt(header_receipt)
        header_receipt["cases"]["acceptance"][0]["input_wire_header_count"] = 99
        with self.assertRaises(Exception):
            validate_runtime_receipt(header_receipt)

    def test_effective_tls_admin_metadata_is_bound_to_the_admin_probe(self):
        image_digest = wp3_flow.IMAGES["kong-api"][1]
        admin = {"metadata_source": "admin_root_configuration", "cipher_suite": "modern", "protocols": []}
        config_dump = (
            b"# configuration file /usr/local/kong/nginx.conf:\n"
            b"include 'nginx-inject.conf';\nevents {}\nhttp { include 'nginx-kong.conf'; }\n"
            b"# configuration file /usr/local/kong/nginx-inject.conf:\n"
            b"# configuration file /usr/local/kong/nginx-kong.conf:\n"
            b"include 'nginx-kong-inject.conf';\nserver { listen 0.0.0.0:8443 ssl; }\n"
            b"# configuration file /usr/local/kong/nginx-kong-inject.conf:\n"
            b"ssl_protocols TLSv1.3;\n"
            b"nginx: the configuration file /usr/local/kong/nginx.conf syntax is ok\n"
            b"nginx: configuration file /usr/local/kong/nginx.conf test is successful\n"
        )
        effective = wp3_flow.derive_effective_inbound_tls_policy(
            config_dump, dump_succeeded=True,
            openresty_version="openresty/1.29.2.5",
            image_metadata={"digest": image_digest, "architecture": "arm64"},
            admin_tls_metadata=admin,
        )
        self.assertTrue(wp3_prepare.effective_tls_matches_admin_observation(effective, admin))
        self.assertTrue(effective["effective_inbound_tls_proven"])

        changed_cipher = {**admin, "cipher_suite": "not_proven"}
        self.assertFalse(wp3_prepare.effective_tls_matches_admin_observation(effective, changed_cipher))
        changed_protocols = {**admin, "protocols": ["TLSv1.3"]}
        self.assertFalse(wp3_prepare.effective_tls_matches_admin_observation(effective, changed_protocols))

    def test_runtime_receipt_writer_rejects_unknown_payload_before_file_creation(self):
        with TemporaryDirectory() as directory:
            preview = Path(directory)
            evidence = preview / "evidence"
            evidence.mkdir(mode=0o700)
            evidence.chmod(0o700)
            with patch.object(wp3_flow, "PREVIEW", preview):
                with self.assertRaisesRegex(wp3_flow.FlowError, "strict private schema"):
                    wp3_flow.write_runtime_receipt({"raw_token": "WRITER-SECRET-SENTINEL"})
            self.assertEqual(list(evidence.iterdir()), [])

    def test_cleanup_rejects_dangling_receipt_symlink_and_removes_owned_fixture(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / ".generated"
            preview = generated / "wp3-preview"
            (preview / "evidence").mkdir(mode=0o700, parents=True)
            (preview / "pki").mkdir(mode=0o700)
            preview.chmod(0o700)
            secret = preview / "pki/private.key"
            secret.write_text("PRIVATE-KEY-SENTINEL-NEVER-PRESERVE")
            secret.chmod(0o600)
            prep_receipt = preview / "evidence/wp3-preparation-receipt.json"
            prep_receipt.write_text('{"safe":true}\n')
            prep_receipt.chmod(0o600)
            (preview / "evidence/wp3-runtime-receipt.json").symlink_to("missing-runtime-receipt.json")
            image_contract = {
                name: {"digest": digest, "architecture": "arm64"}
                for name, (_reference, digest) in wp3_flow.IMAGES.items()
            }
            completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with patch.object(wp3_cleanup, "ROOT", root), patch.object(wp3_cleanup, "PREVIEW", preview), patch.object(
                wp3_cleanup, "COMPOSE_FILE", root / "compose.yml"
            ), patch.object(wp3_cleanup, "verify_preparation_receipt", return_value={"images": image_contract}), patch.object(
                wp3_cleanup, "load_runtime_role_values",
                return_value={"API_INTROSPECTION_KEY": "role-secret-a", "API_UPSTREAM_KEY": "role-secret-b"},
            ), patch.object(wp3_cleanup, "inspect_images", return_value=image_contract), patch.object(
                wp3_cleanup, "project_container_ids", return_value=[]
            ), patch.object(wp3_cleanup, "compose_command", return_value=completed), patch.object(
                wp3_cleanup, "require_isolated_project_absent"
            ), patch.object(wp3_cleanup, "require_cleanup_ports_free"), patch.object(
                wp3_cleanup.subprocess, "run", return_value=completed
            ), patch.dict(wp3_cleanup.os.environ, {"KONG_LICENSE_DATA": "LICENSE-SENTINEL"}):
                with self.assertRaisesRegex(wp3_cleanup.PreviewError, "unsafe sanitized receipt was not preserved"):
                    wp3_cleanup.cleanup()
            self.assertFalse(preview.exists())
            self.assertFalse(secret.exists())
            status_files = list((generated / "evidence").glob("wp3-cleanup-status-*.json"))
            self.assertEqual(len(status_files), 1)
            self.assertEqual(json.loads(status_files[0].read_text())["status"], "sanitized_receipt_rejected")

    def test_cleanup_persists_bounded_port_failure_after_private_fixture_removal(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / ".generated"
            preview = generated / "wp3-preview"
            (preview / "evidence").mkdir(mode=0o700, parents=True)
            (preview / "pki").mkdir(mode=0o700)
            preview.chmod(0o700)
            key = preview / "pki/private.key"
            key.write_text("PRIVATE-KEY-SENTINEL-NEVER-PRESERVE")
            key.chmod(0o600)
            prep_receipt = preview / "evidence/wp3-preparation-receipt.json"
            prep_receipt.write_text('{"safe":true}\n')
            prep_receipt.chmod(0o600)
            image_contract = {
                name: {"digest": digest, "architecture": "arm64"}
                for name, (_reference, digest) in wp3_flow.IMAGES.items()
            }
            completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with patch.object(wp3_cleanup, "ROOT", root), patch.object(wp3_cleanup, "PREVIEW", preview), patch.object(
                wp3_cleanup, "COMPOSE_FILE", root / "compose.yml"
            ), patch.object(wp3_cleanup, "verify_preparation_receipt", return_value={"images": image_contract}), patch.object(
                wp3_cleanup, "load_runtime_role_values",
                return_value={"API_INTROSPECTION_KEY": "role-secret-a", "API_UPSTREAM_KEY": "role-secret-b"},
            ), patch.object(wp3_cleanup, "inspect_images", return_value=image_contract), patch.object(
                wp3_cleanup, "project_container_ids", return_value=[]
            ), patch.object(wp3_cleanup, "compose_command", return_value=completed), patch.object(
                wp3_cleanup, "require_isolated_project_absent"
            ), patch.object(
                wp3_cleanup, "require_cleanup_ports_free",
                side_effect=wp3_cleanup.PreviewError("dedicated WP3 ports remained occupied after bounded cleanup wait"),
            ), patch.object(wp3_cleanup.subprocess, "run", return_value=completed), patch.dict(
                wp3_cleanup.os.environ, {"KONG_LICENSE_DATA": "LICENSE-SENTINEL"}
            ):
                with self.assertRaisesRegex(wp3_cleanup.PreviewError, "bounded cleanup wait"):
                    wp3_cleanup.cleanup()
            self.assertFalse(preview.exists())
            self.assertFalse(key.exists())
            status_files = list((generated / "evidence").glob("wp3-cleanup-status-*.json"))
            self.assertEqual(len(status_files), 1)
            self.assertEqual(json.loads(status_files[0].read_text())["status"], "ports_remained_occupied")

    def test_cleanup_removes_fixture_when_strict_receipt_is_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / ".generated"
            preview = generated / "wp3-preview"
            (preview / "evidence").mkdir(mode=0o700, parents=True)
            (preview / "pki").mkdir(mode=0o700)
            preview.chmod(0o700)
            secret = preview / "pki/private.key"
            secret.write_text("PRIVATE-KEY-SENTINEL-NEVER-PRESERVE")
            secret.chmod(0o600)
            (preview / "evidence/wp3-preparation-receipt.json").write_text('{"safe":true}\n')
            (preview / "evidence/wp3-preparation-receipt.json").chmod(0o600)
            (preview / "evidence/wp3-runtime-receipt.json").write_text('{"raw_token":"UNSAFE-RECEIPT-SENTINEL"}\n')
            (preview / "evidence/wp3-runtime-receipt.json").chmod(0o600)
            image_contract = {name: {"digest": digest, "architecture": "arm64"} for name, (_reference, digest) in wp3_flow.IMAGES.items()}
            completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with patch.object(wp3_cleanup, "ROOT", root), patch.object(wp3_cleanup, "PREVIEW", preview), patch.object(
                wp3_cleanup, "COMPOSE_FILE", root / "compose.yml"
            ), patch.object(wp3_cleanup, "verify_preparation_receipt", return_value={"images": image_contract}), patch.object(
                wp3_cleanup, "load_runtime_role_values", return_value={"API_INTROSPECTION_KEY": "role-secret-a", "API_UPSTREAM_KEY": "role-secret-b"}
            ), patch.object(wp3_cleanup, "inspect_images", return_value=image_contract), patch.object(
                wp3_cleanup, "project_container_ids", return_value=[]
            ), patch.object(wp3_cleanup, "compose_command", return_value=completed), patch.object(
                wp3_cleanup, "require_isolated_project_absent"
            ), patch.object(wp3_cleanup, "require_ports_free"), patch.object(
                wp3_cleanup.subprocess, "run", return_value=completed
            ), patch.dict(wp3_cleanup.os.environ, {"KONG_LICENSE_DATA": "LICENSE-SENTINEL"}):
                with self.assertRaisesRegex(wp3_cleanup.PreviewError, "unsafe sanitized receipt was not preserved"):
                    wp3_cleanup.cleanup()
            self.assertFalse(preview.exists())
            status_files = list((generated / "evidence").glob("wp3-cleanup-status-*.json"))
            self.assertEqual(len(status_files), 1)
            self.assertEqual(json.loads(status_files[0].read_text()), {
                "schema_version": 1,
                "scope": "wp3-isolated-fixture-cleanup",
                "status": "sanitized_receipt_rejected",
            })
            self.assertNotIn("UNSAFE-RECEIPT-SENTINEL", "".join(path.read_text() for path in (generated / "evidence").iterdir()))

    def test_cleanup_port_release_check_retries_only_expected_bind_race(self):
        with patch.object(
            wp3_cleanup, "require_ports_free",
            side_effect=[wp3_cleanup.PreviewError("required isolated preview port 18443 is already in use"), None],
        ) as require_free, patch.object(
            wp3_cleanup.time, "monotonic", side_effect=[10.0, 10.1]
        ), patch.object(wp3_cleanup.time, "sleep") as sleep:
            wp3_cleanup.require_cleanup_ports_free(timeout_seconds=1.0, poll_interval_seconds=0.2)
        self.assertEqual(require_free.call_count, 2)
        sleep.assert_called_once_with(0.2)

    def test_cleanup_port_release_check_times_out_and_does_not_retry_other_errors(self):
        with patch.object(
            wp3_cleanup, "require_ports_free",
            side_effect=wp3_cleanup.PreviewError("required isolated preview port 18443 is already in use"),
        ) as require_free, patch.object(wp3_cleanup.time, "monotonic", side_effect=[5.0, 5.0]), patch.object(
            wp3_cleanup.time, "sleep"
        ) as sleep:
            with self.assertRaisesRegex(wp3_cleanup.PreviewError, "bounded cleanup wait"):
                wp3_cleanup.require_cleanup_ports_free(timeout_seconds=0)
        require_free.assert_called_once()
        sleep.assert_not_called()

        with patch.object(
            wp3_cleanup, "require_ports_free",
            side_effect=wp3_cleanup.PreviewError("could not inspect isolated preview port 18443"),
        ) as require_free, patch.object(wp3_cleanup.time, "sleep") as sleep:
            with self.assertRaisesRegex(wp3_cleanup.PreviewError, "could not inspect"):
                wp3_cleanup.require_cleanup_ports_free(timeout_seconds=1)
        require_free.assert_called_once()
        sleep.assert_not_called()

    def test_port_guard_rejects_active_listener_and_accepts_time_wait_only(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
        except PermissionError:
            listener.close()
            self.skipTest("sandbox denied loopback listener creation; run this OS check with local bind access")
        try:
            listener.listen(1)
            active_port = listener.getsockname()[1]
            active_lsof = subprocess.CompletedProcess(
                ["lsof"], 0, stdout="COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nlistener 1 user 3u IPv4 1 0t0 TCP 127.0.0.1:1234 (LISTEN)\n", stderr=""
            )
            with patch.object(wp3_prepare, "command", return_value=active_lsof):
                with self.assertRaisesRegex(wp3_prepare.PreviewError, "already in use"):
                    wp3_prepare.require_loopback_port_free(active_port)
        finally:
            listener.close()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bound_owner:
            bound_owner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bound_owner.bind(("127.0.0.1", 0))
            bound_port = bound_owner.getsockname()[1]
            bound_lsof = subprocess.CompletedProcess(
                ["lsof"], 0, stdout="COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nowner 1 user 3u IPv4 1 0t0 TCP 127.0.0.1:2345\n", stderr=""
            )
            with patch.object(wp3_prepare, "command", return_value=bound_lsof):
                with self.assertRaisesRegex(wp3_prepare.PreviewError, "already in use"):
                    wp3_prepare.require_loopback_port_free(bound_port)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
        except PermissionError:
            server.close()
            self.skipTest("sandbox denied loopback connection setup; run this OS check with local bind access")
        server.listen(1)
        accepted = {}

        def drain_peer():
            connection, _address = server.accept()
            accepted["connection"] = connection
            connection.recv(1)
            connection.close()

        thread = threading.Thread(target=drain_peer, daemon=True)
        thread.start()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.bind(("127.0.0.1", 0))
            client.connect(server.getsockname())
        except PermissionError:
            client.close()
            server.close()
            self.skipTest("sandbox denied loopback connection setup; run this OS check with local bind access")
        time_wait_port = client.getsockname()[1]
        client.shutdown(socket.SHUT_WR)
        client.close()
        thread.join(timeout=2)
        server.close()
        self.assertFalse(thread.is_alive())

        plain_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            plain_probe.bind(("127.0.0.1", time_wait_port))
        except OSError as error:
            self.assertIn(error.errno, {98, 48, 10048})
        else:
            plain_probe.close()
            self.skipTest("host did not retain a TIME_WAIT-only loopback bind conflict")
        finally:
            plain_probe.close()

        no_listeners = subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr="")
        with patch.object(wp3_prepare, "command", return_value=no_listeners):
            wp3_prepare.require_loopback_port_free(time_wait_port)

    def test_port_guard_fails_closed_when_bind_permissions_hide_unknown_socket_state(self):
        class PermissionDeniedSocket:
            def setsockopt(self, *_args):
                return None

            def bind(self, _address):
                raise PermissionError(1, "operation not permitted")

            def close(self):
                return None

        no_open_fds = subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr="")
        with patch.object(wp3_prepare.socket, "socket", side_effect=[PermissionDeniedSocket(), PermissionDeniedSocket()]), patch.object(
            wp3_prepare, "command", return_value=no_open_fds
        ):
            with self.assertRaisesRegex(wp3_prepare.PreviewError, "could not inspect isolated preview port"):
                wp3_prepare.require_loopback_port_free(18443)

    def test_capture_helper_counter_observer_binds_loopback_and_returns_only_count(self):
        class FakeCapture:
            @staticmethod
            def current_request_count():
                return 3

        created = {}

        class FakeServer:
            def __init__(self, address, handler):
                created["address"] = address
                created["handler"] = handler
                self.daemon_threads = False

        with patch.object(wp3_capture.http.server, "ThreadingHTTPServer", FakeServer):
            server = wp3_capture.build_loopback_count_server(FakeCapture(), port=9444)
        self.assertEqual(created["address"], ("127.0.0.1", 9444))
        self.assertTrue(server.daemon_threads)

        handler = object.__new__(wp3_capture.LoopbackCountHandler)
        handler.path = "/count"
        handler.server = SimpleNamespace(capture_server=FakeCapture())
        handler.wfile = io.BytesIO()
        handler.close_connection = False
        handler.send_response = lambda *_args: None
        handler.send_header = lambda *_args: None
        handler.end_headers = lambda: None
        handler.do_GET()
        self.assertEqual(json.loads(handler.wfile.getvalue()), {"request_count": 3})

    def test_capture_evidence_accepts_opaque_query_without_reflecting_or_parsing_it(self):
        for target, expected_status, expected_count in (
            ("/evidence?probe=harmless", 200, 1),
            ("/evidence?access_token=QUERY_SENTINEL_VALUE", 200, 1),
            ("/evidence-extra?probe=harmless", 404, 0),
            ("https://capture.invalid/evidence?probe=harmless", 404, 0),
        ):
            with self.subTest(target=target.split("?", 1)[0]):
                counts = {"current": 0}

                def next_request_count():
                    counts["current"] += 1
                    return counts["current"]

                handler = object.__new__(wp3_capture.CaptureHandler)
                handler.path = target
                handler._peer_gate = lambda: True
                handler.server = SimpleNamespace(
                    current_request_count=lambda: counts["current"],
                    next_request_count=next_request_count,
                    capture_config=object(),
                )
                handler.headers = {}
                handler.wfile = io.BytesIO()
                handler.close_connection = False
                statuses = []
                handler.send_response = lambda status, *_args: statuses.append(status)
                handler.send_header = lambda *_args: None
                handler.end_headers = lambda: None
                with patch.object(wp3_capture, "summarize_request_headers", return_value={"safe": True}):
                    handler.do_GET()
                self.assertEqual(statuses, [expected_status])
                self.assertEqual(counts["current"], expected_count)
                response = handler.wfile.getvalue().decode("utf-8")
                self.assertNotIn("QUERY_SENTINEL_VALUE", response)
                if expected_status == 200:
                    self.assertEqual(json.loads(response)["request_count"], 1)
        values = {
            "iss": wp3_flow.PUBLIC_ISSUER,
            "aud": ["fapi-demo-api", "api-gateway-introspection", "TEST-UNKNOWN-AUD-MARKER"],
            "scope": "openid profile",
            "client": {"client_id": "third-party-fapi-mtls", "certificate": "route-a.crt", "key": "route-a.key"},
        }
        wp3_flow.remember_sensitive(values)
        logs = " ".join([values["iss"], *values["aud"], values["scope"], *values["client"].values()])
        with patch.object(wp3_flow, "compose_service_logs", return_value=complete_service_logs({"keycloak": logs})):
            result = wp3_flow.scan_logs_for_sensitive_values([])
        self.assertFalse(result["passed"])
        self.assertEqual(result["secret_match_category_counts"]["unknown"], 1)
        self.assertGreaterEqual(result["public_fixed_protocol_constant_observation_count"], 4)
        self.assertGreaterEqual(result["public_fixture_identifier_observation_count"], 3)
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_incomplete_log_capture_reports_zero_checked_values_and_fixed_reason(self):
        with patch.object(
            wp3_flow,
            "compose_service_logs",
            return_value=failed_service_logs("container_inventory_unavailable", failed_service="keycloak"),
        ):
            result = wp3_flow.scan_logs_for_sensitive_values(["private-fixture-password"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["completed"])
        self.assertEqual(result["failure_reason"], "container_inventory_unavailable")
        self.assertEqual(
            result["candidate_value_count"],
            len(wp3_flow.normalize_log_candidates(["private-fixture-password"])),
        )
        self.assertEqual(result["checked_value_count"], 0)
        self.assertTrue(all(
            row["matched_candidate_provenance"] == []
            and all(value == 0 for value in row["matched_log_context_counts"].values())
            for row in result["service_scans"].values()
        ))

    def test_crypto_dependency_preflight_stops_before_oauth_setup(self):
        missing = {
            "interpreter": "/path/python3",
            "python_version": "3.14.6",
            "pyjwt_version": "not_installed",
            "pyjwt_importable": False,
            "cryptography_version": "not_installed",
            "cryptography_importable": False,
        }
        execution = {"phase": "preflight"}
        with patch.object(wp3_flow, "host_crypto_diagnostics", return_value=missing), patch.object(
            wp3_flow, "load_wp2_flow", side_effect=AssertionError("OAuth support must not load")
        ):
            with self.assertRaisesRegex(wp3_flow.FlowError, "PS256 verification dependencies"):
                wp3_flow.run_positive_flows([], {}, {}, [], execution)
        self.assertEqual(execution["phase"], "crypto_dependency_preflight")
        self.assertEqual(execution["host_runtime"], missing)

    def test_successful_exchange_then_validation_failure_records_only_safe_phase(self):
        phases = []

        class FakeWp2:
            def exchange_code(self, *_args):
                return {"access_token": "synthetic-private-token-value"}

            def verify_access_token(self, *_args):
                raise wp3_flow.FlowError("verification failed")

        wp3_flow.SENSITIVE_VALUES.clear()
        with self.assertRaisesRegex(wp3_flow.FlowError, "verification failed"):
            wp3_flow.exchange_and_validate_token(
                FakeWp2(), {}, "issuer", {}, {}, Path("/unused"), Path("/unused"), phases.append
            )
        self.assertEqual(phases, ["token_exchange", "token_signature_and_claim_validation"])
        self.assertIn(("oauth_token", "synthetic-private-token-value"), wp3_flow.SENSITIVE_VALUES)
        wp3_flow.SENSITIVE_VALUES.clear()

    def test_owned_log_inventory_accepts_exact_stopped_services_only_for_log_scan(self):
        services = ["keycloak", "kong-api", "pop-verifier"]
        ids = [f"id-{name}" for name in services]
        inspect = []
        for name, container_id in zip(services, ids):
            inspect.append({
                "Id": container_id,
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": wp3_flow.PROJECT,
                        "com.docker.compose.service": name,
                    },
                    "Image": wp3_flow.IMAGES[name][0],
                },
                "State": {"Running": False},
            })
        outputs = [
            subprocess.CompletedProcess([], 0, stdout="\n".join(ids), stderr=""),
            subprocess.CompletedProcess([], 0, stdout=json.dumps(inspect), stderr=""),
        ]
        with patch.object(wp3_flow.subprocess, "run", side_effect=outputs) as run:
            observed = wp3_flow.verify_owned_project_containers(allow_stopped=True)
        self.assertEqual(set(observed), set(services))
        self.assertIn("--all", run.call_args_list[0].args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
