#!/usr/bin/env python3
"""No-Docker checks for the isolated WP5 runtime fixture helpers."""

from __future__ import annotations

import base64
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
import ssl
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests/harness/wp5_observer"
sys.path.insert(0, str(HARNESS))
import runtime_fixture as runtime  # noqa: E402

try:
    import cryptography  # noqa: F401
except ImportError:
    HAS_CRYPTOGRAPHY = False
else:
    HAS_CRYPTOGRAPHY = True


class FakeSocket:
    """A deterministic recv stream that honors the requested read size."""

    def __init__(self, chunks: list[bytes]):
        self.chunks = iter(chunks)
        self.pending = bytearray()
        self.timeouts: list[float | None] = []

    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)

    def recv(self, size: int) -> bytes:
        if not self.pending:
            self.pending.extend(next(self.chunks, b""))
        result = bytes(self.pending[:size])
        del self.pending[:size]
        return result


def fragmented(data: bytes, size: int = 7) -> list[bytes]:
    return [data[offset : offset + size] for offset in range(0, len(data), size)]


def read_response(data: bytes) -> tuple[int, bytes]:
    return runtime._read_response(FakeSocket(fragmented(data)), time.monotonic() + 5)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is available only in the cached WP2 test venv")
class FixturePKITests(unittest.TestCase):
    def test_fresh_fixture_inventory_permissions_signatures_and_digests(self) -> None:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        expected_files = {
            "ca/ca.crt",
            "ca/outside-ca.crt",
            "tls/server.crt",
            "tls/server.key",
            "clients/route-a.crt",
            "clients/route-a.key",
            "clients/route-b.crt",
            "clients/route-b.key",
            "clients/metadata.crt",
            "clients/metadata.key",
            "clients/untrusted.crt",
            "clients/untrusted.key",
            "clients/expired.crt",
            "clients/expired.key",
            "realm/fapi-demo-realm.json",
            "observer-off.env",
            "observer-on.env",
        }
        expected_leaf_names = {
            "server": "localhost",
            "route-a": "kong-fapi-mtls",
            "route-b": "kong-fapi-pkj-mtls",
            "metadata": "third-party-metadata",
            "untrusted": "untrusted",
            "expired": "expired",
        }

        with tempfile.TemporaryDirectory(prefix="wp5-runtime-tests-") as temporary:
            root = Path(temporary) / "fixture"
            receipt = runtime.prepare_fixture(root=root, receipt=None)
            self.assertEqual(receipt["result"], "prepared")
            self.assertEqual(receipt["schema"], "wp5-observer-fixture-prep-v3")
            self.assertEqual(receipt["file_count"], 17)
            self.assertEqual(receipt["directory_mode"], "0700")
            self.assertEqual(receipt["file_mode"], "0600")
            self.assertEqual(receipt["realm"], "fapi-demo")
            self.assertEqual(receipt["accounts_created"], 0)
            self.assertEqual(receipt["oauth_secrets_created"], 0)

            actual_files = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
            actual_dirs = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_dir()}
            self.assertEqual(actual_files, expected_files)
            self.assertEqual(actual_dirs, {"ca", "tls", "clients", "realm"})
            for directory in (root, root / "ca", root / "tls", root / "clients", root / "realm"):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for relative in expected_files:
                self.assertEqual(stat.S_IMODE((root / relative).stat().st_mode), 0o600, relative)

            cert_paths = {
                relative: root / relative
                for relative in expected_files
                if relative.endswith(".crt")
            }
            self.assertEqual(set(receipt["certificates"]), set(cert_paths))
            for relative, path in cert_paths.items():
                self.assertEqual(receipt["certificates"][relative], hashlib.sha256(path.read_bytes()).hexdigest())

            trusted = x509.load_pem_x509_certificate((root / "ca/ca.crt").read_bytes())
            outside = x509.load_pem_x509_certificate((root / "ca/outside-ca.crt").read_bytes())

            def verifies_directly(cert, issuer) -> bool:
                try:
                    cert.verify_directly_issued_by(issuer)
                    return True
                except (InvalidSignature, ValueError):
                    return False

            self.assertTrue(verifies_directly(trusted, trusted))
            self.assertTrue(verifies_directly(outside, outside))
            self.assertFalse(verifies_directly(trusted, outside))
            for identity, expected_cn in expected_leaf_names.items():
                relative = f"tls/server.crt" if identity == "server" else f"clients/{identity}.crt"
                cert = x509.load_pem_x509_certificate((root / relative).read_bytes())
                common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                self.assertEqual([entry.value for entry in common_names], [expected_cn])
                issuer = outside if identity == "untrusted" else trusted
                self.assertTrue(verifies_directly(cert, issuer), identity)
                self.assertFalse(verifies_directly(cert, trusted if identity == "untrusted" else outside), identity)

                thumbprint = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).rstrip(b"=").decode()
                if identity != "server":
                    self.assertEqual(receipt["peer_thumbprints"][identity], thumbprint)
                usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                expected_usage = ExtendedKeyUsageOID.SERVER_AUTH if identity == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
                self.assertEqual(list(usage), [expected_usage], identity)

                key_rel = relative.removesuffix(".crt") + ".key"
                private_key = serialization.load_pem_private_key((root / key_rel).read_bytes(), password=None)
                cert_public = cert.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                key_public = private_key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.assertEqual(cert_public, key_public, identity)

            self.assertEqual(set(receipt["peer_thumbprints"]), {"route-a", "route-b", "metadata", "untrusted", "expired"})
            server = x509.load_pem_x509_certificate((root / "tls/server.crt").read_bytes())
            san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(san.get_values_for_type(x509.DNSName), ["localhost"])
            self.assertEqual(san.get_values_for_type(x509.IPAddress), [ipaddress.ip_address("127.0.0.1")])
            expired = x509.load_pem_x509_certificate((root / "clients/expired.crt").read_bytes())
            self.assertLess(expired.not_valid_after_utc, datetime.now(timezone.utc))
            realm = json.loads((root / "realm/fapi-demo-realm.json").read_text(encoding="utf-8"))
            self.assertEqual(realm, {"realm": "fapi-demo", "enabled": True})


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is available only in the cached WP2 test venv")
class SSLContextTests(unittest.TestCase):
    def test_context_requires_server_verification_and_is_fresh_without_keylog_side_effects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wp5-ssl-context-") as temporary:
            root = Path(temporary) / "fixture"
            runtime.prepare_fixture(root=root, receipt=None)
            keylog = Path(temporary) / "unexpected-ssl-keylog"
            with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
                first = runtime.create_ssl_context(root / "ca/ca.crt", root / "clients/route-a.crt", root / "clients/route-a.key")
                second = runtime.create_ssl_context(root / "ca/ca.crt")
            self.assertIsNot(first, second)
            for context in (first, second):
                self.assertIsInstance(context, ssl.SSLContext)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(context.check_hostname)
                self.assertIsNone(context.keylog_filename)
            self.assertFalse(keylog.exists())

    def test_context_rejects_an_incomplete_client_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wp5-ssl-context-") as temporary:
            root = Path(temporary) / "fixture"
            runtime.prepare_fixture(root=root, receipt=None)
            with self.assertRaises(runtime.FixtureError) as error:
                runtime.create_ssl_context(root / "ca/ca.crt", root / "clients/route-a.crt")
            self.assertEqual(error.exception.code, "client_identity_incomplete")


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is available only in the cached WP2 test venv")
class ExpiredCertificateNegativeTests(unittest.TestCase):
    def test_expired_fixture_accepts_certificate_unknown_as_peer_rejection(self) -> None:
        from cryptography import x509

        with tempfile.TemporaryDirectory(prefix="wp5-expired-negative-") as temporary:
            root = Path(temporary) / "fixture"
            runtime.prepare_fixture(root=root, receipt=None)
            cert_file = root / "clients/expired.crt"
            cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
            self.assertLess(cert.not_valid_after_utc, datetime.now(timezone.utc))
            diagnostic = {
                "category": "peer_certificate_alert",
                "alert": "TLSV1_ALERT_CERTIFICATE_UNKNOWN",
                "protocol": "TLSv1.3",
                "stage": "handshake",
            }
            with mock.patch.object(
                runtime,
                "tls_request",
                side_effect=runtime.FixtureError("tls_peer_certificate_alert", diagnostic=diagnostic),
            ) as request:
                result = runtime.tls_negative(
                    "expired",
                    cert_file=cert_file,
                    key_file=root / "clients/expired.key",
                    ca_file=root / "ca/ca.crt",
                    correlation="0123456789abcdef0123456789abcdef",
                )
            self.assertEqual(
                result,
                {
                    "result": "certificate_rejected",
                    "alert": "TLSV1_ALERT_CERTIFICATE_UNKNOWN",
                    "protocol": "TLSv1.3",
                    "stage": "handshake",
                },
            )
            self.assertEqual(request.call_args.kwargs["cert_file"], cert_file)


class TLSAlertClassificationTests(unittest.TestCase):
    def test_only_explicit_allowlisted_peer_alerts_are_classified(self) -> None:
        self.assertEqual(runtime._alert_category("TLSV1_ALERT_UNKNOWN_CA"), "certificate")
        self.assertEqual(runtime._alert_category("SSLV3_ALERT_BAD_CERTIFICATE"), "certificate")
        self.assertEqual(runtime._alert_category("TLSV1_ALERT_CERTIFICATE_UNKNOWN"), "certificate")
        self.assertEqual(runtime._alert_category("TLSV1_ALERT_CERTIFICATE_EXPIRED"), "certificate")
        self.assertEqual(runtime._alert_category("UNEXPECTED_EOF_WHILE_READING"), "other")
        self.assertEqual(runtime._alert_category("timed out"), "other")

    def test_explicit_certificate_alert_diagnostic_is_preserved(self) -> None:
        arguments = {
            "cert_file": Path("unused-client.crt"),
            "key_file": Path("unused-client.key"),
            "ca_file": Path("unused-ca.crt"),
            "correlation": "0123456789abcdef0123456789abcdef",
        }
        diagnostic = {
            "category": "peer_certificate_alert",
            "alert": "TLSV1_ALERT_CERTIFICATE_UNKNOWN",
            "protocol": "TLSv1.3",
            "stage": "handshake",
        }
        with mock.patch.object(
            runtime,
            "tls_request",
            side_effect=runtime.FixtureError("tls_peer_certificate_alert", diagnostic=diagnostic),
        ):
            self.assertEqual(
                runtime.tls_negative("expired", **arguments),
                {
                    "result": "certificate_rejected",
                    "alert": "TLSV1_ALERT_CERTIFICATE_UNKNOWN",
                    "protocol": "TLSv1.3",
                    "stage": "handshake",
                },
            )

    def test_eof_timeout_generic_socket_server_verify_and_http_are_not_peer_proof(self) -> None:
        arguments = {
            "cert_file": Path("unused-client.crt"),
            "key_file": Path("unused-client.key"),
            "ca_file": Path("unused-ca.crt"),
            "correlation": "0123456789abcdef0123456789abcdef",
        }
        rejected = (
            ("tls_failure_unclassified", "tls_failure", "unavailable", "handshake"),  # EOF / generic TLS
            ("tls_socket_timeout", "socket_timeout", "TLSv1.3", "connect"),
            ("tls_socket_failure", "socket_failure", "unavailable", "connect"),
            ("server_certificate_verification_failed", "server_certificate_verify", "TLSv1.3", "handshake"),
        )
        for code, category, protocol, stage in rejected:
            diagnostic = {"category": category, "alert": "none", "protocol": protocol, "stage": stage}
            with self.subTest(category=category), mock.patch.object(
                runtime,
                "tls_request",
                side_effect=runtime.FixtureError(code, diagnostic=diagnostic),
            ):
                with self.assertRaises(runtime.FixtureError) as error:
                    runtime.tls_negative("expired", **arguments)
                self.assertEqual(error.exception.code, code)
                self.assertEqual(error.exception.diagnostic, diagnostic)

        http_diagnostic = {
            "category": "http_received",
            "alert": "none",
            "protocol": "TLSv1.3",
            "stage": "response_read",
        }
        def received_http(*_args, **kwargs):
            kwargs["diagnostic_sink"].update(http_diagnostic)
            return 200

        with mock.patch.object(runtime, "tls_request", side_effect=received_http):
            with self.assertRaises(runtime.FixtureError) as error:
                runtime.tls_negative("expired", **arguments)
        self.assertEqual(error.exception.code, "tls_negative_received_http")
        self.assertEqual(error.exception.diagnostic, http_diagnostic)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is available only in the cached WP2 test venv")
class RuntimeFailureCleanupTests(unittest.TestCase):
    def test_early_matrix_failure_scans_bounded_logs_before_down_and_removes_exact_fixture(self) -> None:
        diagnostic = {
            "category": "tls_failure",
            "alert": "none",
            "protocol": "TLSv1.3",
            "stage": "handshake",
        }
        with tempfile.TemporaryDirectory(prefix="wp5-runtime-cleanup-") as temporary:
            parent = Path(temporary)
            fixture_root = parent / "fresh-fixture"
            prep_receipt = parent / "prep.json"
            run_intent = parent / "run-intent.json"
            run_receipt = parent / "run-receipt.json"
            sibling = parent / "keep-me"
            sibling.mkdir()
            (sibling / "sentinel").write_text("keep", encoding="utf-8")
            prep = runtime.prepare_fixture(root=fixture_root, receipt=None)
            candidate_secret_count = len(runtime.fixture_candidate_secrets(fixture_root))
            runtime.write_exclusive(
                prep_receipt,
                (json.dumps(prep, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            )

            compose_events: list[tuple[str, tuple[str, ...], dict[str, object]]] = []
            observer_failure_row = {
                "v": 1,
                "observed_at": "2026-10-04T03:04:05.123456789Z",
                "correlation_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "endpoint": "discovery",
                "method": "GET",
                "path": "realms/fapi-demo/.well-known/openid-configuration",
                "peer_present": False,
                "chain_count": 0,
                "pkix": False,
                "valid_now": False,
                "client_auth_eku": False,
                "leaf_sha256": "none",
                "error": "observer_failure",
            }
            observer_fields = (
                "v", "observed_at", "correlation_id", "endpoint", "method", "path",
                "peer_present", "chain_count", "pkix", "valid_now", "client_auth_eku",
                "leaf_sha256", "error",
            )
            encoded_fields = [
                f"{name}={str(observer_failure_row[name]).lower() if isinstance(observer_failure_row[name], bool) else observer_failure_row[name]}"
                for name in observer_fields
            ]
            raw_observer_line = (
                "2026-10-04 12:34:56,789 INFO  [org.keycloak.example] (executor-thread-1) "
                + "WP5_AS_PEER_OBS " + " ".join(encoded_fields)
            )
            log_bytes = (raw_observer_line + "\n").encode("utf-8")

            def fake_compose(env_file: str, *args: str, **kwargs) -> bytes:
                compose_events.append((env_file, args, kwargs))
                return log_bytes if "logs" in args else b""

            scan_events: list[tuple[bytes, int]] = []
            real_leak_scan = runtime.leak_scan

            def scan(raw: bytes, candidate_secrets=()):
                scan_events.append((raw, len(candidate_secrets)))
                return real_leak_scan(raw, candidate_secrets)

            primary_failure = runtime.FixtureError("tls_failure_unclassified", diagnostic=diagnostic)

            def fail_first_request(*_args, **_kwargs):
                raise primary_failure

            real_verify_tree = runtime.verify_fixture_tree

            def verify_temp_tree(*_args, **_kwargs):
                return real_verify_tree(fixture_root)

            real_candidate_secrets = runtime.fixture_candidate_secrets

            def fixture_secrets(*_args, **_kwargs):
                return real_candidate_secrets(fixture_root)

            with ExitStack() as stack:
                replacements = {
                    "FIXTURE_ROOT": fixture_root,
                    "PREP_RECEIPT": prep_receipt,
                    "RUN_INTENT": run_intent,
                    "RUN_RECEIPT": run_receipt,
                    "verify_fixture_tree": verify_temp_tree,
                    "fixture_candidate_secrets": fixture_secrets,
                    "preflight_absent": mock.Mock(),
                    "verify_owned_resources": mock.Mock(),
                    "_wait_tls_ready": mock.Mock(),
                    "_compose": fake_compose,
                    "_run_command": mock.Mock(return_value=b""),
                    "_resource_names": mock.Mock(return_value=set()),
                    "wait_port_released": mock.Mock(return_value=False),
                    "tls_request": fail_first_request,
                    "leak_scan": scan,
                }
                for name, replacement in replacements.items():
                    stack.enter_context(mock.patch.object(runtime, name, replacement))

                receipt = runtime.run_fixture()

            self.assertEqual(
                receipt["failure_category"],
                "tls_failure_unclassified",
                f"safe failure_case={receipt.get('failure_case')!r}; phase={receipt.get('failure_phase')!r}",
            )
            self.assertEqual(receipt["failure_case"], "off_metadata_discovery")
            self.assertEqual(receipt["failure_phase"], "observer_off_http_matrix")
            self.assertEqual(receipt["failure_diagnostic"], diagnostic)
            self.assertTrue(receipt["diagnostic_capture"]["attempted"])
            self.assertTrue(receipt["diagnostic_capture"]["complete"])
            capture = receipt["diagnostic_capture"]
            self.assertEqual(capture["validated_rows"], [observer_failure_row])
            self.assertEqual(capture["error_counts"]["observer_failure"], 1)
            self.assertNotIn("none", capture["error_counts"])
            self.assertEqual(capture["rows_joined"], 0)
            self.assertEqual(capture["unmatched_rows"], 1)
            self.assertEqual(capture["partial_rows"], [])
            self.assertNotIn(raw_observer_line, json.dumps(capture, sort_keys=True))

            logs = [event for event in compose_events if "logs" in event[1]]
            stops = [event for event in compose_events if "stop" in event[1]]
            downs = [event for event in compose_events if "down" in event[1]]
            self.assertTrue(logs)
            self.assertTrue(stops)
            self.assertTrue(downs)
            log_index = compose_events.index(logs[0])
            self.assertLess(compose_events.index(stops[0]), log_index)
            self.assertLess(log_index, compose_events.index(downs[0]))
            self.assertEqual(logs[0][2].get("cap"), runtime.MAX_LOG)
            self.assertIn((log_bytes, candidate_secret_count), scan_events)

            wait_calls = replacements["wait_port_released"].call_args_list
            self.assertEqual(len(wait_calls), 1)
            self.assertLessEqual(wait_calls[0].kwargs["timeout"], 30)
            self.assertLessEqual(wait_calls[0].kwargs["interval"], 2)
            self.assertFalse(fixture_root.exists())
            self.assertEqual((sibling / "sentinel").read_text(encoding="utf-8"), "keep")


class PortReleaseWaitTests(unittest.TestCase):
    def test_retries_transient_bind_failure_and_stops_at_bounded_deadline(self) -> None:
        class ProbeSocket:
            def __init__(self, available: bool, attempts: list[bool]):
                self.available = available
                self.attempts = attempts

            def bind(self, _address) -> None:
                self.attempts.append(self.available)
                if not self.available:
                    raise OSError("port still busy")

            def close(self) -> None:
                pass

        now = [0.0]
        sleeps: list[float] = []
        attempts: list[bool] = []
        outcomes = iter((False, True))

        def socket_factory(*_args, **_kwargs):
            return ProbeSocket(next(outcomes), attempts)

        def fake_sleep(delay: float) -> None:
            sleeps.append(delay)
            now[0] += delay

        with mock.patch.object(runtime.socket, "socket", side_effect=socket_factory), \
                mock.patch.object(runtime.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(runtime.time, "sleep", side_effect=fake_sleep):
            self.assertTrue(runtime.wait_port_released(timeout=2, interval=0.5))
        self.assertEqual(attempts, [False, True])
        self.assertEqual(sleeps, [0.5])

        now[0] = 0.0
        sleeps.clear()
        attempts.clear()

        def busy_socket_factory(*_args, **_kwargs):
            return ProbeSocket(False, attempts)

        with mock.patch.object(runtime.socket, "socket", side_effect=busy_socket_factory), \
                mock.patch.object(runtime.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(runtime.time, "sleep", side_effect=fake_sleep):
            self.assertFalse(runtime.wait_port_released(timeout=1, interval=0.5))
        self.assertEqual(attempts, [False, False, False])
        self.assertEqual(sleeps, [0.5, 0.5])
        self.assertLessEqual(sum(sleeps), 1)


class BoundedHTTPParserTests(unittest.TestCase):
    def test_reads_fragmented_content_length_response_completely(self) -> None:
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        status, response = read_response(wire)
        self.assertEqual(status, 200)
        self.assertEqual(response, wire)

    def test_reads_chunked_response_and_detects_secret_split_across_chunks(self) -> None:
        secret = b"fixture-secret-sentinel-77c9"
        parts = (b"prefix=" + secret[:11], secret[11:] + b";suffix")
        chunked = b"".join(f"{len(part):x}\r\n".encode() + part + b"\r\n" for part in parts) + b"0\r\n\r\n"
        self.assertNotIn(secret, chunked)
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked
        status, response = read_response(wire)
        self.assertEqual(status, 200)
        self.assertIn(b"\x00prefix=" + secret + b";suffix", response)
        self.assertEqual(runtime.leak_scan(response, (secret,)), {"fixture_material": 1})

    def test_reads_close_delimited_body_to_eof(self) -> None:
        wire = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nbody"
        status, response = read_response(wire)
        self.assertEqual(status, 200)
        self.assertEqual(response, wire)

    def test_rejects_incomplete_headers_bodies_and_chunks(self) -> None:
        deadline = time.monotonic() + 5
        cases = (
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n", "http_response_incomplete"),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nx", "http_body_incomplete"),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc",
                "http_chunked_body_incomplete",
            ),
        )
        for wire, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(runtime.FixtureError) as error:
                    runtime._read_response(FakeSocket(fragmented(wire)), deadline)
                self.assertEqual(error.exception.code, expected_code)

    def test_rejects_oversized_headers_and_bodies(self) -> None:
        deadline = time.monotonic() + 5
        huge_header = b"HTTP/1.1 200 OK\r\nX-Pad: " + b"x" * (16 * 1024)
        with self.assertRaises(runtime.FixtureError) as header_error:
            runtime._read_response(FakeSocket(fragmented(huge_header)), deadline)
        self.assertEqual(header_error.exception.code, "http_header_limit")

        oversize_length = f"HTTP/1.1 200 OK\r\nContent-Length: {runtime.MAX_RESPONSE + 1}\r\n\r\n".encode()
        with self.assertRaises(runtime.FixtureError) as body_error:
            runtime._read_response(FakeSocket(fragmented(oversize_length)), deadline)
        self.assertEqual(body_error.exception.code, "http_body_limit")

        oversize_chunk = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{runtime.MAX_RESPONSE + 1:x}\r\n".encode()
        )
        with self.assertRaises(runtime.FixtureError) as chunk_error:
            runtime._read_response(FakeSocket(fragmented(oversize_chunk)), deadline)
        self.assertEqual(chunk_error.exception.code, "http_body_limit")


class ComposeIsolationTests(unittest.TestCase):
    def test_compose_uses_only_immutable_image_loopback_limits_and_server_inputs(self) -> None:
        compose_path = ROOT / "tests/harness/docker-compose.wp5-observer.yml"
        compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        service = compose["services"]["keycloak"]

        self.assertEqual(service["image"], runtime.IMAGE_ID)
        self.assertEqual(service["pull_policy"], "never")
        self.assertNotIn("build", service)
        self.assertEqual(service["ports"], ["127.0.0.1:19443:8443"])
        self.assertEqual(service["cpus"], 2)
        self.assertEqual(service["mem_limit"], "4g")
        self.assertEqual(service["pids_limit"], 256)

        expected_binds = {
            ("${WP5_FIXTURE_ROOT:?}/realm/fapi-demo-realm.json", "/opt/keycloak/data/import/fapi-demo-realm.json", "ro"),
            ("${WP5_FIXTURE_ROOT:?}/tls/server.crt", "/opt/keycloak/conf/tls/server.crt", "ro"),
            ("${WP5_FIXTURE_ROOT:?}/tls/server.key", "/opt/keycloak/conf/tls/server.key", "ro"),
            ("${WP5_FIXTURE_ROOT:?}/ca/ca.crt", "/opt/keycloak/conf/trust/ca.crt", "ro"),
        }
        actual_binds = set()
        named_volumes = []
        for mount in service["volumes"]:
            source, target, *mode = mount.rsplit(":", 2)
            if source.startswith("${WP5_FIXTURE_ROOT:"):
                actual_binds.add((source, target, mode[0] if mode else ""))
            else:
                named_volumes.append((source, target))
        self.assertEqual(actual_binds, expected_binds)
        self.assertEqual(named_volumes, [("wp5-as-mtls-observer-data", "/opt/keycloak/data/h2")])
        mounted_text = "\n".join(service["volumes"])
        for forbidden in ("clients/", "route-a.key", "route-b.key", "metadata.key", "untrusted.key", "expired.key"):
            self.assertNotIn(forbidden, mounted_text)

    def test_runtime_attempt_uses_fresh_v3_identity_and_receipt_paths(self) -> None:
        self.assertEqual(runtime.IMAGE_TAG, "wp5-as-peer-observer:20261004-minimal-v3")
        self.assertEqual(runtime.IMAGE_ID, "sha256:3c89b8de02b358f39b0d2b7f47c1505a61087112f9ec81aed712f4b7db777953")
        self.assertTrue(str(runtime.FIXTURE_ROOT).endswith("wp5-as-mtls-observer-20261004-v3"))
        self.assertTrue(str(runtime.PREP_RECEIPT).endswith("prep-receipt-20261004-v3.json"))
        self.assertTrue(str(runtime.RUN_INTENT).endswith("run-intent-20261004-v3.json"))
        self.assertTrue(str(runtime.RUN_RECEIPT).endswith("run-receipt-20261004-v3.json"))


if __name__ == "__main__":
    unittest.main()
