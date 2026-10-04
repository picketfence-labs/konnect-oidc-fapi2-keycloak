#!/usr/bin/env python3
"""Offline trust-boundary tests for the WP5 stock OIDC relay."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RELAY_PATH = ROOT / "tests/harness/wp5_observer/stock_relay.py"
HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None
relay = None
if HAS_CRYPTOGRAPHY:
    spec = importlib.util.spec_from_file_location("wp5_stock_relay_test", RELAY_PATH)
    assert spec is not None and spec.loader is not None
    relay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relay)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class StockRelayCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HAS_CRYPTOGRAPHY:
            raise unittest.SkipTest("cryptography is available only in the cached WP2 test venv")
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        cls.hashes = hashes
        cls.serialization = serialization
        cls.padding = padding
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.kid = "wp5-stock-relay-test-key"
        cls._temp = tempfile.TemporaryDirectory(prefix="wp5-stock-relay-test-")
        cls.root = Path(cls._temp.name)
        os.chmod(cls.root, 0o700)
        keys = cls.root / "keys"
        keys.mkdir(mode=0o700)
        public_bytes = cls.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_path = keys / "route-b-public.pem"
        public_path.write_bytes(public_bytes)
        os.chmod(public_path, 0o600)
        kid_path = keys / "route-b-kid.txt"
        kid_path.write_text(cls.kid + "\n", encoding="ascii")
        os.chmod(kid_path, 0o600)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "_temp", None) is not None:
            cls._temp.cleanup()

    def setUp(self):
        self.state = relay.RelayState(self.root)

    @classmethod
    def token(cls, claims: dict[str, object] | None = None, *, header: dict[str, object] | None = None,
              raw_header: bytes | None = None, raw_claims: bytes | None = None) -> str:
        now = int(time.time())
        if claims is None:
            claims = {
                "iss": relay.CLIENT_ID,
                "sub": relay.CLIENT_ID,
                "aud": relay.ISSUER,
                "iat": now - 10,
                "exp": now + 50,
                "jti": "wp5-jti-" + str(time.time_ns()),
            }
        if header is None:
            header = {"alg": "PS256", "kid": cls.kid}
        protected = raw_header if raw_header is not None else json.dumps(
            header, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        payload = raw_claims if raw_claims is not None else json.dumps(
            claims, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        encoded_header = b64url(protected)
        encoded_payload = b64url(payload)
        signing_input = (encoded_header + "." + encoded_payload).encode("ascii")
        signature = cls.private_key.sign(
            signing_input,
            cls.padding.PSS(mgf=cls.padding.MGF1(cls.hashes.SHA256()), salt_length=32),
            cls.hashes.SHA256(),
        )
        return signing_input.decode("ascii") + "." + b64url(signature)

    @staticmethod
    def par_form(assertion: str) -> bytes:
        return urllib.parse.urlencode(
            [
                ("client_id", relay.CLIENT_ID),
                ("client_assertion_type", relay.ASSERTION_TYPE),
                ("client_assertion", assertion),
                ("response_type", "code"),
                ("redirect_uri", "https://client.example/callback"),
                ("scope", "openid"),
                ("state", "test-state"),
                ("nonce", "test-nonce"),
                ("response_mode", "query"),
                ("code_challenge", "A" * 43),
                ("code_challenge_method", "S256"),
            ]
        ).encode("ascii")

    @staticmethod
    def revoke_form(assertion: str, token: str, hint: str) -> bytes:
        return urllib.parse.urlencode(
            [
                ("client_id", relay.CLIENT_ID),
                ("client_assertion_type", relay.ASSERTION_TYPE),
                ("client_assertion", assertion),
                ("token", token),
                ("token_type_hint", hint),
            ]
        ).encode("ascii")

    def call(self, operation: str, body: bytes):
        return self.state.process(operation, body, "application/x-www-form-urlencoded")

    def prime_session_logout(self, relay_mock) -> None:
        relay_mock.return_value = (201, [("Content-Type", "application/json")], b'{"request_uri":"urn:test"}')
        status, _headers, _body = self.call("par", self.par_form(self.token()))
        self.assertEqual(status, 201)
        self.assertEqual(self.state.snapshot()["stage"], "par_complete")

    def test_actual_ps256_signature_and_required_claims_are_checked(self):
        now = 1_800_000_000
        claims = {
            "iss": relay.CLIENT_ID,
            "sub": relay.CLIENT_ID,
            "aud": relay.ISSUER,
            "iat": now - 10,
            "exp": now + 50,
            "jti": "jti-valid",
        }
        token = self.token(claims)
        summary = relay.verify_stock_assertion(token, self.private_key.public_key(), self.kid, now=now)
        self.assertEqual(summary["algorithm"], "PS256")
        self.assertTrue(summary["audience_is_issuer"])
        self.assertTrue(summary["issuer_subject_match"])
        self.assertEqual(summary["ttl_seconds"], 60)
        self.assertEqual(summary["remaining_ttl_seconds"], 50)

        header, payload, signature = token.split(".")
        altered = ("A" if signature[0] != "A" else "B") + signature[1:]
        with self.assertRaisesRegex(relay.RelayError, "assertion_signature"):
            relay.verify_stock_assertion(header + "." + payload + "." + altered,
                                         self.private_key.public_key(), self.kid, now=now)

    def test_audience_array_identity_future_iat_and_kid_are_rejected(self):
        now = 1_800_000_000
        cases = (
            ({"aud": [relay.ISSUER]}, {"alg": "PS256", "kid": self.kid}, "assertion_audience"),
            ({"iss": "other-client"}, {"alg": "PS256", "kid": self.kid}, "assertion_identity"),
            ({"sub": "other-client"}, {"alg": "PS256", "kid": self.kid}, "assertion_identity"),
            ({"iat": now + 1, "exp": now + 50}, {"alg": "PS256", "kid": self.kid}, "assertion_future_iat"),
            ({}, {"alg": "PS256", "kid": "wrong-kid"}, "assertion_header"),
        )
        for overrides, header, code in cases:
            with self.subTest(code=code, overrides=overrides):
                claims = {
                    "iss": relay.CLIENT_ID,
                    "sub": relay.CLIENT_ID,
                    "aud": relay.ISSUER,
                    "iat": now - 10,
                    "exp": now + 50,
                    "jti": "jti-case",
                    **overrides,
                }
                with self.assertRaises(relay.RelayError) as caught:
                    relay.verify_stock_assertion(
                        self.token(claims, header=header), self.private_key.public_key(), self.kid, now=now,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_expired_long_ttl_and_short_remaining_lifetime_are_rejected(self):
        now = 1_800_000_000
        cases = (
            ({"iat": now - 20, "exp": now - 1}, "assertion_ttl"),
            ({"iat": now, "exp": now + 61}, "assertion_ttl"),
            ({"iat": now - 10, "exp": now + 4}, "assertion_ttl"),
        )
        for overrides, code in cases:
            claims = {
                "iss": relay.CLIENT_ID,
                "sub": relay.CLIENT_ID,
                "aud": relay.ISSUER,
                "iat": now - 10,
                "exp": now + 50,
                "jti": "jti-time-case",
                **overrides,
            }
            with self.subTest(overrides=overrides):
                with self.assertRaises(relay.RelayError) as caught:
                    relay.verify_stock_assertion(
                        self.token(claims), self.private_key.public_key(), self.kid, now=now,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_duplicate_json_keys_fail_before_signature_acceptance(self):
        now = 1_800_000_000
        claims = {
            "iss": relay.CLIENT_ID,
            "sub": relay.CLIENT_ID,
            "aud": relay.ISSUER,
            "iat": now - 10,
            "exp": now + 50,
            "jti": "jti-duplicate-json",
        }
        raw_header = b'{"alg":"PS256","kid":"wp5-stock-relay-test-key","alg":"PS256"}'
        raw_claims = json.dumps(claims, separators=(",", ":")).replace(
            '"iss":"' + relay.CLIENT_ID + '",',
            '"iss":"' + relay.CLIENT_ID + '","iss":"' + relay.CLIENT_ID + '",',
            1,
        ).encode("utf-8")
        for token in (self.token(claims, raw_header=raw_header), self.token(raw_claims=raw_claims)):
            with self.assertRaises(relay.RelayError) as caught:
                relay.verify_stock_assertion(token, self.private_key.public_key(), self.kid, now=now)
            self.assertEqual(caught.exception.code, "assertion_duplicate_json_key")

    def test_deep_json_fails_closed_with_sanitized_nonpending_event(self):
        nested = b"[" * 2000 + b"0" + b"]" * 2000
        now = int(time.time())
        deep_claims = (
            b'{"iss":"' + relay.CLIENT_ID.encode()
            + b'","sub":"' + relay.CLIENT_ID.encode()
            + b'","aud":"' + relay.ISSUER.encode()
            + b'","iat":' + str(now - 10).encode()
            + b',"exp":' + str(now + 50).encode()
            + b',"jti":"deep-json-case","extra":' + nested + b'}'
        )
        token = self.token(raw_claims=deep_claims)
        form = self.par_form(token)
        with mock.patch.object(relay, "relay_once") as sender, \
                mock.patch.object(relay.json, "loads", side_effect=RecursionError):
            status, _headers, body = self.call("par", form)
        snapshot = self.state.snapshot()
        self.assertEqual(status, 400)
        self.assertEqual(body, b'{"error":"invalid_request"}')
        self.assertTrue(snapshot["failed"])
        self.assertEqual(snapshot["events"][-1]["result"], "assertion_json")
        self.assertFalse(snapshot["events"][-1]["forwarded"])
        self.assertEqual(snapshot["events"][-1]["http_status"], 0)
        sender.assert_not_called()

    def test_duplicate_form_parameters_are_rejected(self):
        assertion = self.token()
        body = self.par_form(assertion).decode("ascii")
        duplicated_assertion = body + "&client_assertion=" + urllib.parse.quote(assertion)
        duplicate_client = body + "&client_id=" + urllib.parse.quote(relay.CLIENT_ID)
        for raw in (duplicated_assertion.encode("ascii"), duplicate_client.encode("ascii")):
            with self.assertRaises(relay.RelayError) as caught:
                relay.parse_stock_form(raw, "application/x-www-form-urlencoded", "par")
            self.assertEqual(caught.exception.code, "duplicate_form_parameter")

    def test_revoke_form_client_id_may_be_absent_but_present_value_must_match(self):
        assertion = self.token()
        body = self.revoke_form(assertion, "opaque-access-token", "access_token").decode("ascii")
        without_id = body.replace("client_id=" + relay.CLIENT_ID + "&", "", 1)
        parsed = relay.parse_stock_form(without_id.encode("ascii"), "application/x-www-form-urlencoded", "revoke")
        self.assertEqual(parsed, (assertion, "access_token", hashlib.sha256(b"opaque-access-token").digest(), False))
        mismatched = body.replace("client_id=" + relay.CLIENT_ID, "client_id=other")
        with self.assertRaises(relay.RelayError) as caught:
            relay.parse_stock_form(mismatched.encode("ascii"), "application/x-www-form-urlencoded", "revoke")
        self.assertEqual(caught.exception.code, "revoke_form")

    def test_form_parser_returns_only_assertion_and_does_not_return_par_secrets(self):
        assertion = self.token()
        parsed = relay.parse_stock_form(self.par_form(assertion), "application/x-www-form-urlencoded; charset=UTF-8", "par")
        self.assertEqual(parsed, (assertion, None, None, True))

    def test_par_form_client_id_may_be_absent_but_present_value_must_match(self):
        assertion = self.token()
        with_id = self.par_form(assertion).decode("ascii")
        without_id = with_id.replace("client_id=" + relay.CLIENT_ID + "&", "", 1)
        self.assertEqual(
            relay.parse_stock_form(without_id.encode("ascii"), "application/x-www-form-urlencoded", "par"),
            (assertion, None, None, False),
        )
        with self.assertRaises(relay.RelayError) as caught:
            relay.parse_stock_form(
                with_id.replace("client_id=" + relay.CLIENT_ID, "client_id=other").encode("ascii"),
                "application/x-www-form-urlencoded", "par",
            )
        self.assertEqual(caught.exception.code, "par_client_id")

    def test_stock_default_query_response_mode_is_allowed_but_nonquery_and_bad_contracts_are_distinct(self):
        assertion = self.token()
        accepted = self.par_form(assertion)
        self.assertEqual(
            relay.parse_stock_form(accepted, "application/x-www-form-urlencoded", "par"),
            (assertion, None, None, True),
        )

        base = accepted.decode("ascii")
        cases = (
            (base.replace("response_mode=query", "response_mode=form_post"), "par_response_mode"),
            (base + "&unexpected=fixed", "par_unknown_field"),
            (base.replace("client_id=" + relay.CLIENT_ID, "client_id=other"), "par_client_id"),
            (base.replace("response_type=code", "response_type=token"), "par_response_type"),
        )
        for form, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(relay.RelayError) as caught:
                    relay.parse_stock_form(form.encode("ascii"), "application/x-www-form-urlencoded", "par")
                self.assertEqual(caught.exception.code, expected)

    def test_par_201_is_the_only_accepted_success_and_200_cannot_advance_stage(self):
        with mock.patch.object(relay, "relay_once", return_value=(200, [], b"{}")) as sender:
            status, _headers, _body = self.call("par", self.par_form(self.token()))
        snapshot = self.state.snapshot()
        self.assertEqual(status, 200)
        self.assertTrue(snapshot["failed"])
        self.assertEqual(snapshot["stage"], "par_claim_gate")
        self.assertEqual(snapshot["events"][-1]["result"], "as_rejected")
        self.assertTrue(snapshot["events"][-1]["forwarded"])
        sender.assert_called_once()

        accepted = relay.RelayState(self.root)
        with mock.patch.object(relay, "relay_once", return_value=(201, [], b"{}")):
            status, _headers, _body = accepted.process(
                "par", self.par_form(self.token()), "application/x-www-form-urlencoded",
            )
        self.assertEqual(status, 201)
        self.assertFalse(accepted.snapshot()["failed"])
        self.assertEqual(accepted.snapshot()["stage"], "par_complete")

    def test_accepted_stock_par_body_and_assertion_are_forwarded_unchanged(self):
        assertion = self.token()
        original = self.par_form(assertion)
        stock_body = original.replace(("client_id=" + relay.CLIENT_ID + "&").encode("ascii"), b"", 1)
        with mock.patch.object(relay, "relay_once", return_value=(201, [], b"{}")) as sender:
            status, _headers, _body = self.call("par", stock_body)
        self.assertEqual(status, 201)
        args = sender.call_args.args
        self.assertEqual(args[0], stock_body)
        self.assertEqual(args[5], assertion)
        event = self.state.snapshot()["events"][0]
        self.assertFalse(event["stock_form_client_id_present"])
        self.assertTrue(event["forwarded"])

    def test_fresh_assertion_cannot_repeat_par_or_revoke_token_or_hint(self):
        with mock.patch.object(relay, "relay_once", return_value=(201, [], b"{}")) as sender:
            self.prime_session_logout(sender)
            status, _headers, _body = self.call("par", self.par_form(self.token()))
            self.assertEqual(status, 400)
            self.assertEqual(self.state.snapshot()["stage"], "par_complete")
            self.assertTrue(self.state.snapshot()["failed"])
            self.assertEqual(len(self.state.snapshot()["events"]), 1)
            self.assertEqual(self.state.snapshot()["events"][-1]["result"], "as_accepted")
            self.assertEqual(sender.call_count, 1)

        same_token_state = relay.RelayState(self.root)
        def successful_endpoint(_raw_body, operation, *_args):
            return (201 if operation == "par" else 200, [], b"{}")

        with mock.patch.object(relay, "relay_once", side_effect=successful_endpoint) as sender:
            status, _headers, _body = same_token_state.process(
                "par", self.par_form(self.token()), "application/x-www-form-urlencoded",
            )
            self.assertEqual(status, 201)
            same_token_state.stage = "session_logout"
            first = same_token_state.process(
                "revoke", self.revoke_form(self.token(), "opaque-access-1", "access_token"),
                "application/x-www-form-urlencoded",
            )
            second = same_token_state.process(
                "revoke", self.revoke_form(self.token(), "opaque-access-1", "access_token"),
                "application/x-www-form-urlencoded",
            )
            self.assertEqual(first[0], 200)
            self.assertEqual(second[0], 400)
            self.assertEqual(same_token_state.snapshot()["events"][-1]["result"], "revoke_token_replay")
            self.assertEqual(sender.call_count, 2)

        same_hint_state = relay.RelayState(self.root)
        with mock.patch.object(relay, "relay_once", side_effect=successful_endpoint) as sender:
            same_hint_state.stage = "session_logout"
            self.assertEqual(
                same_hint_state.process(
                    "revoke", self.revoke_form(self.token(), "opaque-access-2", "access_token"),
                    "application/x-www-form-urlencoded",
                )[0],
                200,
            )
            retry = same_hint_state.process(
                "revoke", self.revoke_form(self.token(), "opaque-access-3", "access_token"),
                "application/x-www-form-urlencoded",
            )
            self.assertEqual(retry[0], 400)
            self.assertEqual(same_hint_state.snapshot()["events"][-1]["result"], "revoke_kind_replay")
            self.assertEqual(sender.call_count, 1)

    def test_distinct_access_and_refresh_revokes_are_allowed_and_events_hide_tokens(self):
        state = relay.RelayState(self.root)
        state.stage = "session_logout"
        with mock.patch.object(relay, "relay_once", return_value=(200, [], b"")) as sender:
            access = state.process(
                "revoke", self.revoke_form(self.token(), "opaque-access-4", "access_token"),
                "application/x-www-form-urlencoded",
            )
            refresh = state.process(
                "revoke", self.revoke_form(self.token(), "opaque-refresh-5", "refresh_token"),
                "application/x-www-form-urlencoded",
            )
        self.assertEqual((access[0], refresh[0]), (200, 200))
        snapshot = state.snapshot()
        self.assertFalse(snapshot["failed"])
        self.assertEqual([event["token_kind"] for event in snapshot["events"]], ["access_token", "refresh_token"])
        self.assertEqual(sender.call_count, 2)
        self.assertTrue(all(set(event) == set(relay.EVENT_FIELDS) for event in snapshot["events"]))
        serialized = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("opaque-access-4", serialized)
        self.assertNotIn("opaque-refresh-5", serialized)

    def test_event_capacity_overflow_fails_and_never_forwards(self):
        state = relay.RelayState(self.root)
        state.events = [{"result": "prior"} for _ in range(relay.MAX_EVENTS)]
        with mock.patch.object(relay, "relay_once") as sender:
            status, _headers, _body = state.process(
                "par", self.par_form(self.token()), "application/x-www-form-urlencoded",
            )
        snapshot = state.snapshot()
        self.assertEqual(status, 400)
        self.assertTrue(snapshot["failed"])
        self.assertTrue(snapshot["overflow"])
        self.assertEqual(len(snapshot["events"]), relay.MAX_EVENTS)
        sender.assert_not_called()

    def test_form_body_is_forwarded_byte_for_byte_with_a_fixed_header_allowlist(self):
        assertion = self.token()
        raw_body = self.par_form(assertion)
        fake_socket = mock.Mock()
        fake_raw_socket = mock.Mock()
        fake_context = mock.Mock()
        fake_context.wrap_socket.return_value = fake_socket
        fake_response = mock.Mock()
        fake_response.status = 201
        fake_response.read.return_value = b'{"request_uri":"urn:test"}'
        fake_response.getheaders.return_value = [
            ("Content-Type", "application/json"),
            ("Set-Cookie", "private=never-forward"),
            ("X-Unlisted", "discard"),
        ]
        order: list[str] = []
        fake_raw_socket.settimeout.side_effect = lambda _timeout: None
        fake_socket.settimeout.side_effect = lambda _timeout: None
        fake_socket.sendall.side_effect = lambda _wire: order.append("send")
        fake_raw_socket.connect = mock.Mock(side_effect=lambda *_args, **_kwargs: order.append("connect"))
        with mock.patch.object(relay, "_relay_context", return_value=fake_context), \
                mock.patch.object(relay.socket, "create_connection", return_value=fake_raw_socket), \
                mock.patch.object(relay.http.client, "HTTPResponse", return_value=fake_response), \
                mock.patch.object(relay.threading, "Timer", autospec=True) as timer_factory, \
                mock.patch.object(relay, "verify_stock_assertion", wraps=relay.verify_stock_assertion) as verifier:
            result = relay.relay_once(
                raw_body, "par", "0123456789abcdef0123456789abcdef",
                {"ca": Path("/unused/ca"), "route_cert": Path("/unused/cert"), "route_key": Path("/unused/key")},
                "application/x-www-form-urlencoded", assertion, self.private_key.public_key(), self.kid,
            )
        self.assertEqual(result, (201, [("Content-Type", "application/json")], b'{"request_uri":"urn:test"}'))
        sent = fake_socket.sendall.call_args.args[0]
        headers, body = sent.split(b"\r\n\r\n", 1)
        self.assertEqual(body, raw_body)
        self.assertIn(b"POST " + relay.PAR_PATH.encode() + b" HTTP/1.1", headers)
        self.assertIn(b"X-Fapi-Demo-Observation-ID: 0123456789abcdef0123456789abcdef", headers)
        self.assertEqual(verifier.call_count, 1)
        self.assertEqual(order, ["send"])
        timer_factory.assert_called_once()
        self.assertGreater(timer_factory.call_args.args[0], 0)
        self.assertLessEqual(timer_factory.call_args.args[0], relay.MAX_REQUEST_SECONDS)
        timer_factory.return_value.start.assert_called_once()
        timer_factory.return_value.cancel.assert_called_once()
        fake_socket.close.assert_called_once()
        fake_raw_socket.close.assert_not_called()


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is available only in the cached WP2 test venv")
class RelayDeadlineTests(unittest.TestCase):
    class TimerProbe:
        def __init__(self, interval, function):
            self.interval = interval
            self.function = function
            self.daemon = False
            self.started = False
            self.cancelled = False

        def start(self):
            self.started = True

        def cancel(self):
            self.cancelled = True

        def fire(self):
            self.function()

    def test_upstream_absolute_deadline_consumes_connect_and_handshake_time(self):
        # This suite's crypto fixture owns the signed input, but the clock test itself
        # never opens a socket or performs a TLS handshake.
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # The exact clock edge is tested by expiring between socket setup and the
        # post-handshake remaining-time check. No HTTP request may be sent.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        now = int(time.time())
        claims = {"iss": relay.CLIENT_ID, "sub": relay.CLIENT_ID, "aud": relay.ISSUER,
                  "iat": now - 10, "exp": now + 50, "jti": "deadline-test"}
        header = {"alg": "PS256", "kid": "deadline-kid"}
        encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
        encoded_claims = b64url(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = (encoded_header + "." + encoded_claims).encode("ascii")
        signature = private_key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        assertion = signing_input.decode("ascii") + "." + b64url(signature)
        raw_socket = mock.Mock()
        wrapped_socket = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = wrapped_socket
        clock_values = iter((100.0, 101.0, 102.0, 111.0))
        with mock.patch.object(relay, "_relay_context", return_value=context), \
                mock.patch.object(relay.socket, "create_connection", return_value=raw_socket) as connect, \
                mock.patch.object(relay.time, "monotonic", side_effect=lambda: next(clock_values)), \
                mock.patch.object(relay, "verify_stock_assertion", wraps=relay.verify_stock_assertion) as verifier:
            with self.assertRaises(relay.RelayError) as caught:
                relay.relay_once(
                    b"body", "par", "0123456789abcdef0123456789abcdef",
                    {"ca": Path("/ca"), "route_cert": Path("/cert"), "route_key": Path("/key")},
                    "application/x-www-form-urlencoded", assertion, private_key.public_key(), "deadline-kid",
                )
        self.assertEqual(caught.exception.code, "as_deadline_exceeded")
        connect.assert_called_once_with(("keycloak", 8443), timeout=9.0)
        raw_socket.settimeout.assert_called_once_with(8.0)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="keycloak")
        verifier.assert_not_called()
        wrapped_socket.sendall.assert_not_called()
        wrapped_socket.close.assert_called_once()

    def test_inbound_connection_deadline_interrupts_socket_and_is_cancelled_on_finish(self):
        handler = relay.RelayHandler.__new__(relay.RelayHandler)
        handler.connection = mock.Mock()
        timer = self.TimerProbe(relay.MAX_REQUEST_SECONDS, handler._interrupt_client)
        with mock.patch.object(relay.BaseHTTPRequestHandler, "setup", autospec=True) as base_setup, \
                mock.patch.object(relay.BaseHTTPRequestHandler, "finish", autospec=True) as base_finish, \
                mock.patch.object(relay.threading, "Timer", return_value=timer) as timer_factory:
            handler.setup()
            base_setup.assert_called_once_with(handler)
            self.assertEqual(timer_factory.call_args.args[0], relay.MAX_REQUEST_SECONDS)
            self.assertTrue(timer.started)
            timer.fire()
            handler.connection.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            handler.finish()
            self.assertTrue(timer.cancelled)
            base_finish.assert_called_once_with(handler)


if __name__ == "__main__":
    unittest.main()
