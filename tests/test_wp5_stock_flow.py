import email.message
import http.cookiejar
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

from tests.harness.wp5_observer import stock_flow


INITIAL_LOCATION = (
    "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/auth"
    "?client_id=kong-fapi-pkj-mtls&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Afixture"
)
CALLBACK_LOCATION = (
    "https://localhost:8443/api/fapi/pkj-mtls?code=one%2Btwo&state=state-value"
)
ROUTE_A_INITIAL_LOCATION = (
    "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/auth"
    "?client_id=third-party-fapi-mtls&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Afixture-a"
)
ROUTE_A_CALLBACK_LOCATION = (
    "https://localhost:8443/api/fapi/mtls?code=a-code&state=a-state"
)


class FakeResponse:
    def __init__(self, status, headers=(), body=b""):
        self.code = status
        self.headers = email.message.Message()
        for name, value in headers:
            self.headers.add_header(name, value)
        self._body = io.BytesIO(body)

    def read(self, size=-1):
        return self._body.read(size)

    def info(self):
        return self.headers

    def close(self):
        self._body.close()


class FakeOpener:
    def __init__(self, cookie_jar, script):
        self.cookie_jar = cookie_jar
        self.script = script
        self.requests = []

    def open(self, request, timeout):
        self.cookie_jar.add_cookie_header(request)
        self.requests.append({
            "url": request.full_url,
            "method": request.get_method(),
            "body": request.data,
            "cookie": request.get_header("Cookie"),
            "timeout": timeout,
        })
        response = self.script(request)
        self.cookie_jar.extract_cookies(response, request)
        if response.code in stock_flow.REDIRECT_STATUSES:
            raise urllib.error.HTTPError(
                request.full_url, response.code, "redirect", response.headers, response._body,
            )
        return response


class StockFlowTests(unittest.TestCase):
    def test_issuer_probe_replaces_one_supplied_issuer_and_rejects_duplicates(self):
        callback = "https://localhost:8443/api/fapi/mtls?code=opaque&state=opaque&iss=https%3A%2F%2Flocalhost%3A8444"
        altered = stock_flow._mismatched_iss_url(callback)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(altered).query)
        self.assertEqual(query["iss"], ["https://wp5-mismatch.invalid/issuer"])
        self.assertEqual(query["code"], ["opaque"])
        with self.assertRaises(stock_flow._FlowFailure):
            stock_flow._mismatched_iss_url(callback + "&iss=duplicate")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ca_file = Path(self.temp.name) / "ca.crt"
        self.ca_file.write_text("unused fake CA")
        self.addCleanup(self.temp.cleanup)

    def _run(self, opener, *, location=INITIAL_LOCATION, cookies=(
        "wp5_stock_route_b_session=preauth; Path=/; Secure; HttpOnly",
    ), on_session_ready=None, profile="route_b", trigger_refresh=False, extended_flow=False):
        if on_session_ready is None:
            on_session_ready = lambda _timeout: True
        class FakeSSLContext:
            check_hostname = True
            verify_mode = None
            keylog_filename = None

            def load_verify_locations(self, **_kwargs):
                pass

            def set_alpn_protocols(self, _protocols):
                pass

        context = FakeSSLContext()
        with (
            mock.patch.object(stock_flow.ssl, "SSLContext", return_value=context),
            mock.patch.object(stock_flow.urllib.request, "build_opener", return_value=opener),
        ):
            return stock_flow.run_stock_flow(
                302, location, cookies, self.ca_file, "demo-user", "demo-password",
                on_session_ready=on_session_ready, on_sensitive_value=lambda _value: None,
                profile=profile, trigger_refresh=trigger_refresh, extended_flow=extended_flow,
            )

    def _main_script(self, events=None, *, profile="route_b", refresh=False):
        selected = stock_flow.FLOW_PROFILES[profile]
        initial_location = ROUTE_A_INITIAL_LOCATION if profile == "route_a" else INITIAL_LOCATION
        callback_location = ROUTE_A_CALLBACK_LOCATION if profile == "route_a" else CALLBACK_LOCATION
        callback_seen = False
        def script(request):
            nonlocal callback_seen
            url = request.full_url
            if url == initial_location and request.get_method() == "GET":
                return FakeResponse(200, body=(
                    b'<form action="https://localhost:8444/realms/fapi-demo/login-actions/auth?execution=e1" method="post">'
                    b'<input type="hidden" name="session_code" value="sensitive-csrf">'
                    b'<input name="username"><input type="password" name="password">'
                    b'<button name="login" value="Sign in">Sign in</button></form>'
                ))
            if "/login-actions/auth?execution=e1" in url and request.get_method() == "POST":
                return FakeResponse(302, [("Location", callback_location)])
            if (url == selected["callback_url"] and request.get_method() == "GET"
                and callback_seen and refresh):
                if events is not None:
                    events.append("protected-refresh")
                return FakeResponse(200, body=b"WP5_TRANSPORT_REFRESH_OK")
            if url == callback_location and request.get_method() == "GET":
                callback_seen = True
                return FakeResponse(302, [
                    ("Location", selected["login_terminal"]),
                    ("Set-Cookie", f"{selected['session_cookie']}=formed-session; Path=/; Secure; HttpOnly"),
                ])
            if url == selected["logout_url"] and request.get_method() == "GET":
                if events is not None:
                    events.append("logout")
                return FakeResponse(302, [("Location", "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/logout?id_token_hint=memory-only")])
            if url == "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/logout?id_token_hint=memory-only":
                return FakeResponse(302, [("Location", selected["logout_terminal"])])
            raise AssertionError("unexpected scripted request")
        return script

    def test_real_flow_preserves_callback_url_cookie_and_order_without_fetching_3443(self):
        events = []
        jar_holder = {}
        runtime_values = []

        def build_opener(*handlers):
            cookie_handler = next(
                handler for handler in handlers
                if isinstance(handler, stock_flow.urllib.request.HTTPCookieProcessor)
            )
            opener = FakeOpener(cookie_handler.cookiejar, self._main_script(events))
            jar_holder["opener"] = opener
            return opener

        def ready(timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, stock_flow.HTTP_TIMEOUT_SECONDS)
            events.append("session-ready")
            return True

        class FakeSSLContext:
            check_hostname = True
            verify_mode = None
            keylog_filename = None

            def load_verify_locations(self, **_kwargs):
                pass

            def set_alpn_protocols(self, _protocols):
                pass

        context = FakeSSLContext()
        with (
            mock.patch.object(stock_flow.ssl, "SSLContext", return_value=context),
            mock.patch.object(stock_flow.urllib.request, "build_opener", side_effect=build_opener),
        ):
            result = stock_flow.run_stock_flow(
                302, INITIAL_LOCATION,
                "wp5_stock_route_b_session=preauth; Path=/; Secure; HttpOnly",
                self.ca_file, "demo-user", "demo-password", on_session_ready=ready,
                on_sensitive_value=runtime_values.append,
            )

        opener = jar_holder["opener"]
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["outcome"], "complete")
        self.assertTrue(result["callback_completed"])
        self.assertTrue(result["session_cookie_changed"])
        self.assertTrue(result["phase_callback_called"])
        self.assertTrue(result["logout_completed"])
        self.assertNotIn("extended_evidence", result)
        self.assertLess(events.index("session-ready"), events.index("logout"))
        self.assertEqual(result["http_requests"], len(opener.requests) + 1)
        self.assertLessEqual(result["http_requests"], stock_flow.MAX_HTTP_REQUESTS)
        self.assertTrue(all(item["timeout"] <= stock_flow.HTTP_TIMEOUT_SECONDS for item in opener.requests))
        self.assertEqual(
            [item["url"] for item in opener.requests],
            [
                INITIAL_LOCATION,
                "https://localhost:8444/realms/fapi-demo/login-actions/auth?execution=e1",
                CALLBACK_LOCATION,
                stock_flow.LOGOUT_URL,
                "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/logout?id_token_hint=memory-only",
            ],
        )
        self.assertIn(f"{stock_flow.SESSION_COOKIE}=preauth", opener.requests[2]["cookie"])
        self.assertIn(f"{stock_flow.SESSION_COOKIE}=formed-session", opener.requests[3]["cookie"])
        self.assertNotIn("localhost:3443", " ".join(item["url"] for item in opener.requests))
        form = urllib.parse.parse_qs(opener.requests[1]["body"].decode("ascii"), keep_blank_values=True)
        self.assertEqual(form, {
            "session_code": ["sensitive-csrf"],
            "username": ["demo-user"],
            "password": ["demo-password"],
            "login": ["Sign in"],
        })
        self.assertNotIn("demo-password", json.dumps(result))
        self.assertNotIn("formed-session", json.dumps(result))
        collected = b"\n".join(runtime_values)
        self.assertIn(b"demo-password", collected)
        self.assertIn(b"one%2Btwo", collected)
        self.assertIn(b"formed-session", collected)
        self.assertIn(b"one+two", runtime_values)
        self.assertIn(b"state-value", runtime_values)
        self.assertIn(b"preauth", runtime_values)
        self.assertIn(b"formed-session", runtime_values)
        returned = json.dumps(result).encode("utf-8")
        self.assertNotIn(b"one+two", returned)
        self.assertNotIn(b"state-value", returned)
        self.assertNotIn(b"preauth", returned)
        self.assertNotIn(b"formed-session", returned)

    def test_untrusted_location_is_rejected_before_network(self):
        opener = FakeOpener(None, self._main_script())
        result = self._run(opener, location="https://attacker.invalid/auth")
        self.assertFalse(result["ok"])
        self.assertEqual(result["outcome"], "location_rejected")
        self.assertEqual(opener.requests, [])

    def test_callback_cookie_is_required_before_phase_transition_or_logout(self):
        def script(request):
            if request.full_url == INITIAL_LOCATION:
                return FakeResponse(200, body=(
                    b'<form action="https://localhost:8444/realms/fapi-demo/login-actions/auth" method="post">'
                    b'<input name="username"><input name="password" type="password"></form>'
                ))
            if request.full_url == "https://localhost:8444/realms/fapi-demo/login-actions/auth":
                return FakeResponse(302, [("Location", CALLBACK_LOCATION)])
            if request.full_url == CALLBACK_LOCATION:
                return FakeResponse(302, [("Location", stock_flow.LOGIN_TERMINAL)])
            raise AssertionError("logout must not run without a formed session")

        cookie_jar = http.cookiejar.CookieJar()
        opener = FakeOpener(cookie_jar, script)
        transitioned = []
        result = self._run(opener, on_session_ready=lambda: transitioned.append(True))
        self.assertEqual(result["outcome"], "session_cookie_missing")
        self.assertFalse(result["callback_completed"])
        self.assertEqual(transitioned, [])
        self.assertEqual(len(opener.requests), 3)

    def test_callback_http_error_returns_only_bounded_oauth_enum(self):
        login_action = "https://localhost:8444/realms/fapi-demo/login-actions/auth"
        for error_value, expected_enum in (
            ("invalid_client", "invalid_client"),
            ("private-server-message", "unknown"),
        ):
            with self.subTest(error_value=expected_enum):
                raw_marker = "never-return-this-description"

                def script(request):
                    if request.full_url == INITIAL_LOCATION:
                        return FakeResponse(200, body=(
                            f'<form action="{login_action}" method="post">'
                            '<input name="username"><input name="password" type="password"></form>'
                        ).encode("ascii"))
                    if request.full_url == login_action:
                        return FakeResponse(302, [("Location", CALLBACK_LOCATION)])
                    if request.full_url == CALLBACK_LOCATION:
                        body = json.dumps({
                            "error": error_value,
                            "error_description": raw_marker,
                            "private_detail": "another-private-value",
                        }).encode("utf-8")
                        return FakeResponse(400, body=body)
                    raise AssertionError("no follow-up request is allowed after callback failure")

                opener = FakeOpener(http.cookiejar.CookieJar(), script)
                transitioned = []
                result = self._run(
                    opener, on_session_ready=lambda _timeout: transitioned.append(True),
                )
                self.assertFalse(result["ok"])
                self.assertEqual(result["outcome"], "callback_rejected")
                self.assertEqual(result["callback_http_status"], 400)
                self.assertEqual(result["callback_error_enum"], expected_enum)
                self.assertEqual(result["status_4xx"], 1)
                self.assertEqual(transitioned, [])
                self.assertEqual(len(opener.requests), 3)
                returned = json.dumps(result)
                self.assertNotIn(raw_marker, returned)
                self.assertNotIn("another-private-value", returned)
                if expected_enum == "unknown":
                    self.assertNotIn(error_value, returned)

    def test_redirect_budget_is_finite_and_redirect_targets_are_not_fetched_unless_allowlisted(self):
        calls = []

        def script(request):
            calls.append(request.full_url)
            return FakeResponse(302, [("Location", "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/auth?loop=1")])

        opener = FakeOpener(http.cookiejar.CookieJar(), script)
        result = self._run(opener)
        self.assertEqual(result["outcome"], "budget_exceeded")
        self.assertEqual(len(calls), stock_flow.MAX_HTTP_REQUESTS)
        self.assertTrue(all(url.startswith("https://localhost:8444/") for url in calls))

    def test_route_a_profile_can_trigger_one_bounded_stock_refresh_before_logout(self):
        events = []
        opener_box = {}
        ready_calls = []

        def ready(timeout):
            ready_calls.append(timeout)
            events.append("session-ready")
            return True

        class FakeSSLContext:
            check_hostname = True
            verify_mode = None
            keylog_filename = None

            def load_verify_locations(self, **_kwargs):
                pass

            def set_alpn_protocols(self, _protocols):
                pass

        def build_opener(*handlers):
            cookie_handler = next(
                handler for handler in handlers
                if isinstance(handler, stock_flow.urllib.request.HTTPCookieProcessor)
            )
            opener = FakeOpener(
                cookie_handler.cookiejar,
                self._main_script(events, profile="route_a", refresh=True),
            )
            opener_box["opener"] = opener
            return opener

        with (
            mock.patch.object(stock_flow.ssl, "SSLContext", return_value=FakeSSLContext()),
            mock.patch.object(stock_flow.urllib.request, "build_opener", side_effect=build_opener),
            mock.patch.object(stock_flow.time, "sleep") as sleep,
        ):
            result = stock_flow.run_stock_flow(
                302, ROUTE_A_INITIAL_LOCATION,
                "fapi_route_a_session=preauth; Path=/; Secure; HttpOnly",
                self.ca_file, "demo-user", "demo-password", on_session_ready=ready,
                on_sensitive_value=lambda _value: None, profile="route_a", trigger_refresh=True,
            )

        opener = opener_box["opener"]
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["outcome"], "complete")
        self.assertTrue(result["callback_completed"])
        self.assertTrue(result["session_cookie_changed"])
        self.assertEqual(result["protected_refresh"], {
            "attempted": True, "http_status": 200, "completed": True,
        })
        self.assertEqual(len(ready_calls), 1)
        sleep.assert_called_once_with(stock_flow.REFRESH_WAIT_SECONDS)
        self.assertLess(events.index("session-ready"), events.index("protected-refresh"))
        self.assertLess(events.index("protected-refresh"), events.index("logout"))
        self.assertEqual(opener.requests[2]["url"], ROUTE_A_CALLBACK_LOCATION)
        self.assertEqual(opener.requests[3]["url"], stock_flow.FLOW_PROFILES["route_a"]["callback_url"])
        self.assertIn("fapi_route_a_session=formed-session", opener.requests[3]["cookie"])
        self.assertEqual(opener.requests[4]["url"], stock_flow.FLOW_PROFILES["route_a"]["logout_url"])
        self.assertLessEqual(result["http_requests"], stock_flow.MAX_HTTP_REQUESTS)
        returned = json.dumps(result)
        self.assertNotIn("demo-password", returned)
        self.assertNotIn("formed-session", returned)

    def test_extended_flow_probes_iss_on_copied_jar_then_refreshes_twice(self):
        selected = stock_flow.FLOW_PROFILES["transport_route_b"]
        initial = (
            "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/auth"
            "?client_id=third-party-fapi-pkj-mtls&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Av4"
        )
        callback = "https://localhost:8443/api/fapi/pkj-mtls?code=v4-code&state=v4-state"
        login_action = "https://localhost:8444/realms/fapi-demo/login-actions/auth?execution=v4"
        events = []
        openers = []

        def script(request):
            url = request.full_url
            if url == initial and request.get_method() == "GET":
                return FakeResponse(200, body=(
                    f'<form action="{login_action}" method="post">'
                    '<input name="username"><input type="password" name="password">'
                    '<button name="login" value="Sign in">Sign in</button></form>'
                ).encode("ascii"))
            if url == login_action and request.get_method() == "POST":
                return FakeResponse(302, [("Location", callback)])
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if url.startswith("https://localhost:8443/api/fapi/pkj-mtls?") and query.get("iss"):
                events.append("iss-mismatch")
                return FakeResponse(400, [
                    ("Set-Cookie", "fapi_route_b_session=; Max-Age=0; Path=/; Secure; HttpOnly"),
                ], b'{"error":"invalid_request","detail":"private-mismatch-detail"}')
            if url == callback:
                events.append("callback-control")
                return FakeResponse(302, [
                    ("Location", selected["login_terminal"]),
                    ("Set-Cookie", f"{selected['session_cookie']}=formed-session; Path=/; Secure; HttpOnly"),
                ])
            if url == selected["callback_url"] and request.get_method() == "GET":
                events.append("protected-refresh")
                return FakeResponse(200, body=b"WP5_TRANSPORT_REFRESH_OK")
            if url == selected["logout_url"]:
                events.append("logout")
                return FakeResponse(302, [(
                    "Location", "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/logout?id_token_hint=memory-only",
                )])
            if url == "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/logout?id_token_hint=memory-only":
                return FakeResponse(302, [("Location", selected["logout_terminal"])])
            raise AssertionError("unexpected extended-flow request")

        def build_opener(*handlers):
            cookie_handler = next(
                handler for handler in handlers
                if isinstance(handler, stock_flow.urllib.request.HTTPCookieProcessor)
            )
            opener = FakeOpener(cookie_handler.cookiejar, script)
            openers.append(opener)
            return opener

        class FakeSSLContext:
            check_hostname = True
            verify_mode = None
            keylog_filename = None

            def load_verify_locations(self, **_kwargs):
                pass

            def set_alpn_protocols(self, _protocols):
                pass

        with (
            mock.patch.object(stock_flow.ssl, "SSLContext", return_value=FakeSSLContext()),
            mock.patch.object(stock_flow.urllib.request, "build_opener", side_effect=build_opener),
            mock.patch.object(stock_flow.time, "sleep") as sleep,
        ):
            result = stock_flow.run_stock_flow(
                302, initial, "fapi_route_b_session=preauth; Path=/; Secure; HttpOnly",
                self.ca_file, "demo-user", "demo-password", on_session_ready=lambda _timeout: True,
                on_sensitive_value=lambda _value: None, profile="transport_route_b",
                trigger_refresh=True, extended_flow=True,
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(events, ["iss-mismatch", "callback-control", "protected-refresh",
                                  "protected-refresh", "logout"])
        self.assertEqual(len(openers), 2)
        mismatch_opener = next(opener for opener in openers if len(opener.requests) == 1)
        control_opener = next(opener for opener in openers if len(opener.requests) > 1)
        self.assertIn("iss=https%3A%2F%2Fwp5-mismatch.invalid%2Fissuer", mismatch_opener.requests[0]["url"])
        self.assertIn("fapi_route_b_session=preauth", mismatch_opener.requests[0]["cookie"])
        self.assertIn("fapi_route_b_session=preauth", control_opener.requests[2]["cookie"])
        self.assertIn("fapi_route_b_session=formed-session", control_opener.requests[3]["cookie"])
        self.assertEqual(sleep.call_args_list, [mock.call(stock_flow.REFRESH_WAIT_SECONDS)] * 2)
        self.assertEqual(result["extended_evidence"], {
            "initial_redirect_query": {
                "query_names": ["client_id", "request_uri"], "only_expected_names": True,
                "client_id_matches": True, "request_uri_present": True,
            },
            "callback_iss_mismatch": {"attempted": True, "http_status": 400, "rejected": True},
            "protected_refresh_gets": 2,
            "refresh_waits": 2,
        })
        returned = json.dumps(result)
        for secret in ("demo-password", "v4-code", "v4-state", "private-mismatch-detail", "formed-session"):
            self.assertNotIn(secret, returned)

    def test_extended_flow_rejects_non_stock_initial_query_before_network(self):
        opener = FakeOpener(None, self._main_script())
        location = INITIAL_LOCATION + "&state=unexpected"
        result = self._run(opener, location=location, trigger_refresh=True, extended_flow=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["outcome"], "location_rejected")
        self.assertEqual(opener.requests, [])

    def test_unknown_profile_is_rejected_before_network(self):
        opener = FakeOpener(None, self._main_script())
        result = self._run(opener, profile="route_c")
        self.assertFalse(result["ok"])
        self.assertEqual(result["outcome"], "input_rejected")
        self.assertEqual(opener.requests, [])


if __name__ == "__main__":
    unittest.main()
