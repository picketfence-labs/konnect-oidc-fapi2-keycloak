#!/usr/bin/env python3
"""Bounded, memory-only browser flow for the stock WP5 Route B fixture."""

from __future__ import annotations

import http.cookiejar
import http.cookies
import copy
import importlib.util
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Callable, Iterable


HERE = Path(__file__).resolve().parent
WP2_FLOW = HERE.parent / "wp2_flow.py"
_WP2_SPEC = importlib.util.spec_from_file_location("_wp2_stock_flow_forms", WP2_FLOW)
if _WP2_SPEC is None or _WP2_SPEC.loader is None:
    raise RuntimeError("wp2_flow_unavailable")
_WP2_MODULE = importlib.util.module_from_spec(_WP2_SPEC)
_WP2_SPEC.loader.exec_module(_WP2_MODULE)
LoginForms = _WP2_MODULE.LoginForms


KEYCLOAK_ORIGIN = "https://localhost:8444"
FLOW_PROFILES = {
    "route_a": {
        "callback_url": "https://localhost:8443/api/fapi/mtls",
        "callback_path": "/api/fapi/mtls",
        "logout_url": "https://localhost:8443/api/fapi/mtls/logout",
        "session_cookie": "fapi_route_a_session",
        "login_terminal": "https://localhost:3443/?authenticated=route-a",
        "logout_terminal": "https://localhost:3443/?logout=route-a",
        "refresh_status": 200,
        "refresh_body": b"WP5_TRANSPORT_REFRESH_OK",
    },
    "route_b": {
        "callback_url": "https://localhost:8443/api/fapi/pkj-mtls",
        "callback_path": "/api/fapi/pkj-mtls",
        "logout_url": "https://localhost:8443/api/fapi/pkj-mtls/logout",
        "session_cookie": "wp5_stock_route_b_session",
        "login_terminal": "https://localhost:3443/?authenticated=route-b",
        "logout_terminal": "https://localhost:3443/?logout=route-b",
    },
    "transport_route_b": {
        "callback_url": "https://localhost:8443/api/fapi/pkj-mtls",
        "callback_path": "/api/fapi/pkj-mtls",
        "logout_url": "https://localhost:8443/api/fapi/pkj-mtls/logout",
        "session_cookie": "fapi_route_b_session",
        "login_terminal": "https://localhost:3443/?authenticated=route-b",
        "logout_terminal": "https://localhost:3443/?logout=route-b",
        "refresh_status": 200,
        "refresh_body": b"WP5_TRANSPORT_REFRESH_OK",
    },
}
EXPECTED_CLIENT_IDS = {
    "route_a": "third-party-fapi-mtls",
    "route_b": "third-party-fapi-pkj-mtls",
    "transport_route_b": "third-party-fapi-pkj-mtls",
}
CALLBACK_URL = FLOW_PROFILES["route_b"]["callback_url"]
LOGOUT_URL = FLOW_PROFILES["route_b"]["logout_url"]
SESSION_COOKIE = FLOW_PROFILES["route_b"]["session_cookie"]
LOGIN_TERMINAL = FLOW_PROFILES["route_b"]["login_terminal"]
LOGOUT_TERMINAL = FLOW_PROFILES["route_b"]["logout_terminal"]
REFRESH_WAIT_SECONDS = 6.0

MAX_HTTP_REQUESTS = 10
HTTP_TIMEOUT_SECONDS = 10
TOTAL_TIMEOUT_SECONDS = 60
MAX_HTML_BYTES = 1024 * 1024
MAX_FORM_BYTES = 1024 * 1024
MAX_LOCATION_CHARS = 16 * 1024
MAX_COOKIE_HEADERS = 16
MAX_COOKIE_CHARS = 16 * 1024
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
OAUTH_ERROR_ENUMS = frozenset({
    "invalid_client", "invalid_grant", "invalid_request", "invalid_scope",
    "invalid_token", "unauthorized_client", "unsupported_grant_type",
    "unsupported_response_type", "access_denied", "server_error",
    "temporarily_unavailable",
})
SENSITIVE_QUERY_NAMES = frozenset({"code", "state", "request_uri", "id_token_hint"})
SENSITIVE_COOKIE_NAMES = frozenset({
    SESSION_COOKIE,
    FLOW_PROFILES["route_a"]["session_cookie"],
    FLOW_PROFILES["transport_route_b"]["session_cookie"],
    "AUTH_SESSION_ID", "AUTH_SESSION_ID_LEGACY", "AUTH_SESSION_ID_HASH",
    "KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION", "KEYCLOAK_SESSION_LEGACY",
    "KEYCLOAK_REMEMBER_ME", "KC_RESTART", "KC_AUTH_STATE", "KC_AUTH_STATE_HASH",
    "KC_AUTH_SESSION_HASH",
})
OUTCOMES = frozenset({
    "complete",
    "initial_response_rejected",
    "input_rejected",
    "location_rejected",
    "cookie_rejected",
    "transport_failure",
    "http_failure",
    "form_rejected",
    "callback_rejected",
    "session_cookie_missing",
    "phase_callback_failed",
    "secret_collector_failed",
    "logout_rejected",
    "refresh_trigger_rejected",
    "budget_exceeded",
    "internal_failure",
})


class _FlowFailure(Exception):
    def __init__(self, outcome: str):
        self.outcome = outcome if outcome in OUTCOMES else "internal_failure"
        super().__init__(self.outcome)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class _InitialCookieResponse:
    def __init__(self, headers: Message):
        self._headers = headers

    def info(self):
        return self._headers


def _result() -> dict[str, object]:
    return {
        "ok": False,
        "outcome": "internal_failure",
        "http_requests": 0,
        "redirects": 0,
        "status_2xx": 0,
        "status_3xx": 0,
        "status_4xx": 0,
        "status_5xx": 0,
        "login_submissions": 0,
        "consent_submissions": 0,
        "callback_completed": False,
        "callback_http_status": 0,
        "callback_error_enum": "none",
        "session_cookie_changed": False,
        "phase_callback_called": False,
        "logout_completed": False,
    }


def _headers_values(headers: Message, name: str) -> list[str]:
    values = headers.get_all(name, [])
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str)]


def _url_parts(value: str):
    if not isinstance(value, str) or not value or len(value) > MAX_LOCATION_CHARS:
        raise _FlowFailure("location_rejected")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise _FlowFailure("location_rejected") from None
    if (parsed.scheme != "https" or parsed.hostname != "localhost" or parsed.username
        or parsed.password or parsed.fragment or port is None):
        raise _FlowFailure("location_rejected")
    return parsed, port


def _is_keycloak_url(value: str) -> bool:
    parsed, port = _url_parts(value)
    return port == 8444 and parsed.path.startswith("/realms/fapi-demo/")


def _validate_initial_location(value: str, profile: str = "route_b") -> str:
    if profile not in FLOW_PROFILES:
        raise _FlowFailure("location_rejected")
    if not _is_keycloak_url(value):
        raise _FlowFailure("location_rejected")
    parsed, _ = _url_parts(value)
    if parsed.path != "/realms/fapi-demo/protocol/openid-connect/auth":
        raise _FlowFailure("location_rejected")
    return value


def _initial_redirect_summary(value: str, profile: str) -> dict[str, object]:
    parsed, _port = _url_parts(value)
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4,
        )
    except ValueError:
        raise _FlowFailure("location_rejected") from None
    names = [name for name, _item in pairs]
    values = dict(pairs) if len(pairs) == 2 else {}
    exact = len(pairs) == 2 and sorted(names) == ["client_id", "request_uri"]
    summary = {
        "query_names": ["client_id", "request_uri"] if exact else [],
        "only_expected_names": exact,
        "client_id_matches": exact and values.get("client_id") == EXPECTED_CLIENT_IDS[profile],
        "request_uri_present": exact and bool(values.get("request_uri")),
    }
    if not all((summary["only_expected_names"], summary["client_id_matches"], summary["request_uri_present"])):
        raise _FlowFailure("location_rejected")
    return summary


def _validate_callback_location(value: str, profile: str = "route_b") -> str:
    selected = FLOW_PROFILES.get(profile)
    if selected is None:
        raise _FlowFailure("callback_rejected")
    parsed, port = _url_parts(value)
    if port != 8443 or parsed.path != selected["callback_path"]:
        raise _FlowFailure("callback_rejected")
    try:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise _FlowFailure("callback_rejected") from None
    if (len(query.get("code", [])) != 1 or not query["code"][0]
        or len(query.get("state", [])) != 1 or not query["state"][0]
        or "error" in query):
        raise _FlowFailure("callback_rejected")
    return value


def _terminal_kind(value: str, profile: str = "route_b") -> str | None:
    selected = FLOW_PROFILES.get(profile)
    if selected is None:
        return None
    parsed, port = _url_parts(value)
    if port != 3443 or parsed.path != "/":
        return None
    try:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return None
    if value == selected["login_terminal"]:
        return "login"
    if value == selected["logout_terminal"]:
        return "logout"
    return None


def _location(headers: Message) -> str:
    values = _headers_values(headers, "Location")
    if len(values) != 1 or not values[0] or len(values[0]) > MAX_LOCATION_CHARS:
        raise _FlowFailure("location_rejected")
    if any(ord(char) < 32 or ord(char) == 127 for char in values[0]):
        raise _FlowFailure("location_rejected")
    return values[0]


def _initial_cookie_values(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    else:
        try:
            values = list(value)
        except TypeError:
            raise _FlowFailure("cookie_rejected") from None
    if len(values) > MAX_COOKIE_HEADERS:
        raise _FlowFailure("cookie_rejected")
    for item in values:
        if (not isinstance(item, str) or not item or len(item) > MAX_COOKIE_CHARS
            or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in item)):
            raise _FlowFailure("cookie_rejected")
    return values


def _session_values(cookie_jar: http.cookiejar.CookieJar, profile: str = "route_b") -> frozenset[str]:
    selected = FLOW_PROFILES.get(profile)
    if selected is None:
        return frozenset()
    return frozenset(
        cookie.value for cookie in cookie_jar
        if cookie.name == selected["session_cookie"] and isinstance(cookie.value, str) and cookie.value
    )


def _form_body(form: dict, overrides: dict[str, str], submit_name: str | None) -> tuple[str, bytes]:
    action = urllib.parse.urljoin(form["current_url"], form["attrs"].get("action", form["current_url"]))
    if not _is_keycloak_url(action):
        raise _FlowFailure("form_rejected")
    fields = form["fields"]
    values = [
        (field["name"], field["value"])
        for field in fields
        if field["type"] not in {"submit", "button", "image", "reset"}
        and field["name"] not in overrides
    ]
    values.extend((name, value) for name, value in overrides.items())
    if submit_name:
        button = next((item for item in form["buttons"] if item["name"] == submit_name), None)
        submit_input = next((item for item in fields if item["name"] == submit_name), None)
        if button:
            values.append((button["name"], button["value"] or "Yes"))
        elif submit_input:
            values.append((submit_input["name"], submit_input["value"] or "Yes"))
        else:
            values.append((submit_name, "Yes"))
    encoded = urllib.parse.urlencode(values).encode("utf-8")
    if len(encoded) > MAX_FORM_BYTES:
        raise _FlowFailure("form_rejected")
    return action, encoded


def _find_form(body: bytes, current_url: str, username: str, password: str):
    parser = LoginForms()
    parser.feed(body.decode("utf-8", errors="replace"))
    for form in parser.forms:
        names = {field["name"] for field in form["fields"]}
        if names.issuperset({"username", "password"}):
            return {**form, "current_url": current_url}, "login", {
                "username": username, "password": password,
            }, "login"
    for form in parser.forms:
        consent_name = next(
            (button["name"] for button in form["buttons"]
             if button["name"].lower() in {"accept", "approve"}),
            None,
        ) or next(
            (field["name"] for field in form["fields"]
             if field["name"].lower() in {"accept", "approve"}),
            None,
        )
        if consent_name:
            return {**form, "current_url": current_url}, "consent", {}, consent_name
    return None


def _capture_initial_cookies(cookie_jar: http.cookiejar.CookieJar, values: list[str], callback_url: str) -> None:
    headers = Message()
    for value in values:
        headers.add_header("Set-Cookie", value)
    try:
        request = urllib.request.Request(callback_url)
        cookie_jar.extract_cookies(_InitialCookieResponse(headers), request)
    except Exception:
        raise _FlowFailure("cookie_rejected") from None


def _record_sensitive(callback: Callable[[bytes], object], *values: str | bytes | None) -> None:
    try:
        for value in values:
            if isinstance(value, str) and value:
                callback(value.encode("utf-8"))
                if value.lower().startswith("https://"):
                    try:
                        query = urllib.parse.urlsplit(value).query
                        pairs = urllib.parse.parse_qsl(
                            query, keep_blank_values=False, max_num_fields=128,
                        )
                    except (TypeError, ValueError):
                        pairs = ()
                    for name, item in pairs:
                        if name in SENSITIVE_QUERY_NAMES and item:
                            callback(item.encode("utf-8"))
                try:
                    cookies = http.cookies.SimpleCookie()
                    cookies.load(value)
                except (TypeError, ValueError, http.cookies.CookieError):
                    cookies = http.cookies.SimpleCookie()
                for name in SENSITIVE_COOKIE_NAMES:
                    morsel = cookies.get(name)
                    if morsel is not None and morsel.value:
                        callback(morsel.value.encode("utf-8"))
            elif isinstance(value, bytes) and value:
                callback(value)
    except Exception:
        raise _FlowFailure("secret_collector_failed") from None


def _safe_oauth_error(body: bytes) -> str:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    try:
        parsed = json.loads(body, object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError, TypeError, RecursionError):
        return "unknown"
    if not isinstance(parsed, dict):
        return "unknown"
    error = parsed.get("error")
    return error if isinstance(error, str) and error in OAUTH_ERROR_ENUMS else "unknown"


def _open(opener, metrics: dict[str, object], deadline: float, url: str,
          on_sensitive_value: Callable[[bytes], object],
          method: str = "GET", body: bytes | None = None):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or metrics["http_requests"] >= MAX_HTTP_REQUESTS:
        raise _FlowFailure("budget_exceeded")
    timeout = min(HTTP_TIMEOUT_SECONDS, remaining)
    headers = {"Accept": "text/html"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    metrics["http_requests"] = int(metrics["http_requests"]) + 1
    _record_sensitive(on_sensitive_value, url, body)
    response = None
    try:
        response = opener.open(request, timeout=timeout)
        _record_sensitive(on_sensitive_value, request.get_header("Cookie"))
    except urllib.error.HTTPError as error:
        _record_sensitive(on_sensitive_value, request.get_header("Cookie"))
        response = error
    except _FlowFailure:
        raise
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError):
        _record_sensitive(on_sensitive_value, request.get_header("Cookie"))
        raise _FlowFailure("transport_failure") from None
    try:
        status = int(response.code)
        bucket = status // 100
        key = f"status_{bucket}xx"
        if key in metrics:
            metrics[key] = int(metrics[key]) + 1
        headers_out = response.headers
        locations = _headers_values(headers_out, "Location")
        cookies = _headers_values(headers_out, "Set-Cookie")
        if (len(locations) > 1 or any(
            not value or len(value) > MAX_LOCATION_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            for value in locations
        )):
            raise _FlowFailure("location_rejected")
        if (len(cookies) > MAX_COOKIE_HEADERS or any(
            not value or len(value) > MAX_COOKIE_CHARS
            or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value)
            for value in cookies
        )):
            raise _FlowFailure("cookie_rejected")
        _record_sensitive(
            on_sensitive_value,
            *locations,
            *cookies,
        )
        response_body = b""
        if status not in REDIRECT_STATUSES:
            response_body = response.read(MAX_HTML_BYTES + 1)
            if len(response_body) > MAX_HTML_BYTES:
                raise _FlowFailure("http_failure")
            _record_sensitive(on_sensitive_value, response_body)
        return status, headers_out, response_body
    except _FlowFailure:
        raise
    except Exception:
        raise _FlowFailure("http_failure") from None
    finally:
        try:
            response.close()
        except Exception:
            pass


def _callback_request(opener, metrics: dict[str, object], deadline: float,
                      cookie_jar: http.cookiejar.CookieJar,
                      on_sensitive_value: Callable[[bytes], object], callback_url: str, profile: str,
                      previous_cookie_values: frozenset[str]) -> None:
    callback_url = _validate_callback_location(callback_url, profile)
    status, headers, body = _open(opener, metrics, deadline, callback_url, on_sensitive_value)
    metrics["callback_http_status"] = status
    metrics["redirects"] = int(metrics["redirects"]) + (1 if status in REDIRECT_STATUSES else 0)
    if status not in REDIRECT_STATUSES:
        metrics["callback_error_enum"] = _safe_oauth_error(body)
        raise _FlowFailure("callback_rejected")
    terminal = urllib.parse.urljoin(callback_url, _location(headers))
    if _terminal_kind(terminal, profile) != "login":
        raise _FlowFailure("callback_rejected")
    updated_cookie_values = _session_values(cookie_jar, profile)
    if not any(value not in previous_cookie_values for value in updated_cookie_values):
        raise _FlowFailure("session_cookie_missing")
    metrics["callback_completed"] = True
    metrics["session_cookie_changed"] = True


def _clone_cookie_jar(source: http.cookiejar.CookieJar) -> http.cookiejar.CookieJar:
    target = http.cookiejar.CookieJar()
    for cookie in source:
        target.set_cookie(copy.copy(cookie))
    return target


def _mismatched_iss_url(callback_url: str) -> str:
    parsed = urllib.parse.urlsplit(callback_url)
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=8,
        )
    except ValueError:
        raise _FlowFailure("callback_rejected") from None
    if sum(name == "iss" for name, _value in pairs) > 1:
        raise _FlowFailure("callback_rejected")
    pairs = [(name, value) for name, value in pairs if name != "iss"]
    pairs.append(("iss", "https://wp5-mismatch.invalid/issuer"))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                    urllib.parse.urlencode(pairs), parsed.fragment))


def _probe_iss_mismatch(metrics: dict[str, object], deadline: float,
                        on_sensitive_value: Callable[[bytes], object], callback_url: str,
                        cookie_jar: http.cookiejar.CookieJar, ssl_context: ssl.SSLContext) -> None:
    """Try the callback with a mismatched iss on a copied jar, then leave control intact."""
    evidence = metrics["extended_evidence"]["callback_iss_mismatch"]
    evidence["attempted"] = True
    probe_jar = _clone_cookie_jar(cookie_jar)
    probe_opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl_context),
        urllib.request.HTTPCookieProcessor(probe_jar),
        _NoRedirectHandler(),
    )
    status, _headers, _body = _open(
        probe_opener, metrics, deadline, _mismatched_iss_url(callback_url), on_sensitive_value,
    )
    evidence["http_status"] = status
    if status not in {400, 401}:
        raise _FlowFailure("callback_rejected")
    evidence["rejected"] = True


def _login_until_callback(opener, metrics: dict[str, object], deadline: float,
                          cookie_jar: http.cookiejar.CookieJar,
                          on_sensitive_value: Callable[[bytes], object], authorization_url: str,
                          username: str, password: str, profile: str,
                          *, extended_flow: bool = False, ssl_context: ssl.SSLContext | None = None) -> None:
    current_url = authorization_url
    method = "GET"
    body = None
    while True:
        status, headers, response_body = _open(
            opener, metrics, deadline, current_url, on_sensitive_value, method, body,
        )
        if status in REDIRECT_STATUSES:
            metrics["redirects"] = int(metrics["redirects"]) + 1
            target = urllib.parse.urljoin(current_url, _location(headers))
            try:
                is_keycloak = _is_keycloak_url(target)
            except _FlowFailure:
                is_keycloak = False
            if is_keycloak:
                current_url = target
                if status not in {307, 308}:
                    method, body = "GET", None
                continue
            try:
                callback_url = _validate_callback_location(target, profile)
            except _FlowFailure:
                raise _FlowFailure("location_rejected") from None
            before = _session_values(cookie_jar, profile)
            if extended_flow:
                if ssl_context is None:
                    raise _FlowFailure("internal_failure")
                _probe_iss_mismatch(
                    metrics, deadline, on_sensitive_value, callback_url, cookie_jar, ssl_context,
                )
            _callback_request(
                opener, metrics, deadline, cookie_jar, on_sensitive_value,
                callback_url, profile, before,
            )
            return
        if status != 200 or not _is_keycloak_url(current_url):
            raise _FlowFailure("http_failure")
        selected = _find_form(response_body, current_url, username, password)
        if selected is None:
            raise _FlowFailure("form_rejected")
        form, kind, overrides, submit_name = selected
        if kind == "login":
            if int(metrics["login_submissions"]) != 0:
                raise _FlowFailure("form_rejected")
            metrics["login_submissions"] = 1
        else:
            if int(metrics["consent_submissions"]) != 0:
                raise _FlowFailure("form_rejected")
            metrics["consent_submissions"] = 1
        action, encoded = _form_body(form, overrides, submit_name)
        current_url, method, body = action, "POST", encoded


def _logout_until_terminal(opener, metrics: dict[str, object], deadline: float,
                           on_sensitive_value: Callable[[bytes], object], profile: str) -> None:
    current_url = FLOW_PROFILES[profile]["logout_url"]
    method = "GET"
    body = None
    while True:
        status, headers, _response_body = _open(
            opener, metrics, deadline, current_url, on_sensitive_value, method, body,
        )
        if status not in REDIRECT_STATUSES:
            raise _FlowFailure("logout_rejected")
        metrics["redirects"] = int(metrics["redirects"]) + 1
        target = urllib.parse.urljoin(current_url, _location(headers))
        try:
            if _is_keycloak_url(target):
                current_url = target
                if status not in {307, 308}:
                    method, body = "GET", None
                continue
        except _FlowFailure:
            pass
        if _terminal_kind(target, profile) == "logout":
            metrics["logout_completed"] = True
            return
        raise _FlowFailure("logout_rejected")


def run_stock_flow(
    initial_status: int,
    initial_location: str,
    initial_set_cookies: str | Iterable[str] | None,
    ca_file: str | Path,
    username: str,
    password: str,
    *,
    on_session_ready: Callable[[float], bool],
    on_sensitive_value: Callable[[bytes], object],
    profile: str = "route_b",
    trigger_refresh: bool = False,
    extended_flow: bool = False,
) -> dict[str, object]:
    """Complete one stock PAR browser flow and logout using a dedicated demo user.

    The first Kong response is supplied by the fixture runner so this helper does
    not issue another protected-resource request or another PAR. Sensitive values
    stay in memory; the result contains only fixed outcomes, booleans, and counts.
    """
    metrics = _result()
    if trigger_refresh:
        metrics["protected_refresh"] = {"attempted": False, "http_status": 0, "completed": False}
    if extended_flow:
        metrics["extended_evidence"] = {
            "initial_redirect_query": {},
            "callback_iss_mismatch": {"attempted": False, "http_status": 0, "rejected": False},
            "protected_refresh_gets": 0,
            "refresh_waits": 0,
        }
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    try:
        if (type(initial_status) is not int or initial_status != 302
            or not isinstance(username, str) or not username or len(username) > 256
            or not isinstance(password, str) or not password or len(password) > 1024
            or not callable(on_session_ready) or not callable(on_sensitive_value)
            or profile not in FLOW_PROFILES or type(trigger_refresh) is not bool
            or type(extended_flow) is not bool or (extended_flow and not trigger_refresh)):
            raise _FlowFailure("input_rejected")
        selected_profile = FLOW_PROFILES[profile]
        authorization_url = _validate_initial_location(initial_location, profile)
        if extended_flow:
            metrics["extended_evidence"]["initial_redirect_query"] = _initial_redirect_summary(
                authorization_url, profile,
            )
        cookie_values = _initial_cookie_values(initial_set_cookies)
        _record_sensitive(on_sensitive_value, authorization_url, username, password, *cookie_values)
        _capture_initial_cookies(
            cookie_jar := http.cookiejar.CookieJar(), cookie_values,
            selected_profile["callback_url"],
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_file))
        context.keylog_filename = None
        context.set_alpn_protocols(["http/1.1"])
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(cookie_jar),
            _NoRedirectHandler(),
        )
        _login_until_callback(
            opener, metrics, deadline, cookie_jar, on_sensitive_value,
            authorization_url, username, password, profile,
            extended_flow=extended_flow, ssl_context=context,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0 or int(metrics["http_requests"]) >= MAX_HTTP_REQUESTS:
            raise _FlowFailure("budget_exceeded")
        phase_timeout = min(HTTP_TIMEOUT_SECONDS, remaining)
        metrics["http_requests"] = int(metrics["http_requests"]) + 1
        try:
            phase_result = on_session_ready(phase_timeout)
        except TimeoutError:
            raise _FlowFailure("budget_exceeded") from None
        except Exception:
            raise _FlowFailure("phase_callback_failed") from None
        if phase_result is not True:
            raise _FlowFailure("phase_callback_failed")
        if deadline - time.monotonic() <= 0:
            raise _FlowFailure("budget_exceeded")
        metrics["phase_callback_called"] = True
        if trigger_refresh:
            refresh_row = metrics["protected_refresh"]
            refresh_count = 2 if extended_flow else 1
            for _index in range(refresh_count):
                remaining = deadline - time.monotonic()
                if remaining <= REFRESH_WAIT_SECONDS + 1:
                    raise _FlowFailure("budget_exceeded")
                time.sleep(REFRESH_WAIT_SECONDS)
                if extended_flow:
                    metrics["extended_evidence"]["refresh_waits"] += 1
                refresh_row["attempted"] = True
                status, _headers, refresh_body = _open(
                    opener, metrics, deadline, selected_profile["callback_url"],
                    on_sensitive_value,
                )
                refresh_row["http_status"] = status
                if (status != selected_profile.get("refresh_status")
                    or refresh_body != selected_profile.get("refresh_body")):
                    raise _FlowFailure("refresh_trigger_rejected")
                if extended_flow:
                    metrics["extended_evidence"]["protected_refresh_gets"] += 1
            refresh_row["completed"] = True
        _logout_until_terminal(opener, metrics, deadline, on_sensitive_value, profile)
        metrics["ok"] = True
        metrics["outcome"] = "complete"
    except _FlowFailure as error:
        metrics["outcome"] = error.outcome
    except Exception:
        metrics["outcome"] = "internal_failure"
    return metrics


__all__ = ["run_stock_flow"]
