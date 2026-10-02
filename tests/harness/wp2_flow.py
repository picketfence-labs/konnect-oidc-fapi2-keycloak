#!/usr/bin/env python3
"""Run explicitly gated WP2 Keycloak probes against an isolated loopback realm.

Tokens, authorization codes, assertions, cookies, and client secrets are held
in process memory and are never printed or written to evidence files.
"""

import argparse
import base64
import http.cookiejar
import hashlib
import hmac
import http.server
from html.parser import HTMLParser
import json
import os
import queue
import re
import secrets
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PREVIEW = ROOT / ".generated/wp2-preview"
AUDIENCE_API = "fapi-demo-api"
AUDIENCE_INTROSPECTION = "api-gateway-introspection"
NAMESPACE = "https://fapi-demo.example.com"
CLIENTS = {
    "a": {
        "client_id": "third-party-fapi-mtls",
        "certificate": "route-a.crt",
        "key": "route-a.key",
        "redirect_uri": "https://localhost:8443/api/fapi/mtls",
    },
    "b": {
        "client_id": "third-party-fapi-pkj-mtls",
        "certificate": "route-b.crt",
        "key": "route-b.key",
        "signing_key": "route-b-pkj.key",
        "redirect_uri": "https://localhost:8443/api/fapi/pkj-mtls",
    },
}
INTRO_CERT = "api-introspection.crt"
INTRO_KEY = "api-introspection.key"
AUTH_ACCOUNTS_FILE = "accounts.env"
OAUTH_ERROR_CODES = {
    "access_denied",
    "invalid_client",
    "invalid_grant",
    "invalid_request",
    "invalid_scope",
    "invalid_token",
    "server_error",
    "temporarily_unavailable",
    "unauthorized_client",
    "unsupported_grant_type",
    "unsupported_response_type",
}
OAUTH_ERROR_REASONS = {
    "invalid audience in client assertion": "client_assertion_audience",
    "Client Certification missing for MTLS HoK Token Binding": "mtls_client_certificate_missing",
}
SAFE_OAUTH_ERROR_REASONS = frozenset(OAUTH_ERROR_REASONS.values())


class ProbeError(RuntimeError):
    pass


class ProtocolResponseError(ProbeError):
    def __init__(self, status, error_code, error_reason=None):
        self.status = status
        self.error_code = error_code
        self.error_reason = (
            error_reason
            if isinstance(error_reason, str) and error_reason in SAFE_OAUTH_ERROR_REASONS
            else None
        )
        super().__init__(f"HTTP {status}; OAuth error={error_code or 'unspecified'}")


class TransportError(ProbeError):
    pass


class JwksDocument:
    """Keep one discovery-time JWKS with one bounded unknown-kid refresh."""

    def __init__(self, document, refresh=None):
        self.document = document
        self.refresh_callback = refresh
        self.refresh_attempted = False

    def signing_key(self, kid):
        keys = self._keys(self.document)
        matching_kid = [key for key in keys if key.get("kid") == kid]
        if not matching_kid and self.refresh_callback is not None and not self.refresh_attempted:
            self.refresh_attempted = True
            refreshed = self.refresh_callback()
            self._keys(refreshed)
            self.document = refreshed
            keys = self._keys(self.document)
            matching_kid = [key for key in keys if key.get("kid") == kid]

        candidates = [
            key for key in matching_kid
            if key.get("kty") == "RSA" and key.get("use") == "sig" and key.get("alg") == "PS256"
        ]
        if len(candidates) != 1:
            raise ProbeError("Keycloak JWKS has no unique matching PS256 signing key")
        return candidates[0]

    @staticmethod
    def _keys(document):
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise ProbeError("Keycloak JWKS document is malformed")
        if any(not isinstance(key, dict) for key in document["keys"]):
            raise ProbeError("Keycloak JWKS document is malformed")
        return document["keys"]


def read_env(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise ProbeError("isolated fixture credential file is absent or malformed")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProbeError("isolated fixture credential file permissions are too broad")
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ProbeError("isolated fixture credential file is malformed")
        key, value = line.split("=", 1)
        if key in values:
            raise ProbeError("isolated fixture credential file contains duplicate keys")
        values[key] = value
    return values


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ProbeError("malformed encoded protocol value")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def require_loopback_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        parsed_port = parsed.port
    except ValueError:
        raise ProbeError("Keycloak URL is malformed") from None
    if parsed.scheme != "https" or parsed.hostname != "localhost":
        raise ProbeError("only an HTTPS loopback Keycloak URL is allowed")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProbeError("Keycloak URL must not contain credentials or query data")
    if parsed.path not in {"", "/"}:
        raise ProbeError("Keycloak URL must be an origin without a path")
    if parsed_port is None:
        raise ProbeError("Keycloak URL must include its isolated preview port")
    if parsed_port != 18444:
        raise ProbeError("only the isolated Keycloak port 18444 is allowed")
    return value.rstrip("/")


def ssl_context(ca_path, certificate=None, private_key=None):
    context = ssl.create_default_context(cafile=str(ca_path))
    if certificate or private_key:
        if not certificate or not private_key:
            raise ProbeError("both certificate and private key are required")
        context.load_cert_chain(str(certificate), str(private_key))
    return context


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def request_json(base_url, path_or_url, ca_path, certificate=None, private_key=None,
                 form=None, method=None, bearer=None, json_body=None):
    target = path_or_url if path_or_url.startswith("https://") else base_url + path_or_url
    parsed = urllib.parse.urlsplit(target)
    base = urllib.parse.urlsplit(base_url)
    if (parsed.scheme, parsed.hostname, parsed.port) != (base.scheme, base.hostname, base.port):
        raise ProbeError("Keycloak metadata advertised a non-loopback endpoint")
    headers = {"Accept": "application/json"}
    body = None
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(form).encode("utf-8")
    elif json_body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(json_body).encode("utf-8")
    request = urllib.request.Request(
        target,
        data=body,
        headers=headers,
        method=method or ("POST" if body is not None else "GET"),
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(
            context=ssl_context(ca_path, certificate, private_key)
        ),
        NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        status = error.code
        error_reason = None
        try:
            body = error.read()
            decoded = json.loads(body) if body else {}
            error_code = decoded.get("error") if isinstance(decoded, dict) else None
            if error_code == "invalid_grant" and isinstance(decoded, dict):
                error_reason = OAUTH_ERROR_REASONS.get(decoded.get("error_description"))
        except (OSError, ValueError, TypeError):
            error_code = None
        finally:
            error.close()
        if not isinstance(error_code, str) or error_code not in OAUTH_ERROR_CODES:
            error_code = None
            error_reason = None
        raise ProtocolResponseError(status, error_code, error_reason) from None
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError):
        raise TransportError("TLS or local transport failed before an HTTP response") from None


def jwt_parts(token):
    if not isinstance(token, str) or len(token) > 65536:
        raise ProbeError("token is absent or exceeds the local harness limit")
    parts = token.split(".")
    if len(parts) != 3:
        raise ProbeError("token is not a compact JWT")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ProbeError("token JWT encoding is malformed") from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ProbeError("token JWT header or claims are malformed")
    return parts[0] + "." + parts[1], header, claims, signature


def verify_ps256(token, jwks, issuer=None, audience=None, nonce=None):
    _signed, header, _claims, _signature = jwt_parts(token)
    if header.get("alg") != "PS256" or not isinstance(header.get("kid"), str) or not header["kid"]:
        raise ProbeError("token is not signed with the required PS256 key")
    if isinstance(jwks, JwksDocument):
        signing_key = jwks.signing_key(header["kid"])
    else:
        signing_key = JwksDocument(jwks).signing_key(header["kid"])
    try:
        import jwt

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(signing_key))
        required = ["iss", "exp", "iat"]
        if nonce is not None:
            required.append("nonce")
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["PS256"],
            issuer=issuer,
            audience=audience,
            options={
                "require": required,
                "verify_aud": audience is not None,
            },
        )
    except ImportError:
        raise ProbeError("install the pinned PyJWT crypto dependency from requirements-dev.txt") from None
    except Exception:
        raise ProbeError("PS256 signature or registered-claim verification failed") from None
    if nonce is not None and claims.get("nonce") != nonce:
        raise ProbeError("ID-token nonce does not match the authorization request")
    return header, claims


def certificate_thumbprint(certificate_path):
    result = subprocess.run(
        ["openssl", "x509", "-in", str(certificate_path), "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    return b64url(hashlib.sha256(result.stdout).digest())


def keycloak_key_id(private_key_path):
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key_path), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    return b64url(hashlib.sha256(result.stdout).digest())


def sign_client_assertion(client_id, issuer, key_path, audience=None, assertion=None):
    if assertion is not None:
        return assertion
    now = int(time.time())
    header = b64url(json.dumps(
        {"alg": "PS256", "typ": "JWT", "kid": keycloak_key_id(key_path)},
        separators=(",", ":"),
    ).encode())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience or issuer,
        "iat": now,
        "exp": now + 60,
        "jti": secrets.token_urlsafe(24),
    }
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signed = f"{header}.{payload}"
    result = subprocess.run(
        [
            "openssl", "dgst", "-sha256", "-sign", str(key_path),
            "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest",
            "-sigopt", "rsa_mgf1_md:sha256",
        ],
        input=signed.encode("ascii"),
        check=True,
        capture_output=True,
    )
    return f"{signed}.{b64url(result.stdout)}"


def client_auth_form(client, issuer, signing_key, assertion_audience=None, assertion=None):
    if "signing_key" not in client:
        return {"client_id": client["client_id"]}
    signed = sign_client_assertion(
        client["client_id"], issuer, signing_key,
        audience=assertion_audience, assertion=assertion,
    )
    return {
        "client_id": client["client_id"],
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": signed,
    }


class LoginForms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None
        self.current_button = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"attrs": attrs, "fields": [], "buttons": []}
        elif self.current is not None and tag == "input":
            name = attrs.get("name")
            if name:
                self.current["fields"].append({
                    "name": name,
                    "value": attrs.get("value", ""),
                    "type": attrs.get("type", "text").lower(),
                })
        elif self.current is not None and tag == "button":
            self.current_button = {"name": attrs.get("name", ""), "value": attrs.get("value", "")}

    def handle_endtag(self, tag):
        if tag == "button" and self.current_button is not None:
            self.current["buttons"].append(self.current_button)
            self.current_button = None
        elif tag == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


class LocalAuthRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        if parsed.scheme != "https" or parsed.hostname != "localhost" or parsed.port not in {18444, 8443}:
            return None
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def submit_local_form(opener, current_url, form, overrides=None, submit_name=None):
    action = urllib.parse.urljoin(current_url, form["attrs"].get("action", current_url))
    parsed = urllib.parse.urlsplit(action)
    if parsed.scheme != "https" or parsed.hostname != "localhost" or parsed.port != 18444:
        raise ProbeError("login or consent form attempted a non-Keycloak destination")
    values = [
        (field["name"], field["value"])
        for field in form["fields"]
        if field["type"] not in {"submit", "button", "image", "reset"}
        and field["name"] not in (overrides or {})
    ]
    values.extend((name, value) for name, value in (overrides or {}).items())
    if submit_name:
        button = next(
            (item for item in form["buttons"] if item["name"] == submit_name),
            None,
        )
        submit_input = next(
            (item for item in form["fields"] if item["name"] == submit_name),
            None,
        )
        if button:
            values.append((button["name"], button["value"] or "Yes"))
        elif submit_input:
            values.append((submit_input["name"], submit_input["value"] or "Yes"))
        else:
            values.append((submit_name, "Yes"))
    request = urllib.request.Request(
        action,
        data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"},
        method="POST",
    )
    return opener.open(request, timeout=20)


def complete_authorization_page(opener, authorization_url, accounts):
    try:
        response = opener.open(authorization_url, timeout=20)
        for _ in range(5):
            current_url = response.geturl()
            parsed = urllib.parse.urlsplit(current_url)
            if parsed.scheme == "https" and parsed.hostname == "localhost" and parsed.port == 8443:
                return
            if parsed.scheme != "https" or parsed.hostname != "localhost" or parsed.port != 18444:
                raise ProbeError("authorization flow left the isolated Keycloak or callback origin")
            body = response.read()
            parser = LoginForms()
            parser.feed(body.decode("utf-8", errors="replace"))
            login_form = next(
                (
                    form for form in parser.forms
                    if {field["name"] for field in form["fields"]}.issuperset({"username", "password"})
                ),
                None,
            )
            if login_form is not None:
                response = submit_local_form(
                    opener,
                    current_url,
                    login_form,
                    {
                        "username": accounts["WP2_SALES_USERNAME"],
                        "password": accounts["WP2_SALES_PASSWORD"],
                    },
                    submit_name="login",
                )
                continue
            consent_form = next(
                (
                    form for form in parser.forms
                    if any(button["name"].lower() in {"accept", "approve"} for button in form["buttons"])
                    or any(field["name"].lower() in {"accept", "approve"} for field in form["fields"])
                ),
                None,
            )
            if consent_form is not None:
                consent_name = next(
                    (button["name"] for button in consent_form["buttons"] if button["name"].lower() in {"accept", "approve"}),
                    None,
                ) or next(
                    field["name"] for field in consent_form["fields"] if field["name"].lower() in {"accept", "approve"}
                )
                response = submit_local_form(opener, current_url, consent_form, submit_name=consent_name)
                continue
            raise ProbeError("Keycloak returned an unrecognized login or consent page")
        raise ProbeError("Keycloak authorization did not reach the callback after login and consent")
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise ProbeError(f"isolated authorization page returned HTTP {status}") from None
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError):
        raise TransportError("isolated authorization page TLS or transport failed") from None


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        allowed_paths = {client["redirect_uri"].split(":8443", 1)[1] for client in CLIENTS.values()}
        if parsed.path not in allowed_paths:
            self.send_error(404)
            return
        values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        result = {
            "path": parsed.path,
            "code": values.get("code", [None])[0],
            "state": values.get("state", [None])[0],
            "error": values.get("error", [None])[0],
            "received_at": time.time(),
        }
        self.server.callback_queue.put(result)
        body = b"Authorization response captured in memory. You may close this window."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class CallbackServer:
    def __init__(self, pki):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), CallbackHandler)
        self.server.callback_queue = queue.Queue()
        self.cookie_jar = http.cookiejar.CookieJar()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(pki / "kong-proxy.crt"), str(pki / "kong-proxy.key"))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def receive(self, expected_state, expected_path, timeout=300):
        try:
            value = self.server.callback_queue.get(timeout=timeout)
        except queue.Empty:
            raise ProbeError("authorization callback timed out") from None
        if value["error"] or not value["code"]:
            raise ProbeError("authorization server returned an OAuth error")
        if value["path"] != expected_path:
            raise ProbeError("authorization callback path did not match the registered redirect URI")
        if not isinstance(value["state"], str) or not hmac.compare_digest(value["state"], expected_state):
            raise ProbeError("authorization callback state did not match")
        return value


def authorize_code(route_key, metadata, issuer, pki, callback_server, signing_key, accounts):
    client = CLIENTS[route_key]
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = b64url(secrets.token_bytes(32))
    nonce = b64url(secrets.token_bytes(32))
    certificate = pki / client["certificate"]
    private_key = pki / client["key"]
    form = {
        **client_auth_form(client, issuer, signing_key),
        "response_type": "code",
        "redirect_uri": client["redirect_uri"],
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    issuer_url = urllib.parse.urlsplit(issuer)
    origin = f"{issuer_url.scheme}://{issuer_url.netloc}"
    pushed = request_json(
        origin,
        metadata["pushed_authorization_request_endpoint"],
        pki / "ca.crt",
        certificate,
        private_key,
        form=form,
    )
    request_uri = pushed.get("request_uri")
    if not isinstance(request_uri, str) or not request_uri.startswith("urn:ietf:params:oauth:request_uri:"):
        raise ProbeError("Keycloak PAR response omitted a valid request_uri")
    auth_query = urllib.parse.urlencode({"client_id": client["client_id"], "request_uri": request_uri})
    authorization_url = metadata["authorization_endpoint"] + "?" + auth_query
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_context(pki / "ca.crt")),
        urllib.request.HTTPCookieProcessor(callback_server.cookie_jar),
        LocalAuthRedirectHandler(),
    )
    complete_authorization_page(opener, authorization_url, accounts)
    callback_path = urllib.parse.urlsplit(client["redirect_uri"]).path
    callback = callback_server.receive(state, callback_path)
    return {
        "route_key": route_key,
        "client": client,
        "code": callback["code"],
        "verifier": verifier,
        "nonce": nonce,
        "requested_scopes": {"openid", "profile"},
        "issued_at": callback["received_at"],
        "certificate": certificate,
        "private_key": private_key,
    }


def exchange_code(grant, issuer, metadata, pki, signing_key, certificate_override=None,
                  assertion_audience=None, assertion=None):
    client = grant["client"]
    certificate = certificate_override
    private_key = None
    if certificate is None and certificate_override is not False:
        certificate = grant["certificate"]
        private_key = grant["private_key"]
    elif certificate is not False:
        private_key = pki / "route-b.key" if certificate.name == "route-b.crt" else pki / "route-a.key"
    auth = client_auth_form(
        client, issuer, signing_key, assertion_audience=assertion_audience, assertion=assertion
    )
    form = {
        **auth,
        "grant_type": "authorization_code",
        "code": grant["code"],
        "redirect_uri": client["redirect_uri"],
        "code_verifier": grant["verifier"],
    }
    return request_json(
        issuer + "/protocol/openid-connect/token",
        metadata["token_endpoint"],
        pki / "ca.crt",
        certificate if certificate is not False else None,
        private_key,
        form=form,
    )


def audiences(claims):
    value = claims.get("aud")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def verify_access_token(response, grant, issuer, jwks, expected_intro=True):
    access_token = response.get("access_token")
    header, claims = verify_ps256(access_token, jwks, issuer=issuer)
    now = time.time()
    if claims.get("iss") != issuer:
        raise ProbeError("access-token issuer does not match discovery")
    if not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + 30:
        raise ProbeError("access-token iat is absent or in the future")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
        raise ProbeError("access token is expired")
    if claims.get("azp") != grant["client"]["client_id"]:
        raise ProbeError("access-token azp does not match its route client")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise ProbeError("access-token subject is missing")
    if not any(isinstance(claims.get(name), str) and claims[name] for name in ("sid", "session_state")):
        raise ProbeError("access token does not expose a comparable user-session identifier")
    aud = audiences(claims)
    required_aud = {AUDIENCE_API}
    if expected_intro:
        required_aud.add(AUDIENCE_INTROSPECTION)
    elif AUDIENCE_INTROSPECTION in aud:
        raise ProbeError("negative token still contains the introspection audience")
    if not required_aud.issubset(aud):
        raise ProbeError("access-token audience set is incomplete")
    scopes = set(claims.get("scope", "").split())
    if not grant["requested_scopes"].issubset(scopes):
        raise ProbeError("access-token scope does not include the requested openid and profile scopes")
    binding = claims.get("cnf", {}).get("x5t#S256") if isinstance(claims.get("cnf"), dict) else None
    expected_binding = certificate_thumbprint(grant["certificate"])
    if binding != expected_binding:
        raise ProbeError("access-token certificate binding does not match the route certificate")
    for claim in ("department", "route"):
        key = f"{NAMESPACE}/{claim}"
        if not isinstance(claims.get(key), str) or not claims[key]:
            raise ProbeError(f"access token lacks namespaced {claim} claim")
    id_token = response.get("id_token")
    if not isinstance(id_token, str):
        raise ProbeError("OpenID scope did not return an ID token")
    _, id_claims = verify_ps256(
        id_token,
        jwks,
        issuer=issuer,
        audience=grant["client"]["client_id"],
        nonce=grant["nonce"],
    )
    if id_claims.get("azp") != grant["client"]["client_id"]:
        raise ProbeError("ID-token issuer or nonce validation failed")
    return access_token, claims, header


def verify_introspection(introspection, claims):
    if introspection.get("active") is not True:
        raise ProbeError("dedicated mTLS introspection did not return active=true")
    if not {AUDIENCE_API, AUDIENCE_INTROSPECTION}.issubset(audiences(introspection)):
        raise ProbeError("introspection audience claims do not match the access token")
    if introspection.get("azp") != claims.get("azp"):
        raise ProbeError("introspection azp does not match the access token")
    if introspection.get("sub") != claims.get("sub"):
        raise ProbeError("introspection subject does not match the access token")
    if introspection.get("scope") != claims.get("scope"):
        raise ProbeError("introspection scope does not match the access token")
    for name in ("cnf", f"{NAMESPACE}/department", f"{NAMESPACE}/route"):
        if introspection.get(name) != claims.get(name):
            raise ProbeError(f"introspection claim {name} does not match the access token")


def introspect(access_token, metadata, pki):
    result = request_json(
        metadata["issuer"],
        metadata["introspection_endpoint"],
        pki / "ca.crt",
        pki / INTRO_CERT,
        pki / INTRO_KEY,
        form={"client_id": AUDIENCE_INTROSPECTION, "token": access_token},
    )
    return result


def admin_bearer(base_url, pki, bootstrap_env):
    values = read_env(bootstrap_env)
    username = values.get("KC_BOOTSTRAP_ADMIN_USERNAME")
    password = values.get("KC_BOOTSTRAP_ADMIN_PASSWORD")
    if not username or not password:
        raise ProbeError("isolated Keycloak bootstrap credentials are incomplete")
    result = request_json(
        base_url,
        "/realms/master/protocol/openid-connect/token",
        pki / "ca.crt",
        form={"grant_type": "password", "client_id": "admin-cli", "username": username, "password": password},
    )
    if not isinstance(result.get("access_token"), str):
        raise ProbeError("isolated Keycloak admin authentication failed")
    return result["access_token"]


def sync_user_profile(base_url, pki, bearer):
    path = "/admin/realms/fapi-demo/users/profile"
    live = request_json(base_url, path, pki / "ca.crt", bearer=bearer)
    if not isinstance(live, dict) or not isinstance(live.get("attributes"), list):
        raise ProbeError("isolated Keycloak user-profile representation is malformed")
    desired = json.loads((ROOT / "keycloak/user-profile.json").read_text())
    desired_attributes = desired.get("attributes")
    if not isinstance(desired_attributes, list):
        raise ProbeError("repository user-profile fixture is malformed")
    desired_by_name = {}
    for attribute in desired_attributes:
        name = attribute.get("name") if isinstance(attribute, dict) else None
        if not isinstance(name, str) or name in desired_by_name:
            raise ProbeError("repository user-profile fixture has invalid or duplicate attributes")
        desired_by_name[name] = attribute
    current_attributes = live["attributes"]
    current_names = [item.get("name") for item in current_attributes if isinstance(item, dict)]
    if len(current_names) != len(current_attributes) or len(current_names) != len(set(current_names)):
        raise ProbeError("isolated Keycloak user profile has malformed or duplicate attributes")
    merged = [item for item in current_attributes if item["name"] not in desired_by_name]
    merged.extend(desired_attributes)
    payload = {**live, "attributes": merged}
    if payload != live:
        request_json(base_url, path, pki / "ca.crt", bearer=bearer,
                     method="PUT", json_body=payload)
    verified = request_json(base_url, path, pki / "ca.crt", bearer=bearer)
    observed = verified.get("attributes") if isinstance(verified, dict) else None
    observed_by_name = {
        item.get("name"): item for item in observed if isinstance(item, dict)
    } if isinstance(observed, list) else {}
    if any(
        not isinstance(observed_by_name.get(name), dict)
        or any(observed_by_name[name].get(key) != value for key, value in attribute.items())
        for name, attribute in desired_by_name.items()
    ):
        raise ProbeError("isolated Keycloak user-profile update did not converge")


def sync_fixture_user_attributes(base_url, pki, bearer):
    """Apply only the fixture's custom routing attributes to its two demo users."""
    template = json.loads((ROOT / "keycloak/realm-template.json").read_text())
    desired_users = template.get("users")
    expected_usernames = {
        "sales.user@fapi-demo.invalid",
        "engineering.user@fapi-demo.invalid",
    }
    if (
        not isinstance(desired_users, list)
        or len(desired_users) != 2
        or not all(isinstance(user, dict) for user in desired_users)
        or {user.get("username") for user in desired_users} != expected_usernames
    ):
        raise ProbeError("repository demo-user fixture is malformed")
    managed_attributes = {"department", "departement", "route"}
    prepared = []
    for desired_user in desired_users:
        desired_attributes = desired_user.get("attributes")
        if not isinstance(desired_attributes, dict) or set(desired_attributes) != managed_attributes:
            raise ProbeError("repository demo-user routing attributes are malformed")
        if any(
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item for item in value)
            for value in desired_attributes.values()
        ):
            raise ProbeError("repository demo-user routing attribute values are malformed")
        username = desired_user["username"]
        query = urllib.parse.urlencode({"username": username, "exact": "true"})
        matches = request_json(
            base_url, f"/admin/realms/fapi-demo/users?{query}", pki / "ca.crt", bearer=bearer
        )
        if not isinstance(matches, list) or len(matches) != 1 or not isinstance(matches[0], dict):
            raise ProbeError("isolated fixture user lookup did not return exactly one user")
        user_id = matches[0].get("id")
        if matches[0].get("username") != username or not isinstance(user_id, str) or not user_id:
            raise ProbeError("isolated fixture username lookup returned a different user")
        user_path = f"/admin/realms/fapi-demo/users/{urllib.parse.quote(user_id, safe='')}"
        details = request_json(base_url, user_path, pki / "ca.crt", bearer=bearer)
        if (
            not isinstance(details, dict)
            or details.get("id") != user_id
            or details.get("username") != username
        ):
            raise ProbeError("isolated fixture user detail did not match the exact username and ID")
        current_attributes = details.get("attributes", {})
        if not isinstance(current_attributes, dict):
            raise ProbeError("isolated fixture user attributes are malformed")
        merged = {**current_attributes, **desired_attributes}
        unknown = {key: value for key, value in current_attributes.items() if key not in managed_attributes}
        prepared.append({
            "username": username,
            "user_id": user_id,
            "user_path": user_path,
            "desired_attributes": desired_attributes,
            "unknown_attributes": unknown,
            "current_attributes": current_attributes,
            "merged_attributes": merged,
        })

    for user in prepared:
        if user["current_attributes"] != user["merged_attributes"]:
            request_json(
                base_url,
                user["user_path"],
                pki / "ca.crt",
                bearer=bearer,
                method="PUT",
                json_body={"id": user["user_id"], "attributes": user["merged_attributes"]},
            )

    for user in prepared:
        verified = request_json(
            base_url, user["user_path"], pki / "ca.crt", bearer=bearer
        )
        if (
            not isinstance(verified, dict)
            or verified.get("id") != user["user_id"]
            or verified.get("username") != user["username"]
        ):
            raise ProbeError("isolated fixture user post-read did not match username and ID")
        attributes = verified.get("attributes")
        if not isinstance(attributes, dict):
            raise ProbeError("isolated fixture user post-read attributes are malformed")
        if any(attributes.get(key) != value for key, value in user["desired_attributes"].items()):
            raise ProbeError("isolated fixture user routing attributes did not converge")
        if any(attributes.get(key) != value for key, value in user["unknown_attributes"].items()):
            raise ProbeError("isolated fixture user update changed unmanaged attributes")


def change_audience_mapper(base_url, pki, bearer, route_key, enabled):
    client = CLIENTS[route_key]
    query = urllib.parse.urlencode({"clientId": client["client_id"]})
    matches = request_json(
        base_url, f"/admin/realms/fapi-demo/clients?{query}", pki / "ca.crt", bearer=bearer
    )
    if not isinstance(matches, list) or len(matches) != 1:
        raise ProbeError("isolated route client lookup did not return exactly one client")
    client_uuid = matches[0].get("id")
    mapper_path = f"/admin/realms/fapi-demo/clients/{urllib.parse.quote(client_uuid, safe='')}/protocol-mappers/models"
    live_mappers = request_json(base_url, mapper_path, pki / "ca.crt", bearer=bearer)
    mapper_matches = [
        mapper for mapper in live_mappers
        if mapper.get("name") == "api-gateway-introspection-audience"
    ]
    if len(mapper_matches) != 1 or not isinstance(mapper_matches[0].get("id"), str):
        raise ProbeError("isolated introspection-audience mapper lookup was ambiguous")
    live_config = mapper_matches[0].get("config")
    if not isinstance(live_config, dict):
        raise ProbeError("isolated introspection-audience mapper configuration is malformed")
    template = json.loads((ROOT / "keycloak/realm-template.json").read_text())
    desired_client = next(item for item in template["clients"] if item["clientId"] == client["client_id"])
    desired = next(item for item in desired_client["protocolMappers"] if item["name"] == "api-gateway-introspection-audience")
    desired_config = dict(desired["config"])
    observed = dict(desired_config)
    observed["access.token.claim"] = live_config.get("access.token.claim")
    if live_config != observed or observed["access.token.claim"] not in {"true", "false"}:
        raise ProbeError("introspection-audience mapper has unexpected unmanaged drift")
    mapper_id = mapper_matches[0]["id"]
    config = dict(desired_config)
    config["access.token.claim"] = "true" if enabled else "false"
    if live_config != config:
        request_json(
            base_url,
            mapper_path + "/" + urllib.parse.quote(mapper_id, safe=""),
            pki / "ca.crt",
            bearer=bearer,
            method="PUT",
            json_body={
                "id": mapper_id,
                "name": desired["name"],
                "protocol": desired["protocol"],
                "protocolMapper": desired["protocolMapper"],
                "config": config,
            },
        )
    verified = request_json(base_url, mapper_path, pki / "ca.crt", bearer=bearer)
    verified_matches = [item for item in verified if item.get("name") == desired["name"]]
    if len(verified_matches) != 1 or verified_matches[0].get("config") != config:
        raise ProbeError("introspection-audience mapper change did not converge")


def run_audience_negative(base_url, metadata, issuer, pki, callback_server, jwks, signing_key,
                          bearer, route_key, accounts):
    client = CLIENTS[route_key]
    control_grant = authorize_code(
        route_key, metadata, issuer, pki, callback_server, signing_key, accounts
    )
    control_response = exchange_code(control_grant, issuer, metadata, pki, signing_key)
    control_token, positive_claims, _ = verify_access_token(
        control_response, control_grant, issuer, jwks
    )
    control_introspection = introspect(control_token, metadata, pki)
    verify_introspection(control_introspection, positive_claims)
    before_binding = positive_claims["cnf"]
    session_name = "sid" if positive_claims.get("sid") else "session_state"
    positive_session = positive_claims[session_name]
    try:
        change_audience_mapper(base_url, pki, bearer, route_key, False)
        grant = authorize_code(route_key, metadata, issuer, pki, callback_server, signing_key, accounts)
        response = exchange_code(grant, issuer, metadata, pki, signing_key)
        access_token, claims, _ = verify_access_token(response, grant, issuer, jwks, expected_intro=False)
        negative_session_name = "sid" if claims.get("sid") else "session_state"
        if negative_session_name != session_name or claims.get(negative_session_name) != positive_session:
            raise ProbeError("RS-INT-AUD-01 did not reuse the active Keycloak user session")
        for key in ("sub", "azp", "scope", "cnf", f"{NAMESPACE}/department", f"{NAMESPACE}/route"):
            if claims.get(key) != positive_claims.get(key):
                raise ProbeError(f"RS-INT-AUD-01 changed preserved claim {key}")
        if claims.get("cnf") != before_binding:
            raise ProbeError("RS-INT-AUD-01 certificate binding changed")
        result = introspect(access_token, metadata, pki)
        if result.get("active") is not False:
            raise ProbeError("RS-INT-AUD-01 introspection did not return active=false")
    finally:
        change_audience_mapper(base_url, pki, bearer, route_key, True)
        restored = introspect(control_token, metadata, pki)
        verify_introspection(restored, positive_claims)
    print(f"RS-INT-AUD-01 {client['client_id']}: PASS (audience-only negative; active=false; mapper restored)")


def case_result(case_id, route_key, status, layer, http_status=None, error_code=None, observed=None,
                error_reason=None):
    return {
        "case_id": case_id,
        "route_client_id": CLIENTS[route_key]["client_id"],
        "status": status,
        "layer": layer,
        "http_status": http_status,
        "oauth_error": error_code,
        "oauth_reason": (
            error_reason
            if isinstance(error_reason, str) and error_reason in SAFE_OAUTH_ERROR_REASONS
            else None
        ),
        "observed_result": observed,
    }


def expect_as_rejection(case_id, route_key, grant, issuer, metadata, pki, signing_key,
                        certificate_override=None, assertion_audience=None,
                        assertion=None):
    try:
        exchange_code(
            grant,
            issuer,
            metadata,
            pki,
            signing_key,
            certificate_override=certificate_override,
            assertion_audience=assertion_audience,
            assertion=assertion,
        )
    except ProtocolResponseError as error:
        if not 400 <= error.status < 500:
            print(f"{case_id}: FAIL (AS returned HTTP {error.status})")
            return case_result(case_id, route_key, "fail", "AS", error.status)
        expected_responses = {
            "A-CERT-01": {(None, "invalid_client", None)},
            "A-CERT-02": {(None, "invalid_client", None)},
            "B-AUD-01": {(400, "invalid_grant", "client_assertion_audience")},
            "B-CERT-01": {(400, "invalid_grant", "mtls_client_certificate_missing")},
            "B-JTI-01": {(None, "invalid_client", None)},
        }
        if not any(
            (expected_status is None or expected_status == error.status)
            and (expected_code, expected_reason) == (error.error_code, error.error_reason)
            for expected_status, expected_code, expected_reason in expected_responses[case_id]
        ):
            print(f"{case_id}: FAIL (unexpected AS error: {error.error_code or 'unspecified'})")
            return case_result(case_id, route_key, "fail", "AS", error.status, error.error_code,
                               error_reason=error.error_reason)
        reason = f", reason={error.error_reason}" if error.error_reason else ""
        print(f"{case_id}: PASS (AS rejected: HTTP {error.status}, error={error.error_code or 'unspecified'}{reason})")
        return case_result(case_id, route_key, "pass", "AS", error.status, error.error_code,
                           "expected-AS-rejection", error_reason=error.error_reason)
    except TransportError:
        print(f"{case_id}: FAIL (TLS/transport ended before an AS response)")
        return case_result(case_id, route_key, "fail", "TLS/transport")
    except ProbeError:
        print(f"{case_id}: FAIL (local harness or grant validation failed before an AS rejection)")
        return case_result(case_id, route_key, "fail", "harness")
    print(f"{case_id}: FAIL (AS accepted the negative token request)")
    return case_result(case_id, route_key, "fail", "AS")


def load_metadata(base_url, pki):
    issuer = base_url + "/realms/fapi-demo"
    discovery = request_json(
        base_url,
        issuer + "/.well-known/openid-configuration",
        pki / "ca.crt",
    )
    if discovery.get("issuer") != issuer:
        raise ProbeError("isolated Keycloak discovery issuer did not match the loopback realm")
    for name in ("authorization_endpoint", "token_endpoint", "pushed_authorization_request_endpoint",
                 "introspection_endpoint", "jwks_uri"):
        value = discovery.get(name)
        parsed = urllib.parse.urlsplit(value or "")
        origin = urllib.parse.urlsplit(base_url)
        if (parsed.scheme, parsed.hostname, parsed.port) != (origin.scheme, origin.hostname, origin.port):
            raise ProbeError("Keycloak discovery advertised an endpoint outside the isolated loopback origin")
    jwks = request_json(base_url, discovery["jwks_uri"], pki / "ca.crt")
    return issuer, discovery, JwksDocument(
        jwks,
        refresh=lambda: request_json(base_url, discovery["jwks_uri"], pki / "ca.crt"),
    )


def run_as_negatives(base_url, metadata, issuer, pki, callback_server, signing_key, accounts,
                     receipt=None):
    results = []
    def record(result):
        results.append(result)
        if receipt is not None:
            update_receipt_case(receipt, result)

    grant_a = authorize_code("a", metadata, issuer, pki, callback_server, signing_key, accounts)
    record(expect_as_rejection("A-CERT-01", "a", grant_a, issuer, metadata, pki, signing_key,
                               certificate_override=False))

    grant_a_wrong_cert = authorize_code("a", metadata, issuer, pki, callback_server, signing_key, accounts)
    record(expect_as_rejection("A-CERT-02", "a", grant_a_wrong_cert, issuer, metadata, pki,
                               signing_key, certificate_override=pki / "route-b.crt"))

    grant_b_aud = authorize_code("b", metadata, issuer, pki, callback_server, signing_key, accounts)
    token_url = metadata["token_endpoint"]
    record(expect_as_rejection("B-AUD-01", "b", grant_b_aud, issuer, metadata, pki,
                               signing_key, assertion_audience=token_url))

    grant_b_no_cert = authorize_code("b", metadata, issuer, pki, callback_server, signing_key, accounts)
    record(expect_as_rejection("B-CERT-01", "b", grant_b_no_cert, issuer, metadata, pki,
                               signing_key, certificate_override=False))

    first = authorize_code("b", metadata, issuer, pki, callback_server, signing_key, accounts)
    second = authorize_code("b", metadata, issuer, pki, callback_server, signing_key, accounts)
    if (first["code"] == second["code"] or first["verifier"] == second["verifier"]
            or time.time() - first["issued_at"] > 50 or time.time() - second["issued_at"] > 50):
        print("B-JTI-01: not_run (two fresh authorization codes must remain within the 60-second code lifetime)")
        record(case_result("B-JTI-01", "b", "not_run", "not_run"))
    else:
        assertion = sign_client_assertion(CLIENTS["b"]["client_id"], issuer, signing_key)
        _signed, _header, assertion_claims, _signature = jwt_parts(assertion)
        try:
            first_response = exchange_code(first, issuer, metadata, pki, signing_key, assertion=assertion)
            if not isinstance(first_response.get("access_token"), str):
                raise ProbeError("first B-JTI-01 exchange did not issue an access token")
            remaining = assertion_claims.get("exp", 0) - time.time()
            first_code_age = time.time() - first["issued_at"]
            second_code_age = time.time() - second["issued_at"]
            if remaining <= 3 or first_code_age >= 58 or second_code_age >= 58:
                print("B-JTI-01: not_run (assertion or fresh authorization code lacks safe remaining lifetime)")
                record(case_result("B-JTI-01", "b", "not_run", "not_run"))
            else:
                record(expect_as_rejection("B-JTI-01", "b", second, issuer, metadata, pki,
                                           signing_key, assertion=assertion))
        except ProtocolResponseError as error:
            print("B-JTI-01: FAIL (first fresh grant was rejected by the AS)")
            record(case_result("B-JTI-01", "b", "fail", "AS", error.status, error.error_code))
        except TransportError:
            print("B-JTI-01: FAIL (the first fresh grant was not accepted)")
            record(case_result("B-JTI-01", "b", "fail", "TLS/transport"))
        except ProbeError:
            print("B-JTI-01: FAIL (first exchange did not produce a usable fresh-grant control)")
            record(case_result("B-JTI-01", "b", "fail", "harness"))
    return results


def initial_receipt():
    cases = []
    for route_key in ("a", "b"):
        cases.append(case_result("RS-INT-AUD-02", route_key, "not_run", "not_run"))
        cases.append(case_result("RS-INT-AUD-01", route_key, "not_run", "not_run"))
    for case_id, route_key in (
        ("A-CERT-01", "a"),
        ("A-CERT-02", "a"),
        ("B-AUD-01", "b"),
        ("B-JTI-01", "b"),
        ("B-CERT-01", "b"),
    ):
        cases.append(case_result(case_id, route_key, "not_run", "not_run"))
    return {
        "schema_version": 1,
        "generated_at_epoch": int(time.time()),
        "fixture": "isolated-wp2-keycloak",
        "cases": cases,
        "fixture_operations": [
            {"id": "user-profile-sync", "outcome": "not_run"},
            {"id": "demo-user-routing-attributes-sync", "outcome": "not_run"},
        ],
    }


def update_receipt_case(receipt, result):
    for index, current in enumerate(receipt["cases"]):
        if (current["case_id"], current["route_client_id"]) == (
            result["case_id"], result["route_client_id"]
        ):
            receipt["cases"][index] = result
            return
    raise ProbeError("internal WP2 receipt case mapping is invalid")


def write_receipt(preview, receipt):
    evidence_dir = preview / "evidence"
    if evidence_dir.is_symlink():
        raise ProbeError("isolated evidence directory must not be a symlink")
    evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence_path = evidence_dir / "wp2-receipt.json"
    if evidence_path.exists() or evidence_path.is_symlink():
        raise ProbeError("refusing to overwrite an existing sanitized WP2 receipt")
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    with evidence_path.open("x", encoding="utf-8") as stream:
        stream.write(payload)
    evidence_path.chmod(0o600)
    print(f"Sanitized receipt written to {evidence_path}")


def record_error(receipt, case_id, route_key, layer="harness"):
    result = case_result(case_id, route_key, "fail", layer)
    update_receipt_case(receipt, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-url", default="https://localhost:18444")
    parser.add_argument("--preview-dir", type=Path, default=DEFAULT_PREVIEW)
    parser.add_argument("--run-audience-negative", action="store_true")
    parser.add_argument("--run-as-negatives", action="store_true")
    parser.add_argument("--allow-isolated-auth-and-realm-changes", action="store_true")
    args = parser.parse_args()
    if not args.allow_isolated_auth_and_realm_changes:
        parser.error("authorization sessions, code/token issuance, and optional mapper changes require separate isolated-preview approval")
    base_url = require_loopback_url(args.keycloak_url)
    preview = args.preview_dir.absolute()
    if preview != DEFAULT_PREVIEW.absolute():
        parser.error("the runner is pinned to .generated/wp2-preview; use temporary output only for unit tests")
    if preview.is_symlink() or not preview.is_dir():
        parser.error("the isolated preview directory is absent or a symlink")
    pki = preview / "pki"
    bootstrap_env = preview / "bootstrap.env"
    accounts_path = preview / AUTH_ACCOUNTS_FILE
    required_pki_files = (
        "ca.crt", "keycloak.crt", "keycloak.key", "route-a.crt", "route-a.key",
        "route-b.crt", "route-b.key", "route-b-pkj.key", "api-introspection.crt",
        "api-introspection.key", "kong-proxy.crt", "kong-proxy.key",
    )
    if pki.is_symlink() or any(
        not (pki / filename).is_file() or (pki / filename).is_symlink()
        for filename in required_pki_files
    ) or not bootstrap_env.is_file() or not accounts_path.is_file():
        parser.error("prepare fresh isolated fixture assets first")
    evidence_dir = preview / "evidence"
    receipt_path = evidence_dir / "wp2-receipt.json"
    if evidence_dir.is_symlink() or receipt_path.exists() or receipt_path.is_symlink():
        parser.error("the isolated evidence path is unsafe or already contains a receipt")

    receipt = initial_receipt()
    exit_code = 0
    try:
        accounts = read_env(accounts_path)
        required_account_fields = {"WP2_SALES_USERNAME", "WP2_SALES_PASSWORD"}
        if not required_account_fields.issubset(accounts):
            raise ProbeError("isolated fixture account fields are incomplete")
        issuer, metadata, jwks = load_metadata(base_url, pki)
        introspection_admin = admin_bearer(base_url, pki, bootstrap_env)
        try:
            sync_user_profile(base_url, pki, introspection_admin)
            receipt["fixture_operations"][0]["outcome"] = "pass"
        except ProbeError:
            receipt["fixture_operations"][0]["outcome"] = "fail"
            raise
        try:
            sync_fixture_user_attributes(base_url, pki, introspection_admin)
            receipt["fixture_operations"][1]["outcome"] = "pass"
        except ProbeError:
            receipt["fixture_operations"][1]["outcome"] = "fail"
            raise
        with CallbackServer(pki) as callback_server:
            for route_key in ("a", "b"):
                try:
                    grant = authorize_code(route_key, metadata, issuer, pki, callback_server,
                                           pki / "route-b-pkj.key", accounts)
                    response = exchange_code(grant, issuer, metadata, pki, pki / "route-b-pkj.key")
                    access_token, claims, _header = verify_access_token(response, grant, issuer, jwks)
                    introspection = introspect(access_token, metadata, pki)
                    verify_introspection(introspection, claims)
                    update_receipt_case(receipt, case_result(
                        "RS-INT-AUD-02", route_key, "pass", "JWT+dedicated-mTLS-introspection", 200,
                        observed="active=true; required-claims-matched",
                    ))
                    print(f"RS-INT-AUD-02 {grant['client']['client_id']}: PASS (PS256, binding, audiences, claims, active=true)")
                except ProbeError:
                    record_error(receipt, "RS-INT-AUD-02", route_key)
                    raise

            if args.run_audience_negative:
                for route_key in ("a", "b"):
                    try:
                        run_audience_negative(base_url, metadata, issuer, pki, callback_server, jwks,
                                              pki / "route-b-pkj.key", introspection_admin,
                                              route_key, accounts)
                        update_receipt_case(receipt, case_result(
                            "RS-INT-AUD-01", route_key, "pass", "Keycloak-introspection-audience", 200,
                            observed="active=false; audience-only-negative",
                        ))
                    except ProbeError:
                        record_error(receipt, "RS-INT-AUD-01", route_key)
                        raise
            if args.run_as_negatives:
                outcomes = run_as_negatives(base_url, metadata, issuer, pki, callback_server,
                                            pki / "route-b-pkj.key", accounts, receipt=receipt)
                if any(outcome["status"] == "fail" for outcome in outcomes):
                    exit_code = 1
    except ProbeError as error:
        print(f"WP2 isolated probe failed: {error}", file=sys.stderr)
        exit_code = 1
    except Exception:
        print("WP2 isolated probe stopped after an unexpected local failure; details were suppressed.", file=sys.stderr)
        exit_code = 1
    try:
        write_receipt(preview, receipt)
    except (OSError, ProbeError) as error:
        print(f"Could not write sanitized WP2 receipt: {error}", file=sys.stderr)
        exit_code = 1
    if exit_code == 0:
        print("No token, authorization code, assertion, cookie, secret, or response body was written.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
