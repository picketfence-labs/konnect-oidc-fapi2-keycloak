#!/usr/bin/env python3
import time
from types import SimpleNamespace
from io import BytesIO
from email.message import Message
from unittest.mock import patch
from urllib.error import HTTPError

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
from jwt.jwks_client import _NoRedirectHandler

import app


private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
app.JWK_CLIENT = SimpleNamespace(
    get_signing_key_from_jwt=lambda _: SimpleNamespace(key=public_key)
)


def make_token(peer_der, **overrides):
    now = int(time.time())
    claims = {
        "iss": app.ISSUER,
        "aud": app.AUDIENCE,
        "iat": now,
        "nbf": now - 1,
        "exp": now + 60,
        "scope": "openid profile",
        "cnf": {"x5t#S256": app.base64url_sha256(peer_der)},
        app.DEPARTMENT_CLAIM: "engineering",
        app.ROUTE_CLAIM: "engineering-route",
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="PS256", headers={"kid": "test"})


peer_certificate = b"test peer certificate DER"
token = make_token(peer_certificate)
claims, token_thumbprint, peer_thumbprint = app.verify_access_token(token, peer_certificate)
assert claims[app.DEPARTMENT_CLAIM] == "engineering"
assert token_thumbprint == peer_thumbprint == app.base64url_sha256(peer_certificate)

routing = app.routing_evidence(
    {"X-Demo-Department": "engineering", "X-Demo-Route": "engineering-route"},
    claims,
)
assert routing == {
    "department": "engineering",
    "logical_route": "engineering-route",
    "department_header": "engineering",
    "logical_route_header": "engineering-route",
    "header_claims_match": True,
}
spoofed_routing = app.routing_evidence(
    {"X-Demo-Department": "sales", "X-Demo-Route": "sales-route"}, claims
)
assert spoofed_routing["header_claims_match"] is False

try:
    app.verify_access_token(token, b"different certificate")
    raise AssertionError("certificate mismatch was accepted")
except app.TokenValidationError as error:
    assert str(error) == "certificate binding mismatch"

try:
    app.verify_access_token(make_token(peer_certificate, aud="wrong-audience"), peer_certificate)
    raise AssertionError("wrong audience was accepted")
except app.TokenValidationError as error:
    assert str(error) == "JWT validation failed"

try:
    app.verify_access_token(make_token(peer_certificate, iss="https://issuer.invalid/"), peer_certificate)
    raise AssertionError("wrong issuer was accepted")
except app.TokenValidationError as error:
    assert str(error) == "JWT validation failed"

try:
    app.verify_access_token(make_token(peer_certificate, scope="profile"), peer_certificate)
    raise AssertionError("missing required scope was accepted")
except app.TokenValidationError as error:
    assert str(error) == "required scope is missing"

try:
    app.verify_access_token(make_token(peer_certificate, cnf={}), peer_certificate)
    raise AssertionError("missing cnf thumbprint was accepted")
except app.TokenValidationError as error:
    assert str(error) == "certificate binding mismatch"

unknown_crit_token = jwt.encode(
    {
        "iss": app.ISSUER,
        "aud": app.AUDIENCE,
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
        "scope": "openid",
        "cnf": {"x5t#S256": app.base64url_sha256(peer_certificate)},
    },
    private_key,
    algorithm="PS256",
    headers={"kid": "test", "crit": ["unknown-critical"], "unknown-critical": True},
)
try:
    app.verify_access_token(unknown_crit_token, peer_certificate)
    raise AssertionError("unknown critical JWT header was accepted")
except app.TokenValidationError as error:
    assert str(error) == "JWT validation failed"

unknown_kid_fetches = 0
available_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
available_jwk.update({"kid": "known-key", "use": "sig", "alg": "PS256"})
live_jwks = {"keys": [available_jwk]}
client = PyJWKClient("https://keys.invalid/jwks", cache_keys=True, cooldown_duration=60)


def fake_fetch_data():
    global unknown_kid_fetches
    unknown_kid_fetches += 1
    client.jwk_set_cache.put(live_jwks)
    client._last_successful_fetch = time.monotonic()
    return live_jwks


client.fetch_data = fake_fetch_data
for kid in ("unknown-1", "unknown-2", "unknown-3"):
    try:
        client.get_signing_key(kid)
        raise AssertionError("unknown kid unexpectedly matched")
    except PyJWKClientError:
        pass
assert unknown_kid_fetches == 1

rotated_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
rotated_jwk.update({"kid": "rotated-key", "use": "sig", "alg": "PS256"})
live_jwks = {"keys": [rotated_jwk]}
client._last_successful_fetch -= 61
assert client.get_signing_key("rotated-key").key_id == "rotated-key"
assert unknown_kid_fetches == 2

redirect_handler = _NoRedirectHandler()
assert redirect_handler.redirect_request(
    None, None, 302, "Found", {"Location": "https://attacker.invalid/"}, "https://attacker.invalid/"
) is None
redirect_client = PyJWKClient("https://keys.invalid/jwks")
redirect_error = HTTPError(
    "https://keys.invalid/jwks", 302, "Found", Message(), BytesIO(b"redirect body")
)
with patch("urllib.request.build_opener") as build_opener:
    build_opener.return_value.open.side_effect = redirect_error
    try:
        redirect_client.fetch_data()
        raise AssertionError("JWKS redirect was followed")
    except PyJWKClientConnectionError:
        pass
    assert build_opener.return_value.open.call_count == 1
    assert any(isinstance(handler, _NoRedirectHandler) for handler in build_opener.call_args.args)

assert app.ALLOWED_ALGORITHMS == ("PS256",)
hs256_token = jwt.encode(
    jwt.decode(token, options={"verify_signature": False}),
    "attacker-controlled-hmac-key-that-is-long-enough",
    algorithm="HS256",
    headers={"kid": "test"},
)
try:
    app.verify_access_token(hs256_token, peer_certificate)
    raise AssertionError("HS256 token was accepted by the PS256-only verifier")
except app.TokenValidationError as error:
    assert str(error) == "JWT validation failed"
print("PoP verifier unit checks: PASS")
