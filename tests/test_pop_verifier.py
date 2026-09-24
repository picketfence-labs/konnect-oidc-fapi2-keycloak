#!/usr/bin/env python3
import time
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

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
    app.verify_access_token(make_token(peer_certificate, scope="profile"), peer_certificate)
    raise AssertionError("missing required scope was accepted")
except app.TokenValidationError as error:
    assert str(error) == "required scope is missing"

try:
    app.verify_access_token(make_token(peer_certificate, cnf={}), peer_certificate)
    raise AssertionError("missing cnf thumbprint was accepted")
except app.TokenValidationError as error:
    assert str(error) == "certificate binding mismatch"

assert app.ALLOWED_ALGORITHMS == ("PS256",)
print("PoP verifier unit checks: PASS")
