#!/usr/bin/env python3
import json
import sys
import tempfile
import time
import unittest
from io import BytesIO
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import quote_from_bytes
from urllib.error import HTTPError

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
from jwt.jwks_client import _NoRedirectHandler
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.serialization import Encoding

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pop-verifier"))
import app


def issue_certificate(common_name, ca_key, ca_certificate, *, eku):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = int(time.time())
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.fromtimestamp(now - 60))
        .not_valid_after(__import__("datetime").datetime.fromtimestamp(now + 3600))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def make_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WP4 unit fixture CA")])
    now = int(time.time())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.fromtimestamp(now - 60))
        .not_valid_after(__import__("datetime").datetime.fromtimestamp(now + 3600))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


ca_key, ca_certificate = make_ca()
gateway_certificate = issue_certificate(
    app.API_UPSTREAM_COMMON_NAME,
    ca_key,
    ca_certificate,
    eku=ExtendedKeyUsageOID.CLIENT_AUTH,
)
same_ca_other_certificate = issue_certificate(
    "kong-fapi-mtls", ca_key, ca_certificate, eku=ExtendedKeyUsageOID.CLIENT_AUTH
)
same_cn_different_key_certificate = issue_certificate(
    app.API_UPSTREAM_COMMON_NAME,
    ca_key,
    ca_certificate,
    eku=ExtendedKeyUsageOID.CLIENT_AUTH,
)
client_certificate = issue_certificate(
    "kong-fapi-mtls", ca_key, ca_certificate, eku=ExtendedKeyUsageOID.CLIENT_AUTH
)
other_client_certificate = issue_certificate(
    "kong-fapi-pkj-mtls", ca_key, ca_certificate, eku=ExtendedKeyUsageOID.CLIENT_AUTH
)
gateway_der = gateway_certificate.public_bytes(Encoding.DER)
client_der = client_certificate.public_bytes(Encoding.DER)
other_client_der = other_client_certificate.public_bytes(Encoding.DER)
signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
app.JWK_CLIENT = SimpleNamespace(
    get_signing_key_from_jwt=lambda _: SimpleNamespace(key=signing_key.public_key())
)


def make_token(
    client_der_value,
    *,
    azp="third-party-fapi-mtls",
    algorithm="PS256",
    signing_private_key=None,
    **overrides,
):
    now = int(time.time())
    claims = {
        "iss": app.ISSUER,
        "aud": [app.AUDIENCE, "api-gateway-introspection"],
        "azp": azp,
        "iat": now,
        "nbf": now - 1,
        "exp": now + 60,
        "scope": "openid profile",
        "cnf": {"x5t#S256": app.base64url_sha256(client_der_value)},
        app.DEPARTMENT_CLAIM: "engineering",
        app.ROUTE_CLAIM: "engineering-route",
    }
    claims.update(overrides)
    key = (
        signing_private_key or signing_key
        if algorithm == "PS256"
        else "fixture-hmac-key-with-enough-bytes"
    )
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": "wp4-test"})


def headers_with_client_certificate(certificate, *, encoded=True):
    headers = Message()
    value = certificate.public_bytes(Encoding.PEM).decode("ascii")
    if encoded:
        value = quote_from_bytes(value.encode("ascii"), safe="")
    headers.add_header("X-Client-Cert", value)
    return headers


class PopVerifierTests(unittest.TestCase):
    def test_route_a_and_b_are_derived_from_signed_azp(self):
        for azp, expected in app.AZP_ROUTES.items():
            token = make_token(client_der, azp=azp)
            claims, thumbprint = app.verify_access_token(token)
            self.assertEqual(claims["azp"], azp)
            self.assertEqual(app.AZP_ROUTES[claims["azp"]], expected)
            self.assertEqual(thumbprint, app.base64url_sha256(client_der))

    def test_api_gateway_peer_requires_exact_pinned_leaf_not_only_ca_or_cn(self):
        with tempfile.TemporaryDirectory() as directory:
            pin_path = Path(directory) / "api-upstream.crt"
            pin_path.write_bytes(gateway_certificate.public_bytes(Encoding.PEM))
            self.assertEqual(app.load_pinned_gateway_certificate(pin_path), gateway_der)

            pin_path.write_bytes(same_ca_other_certificate.public_bytes(Encoding.PEM))
            with self.assertRaises(RuntimeError):
                app.load_pinned_gateway_certificate(pin_path)

        self.assertEqual(
            app.verify_api_gateway_peer(gateway_der, gateway_der),
            app.base64url_sha256(gateway_der),
        )
        for other in (
            b"not a certificate",
            same_ca_other_certificate.public_bytes(Encoding.DER),
            same_cn_different_key_certificate.public_bytes(Encoding.DER),
        ):
            with self.subTest(other=other[:16]), self.assertRaises(app.TokenValidationError):
                app.verify_api_gateway_peer(other, gateway_der)
        with self.assertRaises(app.TokenValidationError):
            app.verify_api_gateway_peer(None, gateway_der)

    def test_forwarded_certificate_requires_one_url_encoded_pem(self):
        headers = headers_with_client_certificate(client_certificate)
        self.assertEqual(app.forwarded_client_certificate_der(headers), client_der)

        missing = Message()
        with self.assertRaises(app.TokenValidationError):
            app.forwarded_client_certificate_der(missing)

        duplicate = headers_with_client_certificate(client_certificate)
        duplicate.add_header(
            "X-Client-Cert",
            quote_from_bytes(other_client_certificate.public_bytes(Encoding.PEM), safe=""),
        )
        with self.assertRaises(app.TokenValidationError):
            app.forwarded_client_certificate_der(duplicate)

        comma_ambiguous = Message()
        comma_ambiguous.add_header(
            "X-Client-Cert",
            quote_from_bytes(client_certificate.public_bytes(Encoding.PEM), safe="")
            + ","
            + quote_from_bytes(other_client_certificate.public_bytes(Encoding.PEM), safe=""),
        )
        with self.assertRaises(app.TokenValidationError):
            app.forwarded_client_certificate_der(comma_ambiguous)

    def test_forwarded_certificate_rejects_malformed_percent_pem_and_multiple_leaves(self):
        for invalid_value in (
            "%0Gnot-a-certificate",
            "%FF",
            quote_from_bytes(client_certificate.public_bytes(Encoding.PEM), safe="")
            + quote_from_bytes(other_client_certificate.public_bytes(Encoding.PEM), safe=""),
            "%00" + quote_from_bytes(client_certificate.public_bytes(Encoding.PEM), safe=""),
        ):
            with self.subTest(value=invalid_value[:20]):
                headers = Message()
                headers.add_header("X-Client-Cert", invalid_value)
                with self.assertRaises(app.TokenValidationError):
                    app.forwarded_client_certificate_der(headers)

    def test_forwarded_certificate_thumbprint_must_match_cnf_in_constant_time_path(self):
        headers = headers_with_client_certificate(client_certificate)
        correct = app.base64url_sha256(client_der)
        self.assertEqual(app.verify_forwarded_certificate_binding(headers, correct), correct)
        with self.assertRaises(app.TokenValidationError):
            app.verify_forwarded_certificate_binding(headers, app.base64url_sha256(other_client_der))

    def test_jwt_rechecks_audience_scope_algorithm_and_time_claims(self):
        valid = make_token(client_der)
        claims, _ = app.verify_access_token(valid)
        self.assertIn(app.AUDIENCE, claims["aud"])

        invalid_tokens = {
            "wrong audience": make_token(client_der, aud="other-api"),
            "missing scope": make_token(client_der, scope="profile"),
            "non-string scope": make_token(client_der, scope={"openid": True}),
            "expired": make_token(client_der, exp=int(time.time()) - 1),
            "not active yet": make_token(client_der, nbf=int(time.time()) + 600),
            "unknown azp": make_token(client_der, azp="unknown-client"),
            "missing azp": make_token(client_der, azp=None),
            "missing cnf thumbprint": make_token(client_der, cnf={}),
            "malformed cnf": make_token(client_der, cnf="not-an-object"),
            "HS256 algorithm": make_token(client_der, algorithm="HS256"),
        }
        for name, token in invalid_tokens.items():
            with self.subTest(name=name), self.assertRaises(app.TokenValidationError):
                app.verify_access_token(token)

        missing_nbf_claims = jwt.decode(
            make_token(client_der), options={"verify_signature": False}
        )
        del missing_nbf_claims["nbf"]
        missing_nbf_token = jwt.encode(
            missing_nbf_claims, signing_key, algorithm="PS256", headers={"kid": "wp4-test"}
        )
        claims, _ = app.verify_access_token(missing_nbf_token)
        self.assertNotIn("nbf", claims)

    def test_jwt_rejects_wrong_issuer_unknown_critical_header_and_bad_signature(self):
        with self.assertRaises(app.TokenValidationError):
            app.verify_access_token(make_token(client_der, iss="https://issuer.invalid/"))

        now = int(time.time())
        unknown_crit_token = jwt.encode(
            {
                "iss": app.ISSUER,
                "aud": [app.AUDIENCE, "api-gateway-introspection"],
                "azp": "third-party-fapi-mtls",
                "iat": now,
                "exp": now + 60,
                "scope": "openid",
                "cnf": {"x5t#S256": app.base64url_sha256(client_der)},
            },
            signing_key,
            algorithm="PS256",
            headers={"kid": "wp4-test", "crit": ["unknown-critical"], "unknown-critical": True},
        )
        with self.assertRaises(app.TokenValidationError):
            app.verify_access_token(unknown_crit_token)

        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bad_signature = make_token(client_der, signing_private_key=attacker_key)
        with self.assertRaises(app.TokenValidationError):
            app.verify_access_token(bad_signature)

    def test_jwks_unknown_kid_cooldown_and_rotation(self):
        unknown_kid_fetches = 0
        available_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
        available_jwk.update({"kid": "known-key", "use": "sig", "alg": "PS256"})
        live_jwks = {"keys": [available_jwk]}
        client = PyJWKClient(
            "https://keys.invalid/jwks", cache_keys=True, cooldown_duration=60
        )

        def fake_fetch_data():
            nonlocal unknown_kid_fetches
            unknown_kid_fetches += 1
            client.jwk_set_cache.put(live_jwks)
            client._last_successful_fetch = time.monotonic()
            return live_jwks

        client.fetch_data = fake_fetch_data
        for kid in ("unknown-1", "unknown-2", "unknown-3"):
            with self.assertRaises(PyJWKClientError):
                client.get_signing_key(kid)
        self.assertEqual(unknown_kid_fetches, 1)

        rotated_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
        rotated_jwk.update({"kid": "rotated-key", "use": "sig", "alg": "PS256"})
        live_jwks = {"keys": [rotated_jwk]}
        client._last_successful_fetch -= 61
        self.assertEqual(client.get_signing_key("rotated-key").key_id, "rotated-key")
        self.assertEqual(unknown_kid_fetches, 2)

    def test_jwks_redirect_is_not_followed(self):
        redirect_handler = _NoRedirectHandler()
        self.assertIsNone(
            redirect_handler.redirect_request(
                None,
                None,
                302,
                "Found",
                {"Location": "https://attacker.invalid/"},
                "https://attacker.invalid/",
            )
        )
        redirect_client = PyJWKClient("https://keys.invalid/jwks")
        redirect_error = HTTPError(
            "https://keys.invalid/jwks", 302, "Found", Message(), BytesIO(b"redirect body")
        )
        with patch("urllib.request.build_opener") as build_opener:
            build_opener.return_value.open.side_effect = redirect_error
            with self.assertRaises(PyJWKClientConnectionError):
                redirect_client.fetch_data()
            self.assertEqual(build_opener.return_value.open.call_count, 1)
            self.assertTrue(
                any(
                    isinstance(handler, _NoRedirectHandler)
                    for handler in build_opener.call_args.args
                )
            )

    def test_duplicate_authorization_values_are_rejected(self):
        headers = Message()
        headers.add_header("Authorization", "Bearer first-token")
        headers.add_header("Authorization", "Bearer second-token")
        self.assertIsNone(app.bearer_token(headers))

    def test_evidence_uses_azp_and_omits_untrusted_route_and_auth_headers(self):
        claims, token_thumbprint = app.verify_access_token(make_token(client_der))
        headers = headers_with_client_certificate(client_certificate)
        headers.add_header("X-Demo-Department", "engineering")
        headers.add_header("X-Demo-Route", "engineering-route")
        headers.add_header("X-Fapi-Route", "forged-route")
        headers.add_header("X-Fapi-Client-Auth", "forged-auth")
        evidence = app.build_evidence(
            headers,
            claims,
            token_thumbprint,
            app.base64url_sha256(client_der),
            app.base64url_sha256(gateway_der),
        )
        self.assertEqual(evidence["route"], "route-a")
        self.assertEqual(evidence["client_authentication"], "tls_client_auth")
        self.assertEqual(evidence["azp"], "third-party-fapi-mtls")
        self.assertTrue(evidence["binding_verified"])
        self.assertTrue(evidence["header_claims_match"])
        self.assertNotIn("forged-route", json.dumps(evidence))
        self.assertNotIn("forged-auth", json.dumps(evidence))

        unicode_claims = dict(claims)
        unicode_claims[app.DEPARTMENT_CLAIM] = "engineeré"
        unicode_headers = Message()
        unicode_headers.add_header("X-Demo-Department", "engineeré")
        unicode_headers.add_header("X-Demo-Route", "engineering-route")
        self.assertTrue(app.routing_evidence(unicode_headers, unicode_claims)["header_claims_match"])

    def test_evidence_is_sanitized(self):
        token = make_token(client_der)
        claims, token_thumbprint = app.verify_access_token(token)
        headers = headers_with_client_certificate(client_certificate)
        headers.add_header("Cookie", "private-session-cookie")
        headers.add_header("client_assertion", "private-client-assertion")
        evidence = app.build_evidence(
            headers,
            claims,
            token_thumbprint,
            app.base64url_sha256(client_der),
            app.base64url_sha256(gateway_der),
        )
        response = json.dumps(evidence, separators=(",", ":"))
        for forbidden in (
            token,
            "private-session-cookie",
            "private-client-assertion",
            "BEGIN CERTIFICATE",
            "BEGIN PRIVATE KEY",
            "X-Fapi-Route",
        ):
            self.assertNotIn(forbidden, response)


if __name__ == "__main__":
    unittest.main()
