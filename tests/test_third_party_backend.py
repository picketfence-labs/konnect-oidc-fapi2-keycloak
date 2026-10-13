#!/usr/bin/env python3
"""Offline contract tests; all TLS identities are disposable local fixtures."""

import concurrent.futures
import contextlib
import http.client
from http.server import BaseHTTPRequestHandler
from email.message import Message
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("third_party_backend", ROOT / "third-party-backend/app.py")
app = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = app
SPEC.loader.exec_module(app)


def evidence(route="route-a"):
    return {
        "route": route,
        "azp": "third-party-fapi-mtls" if route == "route-a" else "third-party-fapi-pkj-mtls",
        "client_authentication": "tls_client_auth" if route == "route-a" else "private_key_jwt",
        "department": "sales", "logical_route": "sales-route",
        "department_header": "sales", "logical_route_header": "sales-route",
        "token_certificate_thumbprint": "A" * 43,
        "forwarded_client_certificate_thumbprint": "A" * 43,
        "api_gateway_tls_peer_certificate_thumbprint": "B" * 43,
        "token_signature_verified": True, "binding_verified": True, "header_claims_match": True,
    }


def message(values):
    result = Message()
    for key, value in values:
        result[key] = value
    return result


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, error=None):
        self.status = status
        self.body = json.dumps(evidence()).encode() if body is None else body
        self.headers = message(headers if headers is not None else [("Content-Type", "application/json")])
        self.error = error
        self.read_sizes = []

    def read(self, size):
        self.read_sizes.append(size)
        if self.error:
            raise self.error
        return self.body[:size]


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.closed = False

    def putrequest(self, *args, **kwargs):
        self.calls.append((args, kwargs))

    def putheader(self, *args):
        self.calls.append(args)

    def endheaders(self):
        pass

    def getresponse(self):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self):
        self.closed = True


class ContractTests(unittest.TestCase):
    def fetch(self, response, expected=None):
        context = object()
        connection = FakeConnection(response)
        with patch.object(app.http.client, "HTTPSConnection", return_value=connection) as factory:
            result = app.fetch_evidence("user-token", expected or app.ROUTES["/evidence/route-a"], context)
        factory.assert_called_once_with("kong-api", 8443, timeout=5, context=context)
        self.assertTrue(connection.closed)
        self.assertEqual(connection.calls, [
            (("GET", "/fapi-api/evidence"), {"skip_accept_encoding": True}),
            ("Authorization", "Bearer user-token"), ("Accept", "application/json"),
        ])
        return result

    def test_fixed_upstream_result_and_failures(self):
        self.assertEqual(self.fetch(FakeResponse()), (200, evidence()))
        for status, expected in ((401, 401), (403, 403), (301, 502), (302, 502), (307, 502), (500, 502), (204, 502)):
            with self.subTest(status=status):
                result = self.fetch(FakeResponse(status, b"secret-cookie-token"))
                self.assertEqual(result[0], expected)
                self.assertNotIn("secret", json.dumps(result))
        for error, expected in ((socket.timeout("secret"), 504), (ssl.SSLError("secret"), 502),
                                (http.client.BadStatusLine("secret"), 502), (OSError("secret"), 502)):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(self.fetch(error)[0], expected)
        bad = [
            FakeResponse(body=b"x" * (app.MAX_RESPONSE_BYTES + 1)),
            FakeResponse(body=json.dumps(evidence()).encode() + b" " * app.MAX_RESPONSE_BYTES),
            FakeResponse(body=b"not-json-secret"), FakeResponse(body=b"[]"),
            FakeResponse(body=b'{"route":"route-a","route":"route-b"}'),
            FakeResponse(body=b"\xff"),
            FakeResponse(headers=[]), FakeResponse(headers=[("Content-Type", "text/html")]),
            FakeResponse(headers=[("Content-Type", "application/json"), ("Content-Type", "application/json")]),
        ]
        for length in ("-1", "secret", "9" * 5000, str(app.MAX_RESPONSE_BYTES + 1), "1"):
            bad.append(FakeResponse(headers=[("Content-Type", "application/json"), ("Content-Length", length)]))
        bad.append(FakeResponse(headers=[("Content-Type", "application/json"), ("Content-Length", "1"), ("Content-Length", "1")]))
        for response in bad:
            self.assertEqual(self.fetch(response), (502, {"error": "upstream_unavailable"}))
        response = FakeResponse(error=socket.timeout("secret"))
        self.assertEqual(self.fetch(response)[0], 504)
        self.assertEqual(response.read_sizes, [app.MAX_RESPONSE_BYTES + 1])

    def test_every_schema_field_missing_or_invalid_including_last(self):
        original = evidence()
        for field in original:
            for value in (None, 1, [], {}, "wrong", "\nsecret"):
                if field in app.TEXT_FIELDS and value is None:
                    continue
                candidate = {**original, field: value}
                with self.subTest(field=field, value=value):
                    with self.assertRaises(app.RejectedEvidence):
                        app.project_evidence(json.dumps(candidate).encode(), app.ROUTES["/evidence/route-a"])
            candidate = dict(original)
            del candidate[field]
            with self.assertRaises(app.RejectedEvidence):
                app.project_evidence(json.dumps(candidate).encode(), app.ROUTES["/evidence/route-a"])
        for field in app.TEXT_FIELDS:
            for value in ("x" * 257, "\x7f", "\x00"):
                with self.assertRaises(app.RejectedEvidence):
                    app.project_evidence(json.dumps({**original, field: value}).encode(), app.ROUTES["/evidence/route-a"])
        self.assertEqual(self.fetch(FakeResponse(body=json.dumps({**original, "header_claims_match": False}).encode()))[0], 200)
        nulls = {**original, **dict.fromkeys(app.TEXT_FIELDS), "header_claims_match": False}
        self.assertEqual(self.fetch(FakeResponse(body=json.dumps(nulls).encode()))[0], 200)
        for field in ("binding_verified", "token_signature_verified"):
            self.assertEqual(self.fetch(FakeResponse(body=json.dumps({**original, field: False}).encode()))[0], 502)
        for candidate in (
            {**original, "forwarded_client_certificate_thumbprint": "C" * 43},
            {**original, "department_header": "engineering"},
            {**original, "logical_route_header": "other"},
            {**original, "department": "", "department_header": ""},
        ):
            self.assertEqual(self.fetch(FakeResponse(body=json.dumps(candidate).encode()))[0], 502)
        # Unknown upstream credential fields are never propagated.
        extended = {**original, "access_token": "secret", "cookie": "secret", "client_assertion": "secret"}
        self.assertEqual(self.fetch(FakeResponse(body=json.dumps(extended).encode()))[1], original)
        self.assertEqual(self.fetch(FakeResponse(body=json.dumps(evidence("route-b")).encode()), app.ROUTES["/evidence/route-b"]), (200, evidence("route-b")))

    def test_bearer_single_bounded_and_strict(self):
        self.assertEqual(app.bearer_token(message([("Authorization", "bEaReR abc.DEF-_~+/==")])), "abc.DEF-_~+/==")
        for values in ([], ["Bearer x", "Bearer y"], ["Basic x"], ["Bearer"], ["Bearer "],
                       ["Bearer a b"], ["Bearer\tx"], ["Bearer x\nCookie: secret"],
                       ["Bearer x,y"], ["Bearer x=y"], ["Bearer café"], ["Bearer " + "x" * 8193]):
            self.assertIsNone(app.bearer_token(message([("Authorization", value) for value in values])))

    def test_each_peer_pin_conjunct(self):
        self.assertTrue(app.trusted_peer(b"pin", b"pin"))
        for peer, pin in ((None, b"pin"), (b"", b"pin"), (b"pin", None), (b"pin", b""), (b"other", b"pin")):
            self.assertFalse(app.trusted_peer(peer, pin))

    def test_environment_cannot_select_destination(self):
        with patch.dict(os.environ, {"API_HOST": "evil", "API_URL": "https://evil", "BACKEND_TLS_CA": "/fixture/ca"}):
            self.assertEqual(app.TLSFiles.from_environment().ca, "/fixture/ca")
            self.assertEqual(self.fetch(FakeResponse())[0], 200)


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)


class TLSFixture:
    def __init__(self, directory):
        self.root = Path(directory)
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                "-subj", "/CN=test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", self.root / "ca.key", "-out", self.root / "ca.crt")
        for name, usage, san in (("backend", "serverAuth", "DNS:localhost"), ("provider", "serverAuth", "DNS:kong-api"),
                                 ("wrong-host", "serverAuth", "DNS:wrong-host"), ("hop", "clientAuth", None),
                                 ("other-hop", "clientAuth", None), ("route-a", "clientAuth", None), ("route-b", "clientAuth", None)):
            self.issue(name, usage, san)

    def issue(self, name, usage, san):
        key, cert, request = [self.root / (name + extension) for extension in (".key", ".crt", ".csr")]
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=" + name,
                "-keyout", key, "-out", request)
        extensions = self.root / (name + ".ext")
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + usage + "\n"
                              + ("subjectAltName=" + san + "\n" if san else ""))
        openssl("x509", "-req", "-in", request, "-CA", self.root / "ca.crt", "-CAkey", self.root / "ca.key", "-CAcreateserial",
                "-days", "1", "-extfile", extensions, "-out", cert)

    def path(self, name):
        return str(self.root / name)

    def client(self, name="hop"):
        context = app.verified_context(ssl.Purpose.SERVER_AUTH, self.path("ca.crt"))
        if name:
            context.load_cert_chain(self.path(name + ".crt"), self.path(name + ".key"))
        return context

    def files(self):
        return app.TLSFiles(self.path("ca.crt"), self.path("backend.crt"), self.path("backend.key"), self.path("hop.crt"),
                            self.path("route-a.crt"), self.path("route-a.key"), self.path("route-b.crt"), self.path("route-b.key"))


class ProviderHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observations.append((self.path, dict(self.headers), self.connection.getpeercert(binary_form=True)))
        route = "route-b" if self.headers.get("Authorization") == "Bearer user-b" else "route-a"
        data = json.dumps({**evidence(route), "access_token": "secret-upstream"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", "secret-upstream")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class TLSContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="tp-backend-tests-")
        cls.fixture = TLSFixture(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def provider(self, certificate="provider"):
        server = app.QuietServer(("127.0.0.1", 0), ProviderHandler)
        context = app.verified_context(ssl.Purpose.CLIENT_AUTH, self.fixture.path("ca.crt"))
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(self.fixture.path(certificate + ".crt"), self.fixture.path(certificate + ".key"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.observations = []
        return server

    def request(self, server, path="/evidence/route-a", token="user-a", client="hop", method="GET", extra=()):
        connection = http.client.HTTPSConnection("localhost", server.server_port, context=self.fixture.client(client), timeout=3)
        connection.putrequest(method, path, skip_accept_encoding=True)
        if token is not None:
            connection.putheader("Authorization", "Bearer " + token)
        for key, value in extra:
            connection.putheader(key, value)
        connection.endheaders()
        try:
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            self.assertIsNone(response.getheader("Set-Cookie"))
            return response.status, json.loads(body)
        finally:
            connection.close()

    def redirect_socket(self, provider):
        original = socket.create_connection

        def connect(address, *args, **kwargs):
            if address == ("kong-api", 8443):
                address = ("127.0.0.1", provider.server_port)
            return original(address, *args, **kwargs)
        return patch.object(socket, "create_connection", side_effect=connect)

    def test_real_tls_concurrent_route_context_and_token_isolation(self):
        with running(self.provider()) as provider, running(app.create_server("127.0.0.1", 0, self.fixture.files())) as backend:
            contexts = backend.route_contexts
            self.assertIsNot(contexts["route-a"], contexts["route-b"])
            for context in contexts.values():
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            with self.assertRaises(TypeError):
                contexts["route-a"] = contexts["route-b"]
            self.assertEqual(backend.gateway_pin, ssl.PEM_cert_to_DER_cert(Path(self.fixture.path("hop.crt")).read_text()))
            with self.redirect_socket(provider), concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(self.request, backend, "/evidence/route-" + route, "user-" + route, extra=(
                    ("Cookie", "session-secret"), ("client_assertion", "assertion-secret"),
                    ("X-Client-Cert", "forged"), ("X-Fapi-Route", "route-b"), ("X-Demo-Department", "forged"),
                )) for route in ("a", "b") * 4]
                results = [future.result() for future in futures]
            self.assertEqual(len(provider.observations), 8)
            for index, result in enumerate(results):
                route = "route-a" if index % 2 == 0 else "route-b"
                self.assertEqual(result, (200, evidence(route)))
            pins = {route: ssl.PEM_cert_to_DER_cert(Path(self.fixture.path(route + ".crt")).read_text()) for route in ("route-a", "route-b")}
            for path, headers, peer in provider.observations:
                self.assertEqual(path, "/fapi-api/evidence")
                self.assertEqual(set(headers), {"Host", "Authorization", "Accept"})
                self.assertEqual(headers["Host"], "kong-api:8443")
                self.assertEqual(peer, pins["route-a" if headers["Authorization"] == "Bearer user-a" else "route-b"])

    def test_real_entry_rejects_each_gate_and_health_never_calls_provider(self):
        with running(app.create_server("127.0.0.1", 0, self.fixture.files())) as backend, patch.object(app, "fetch_evidence") as fetch:
            self.assertEqual(self.request(backend, "/healthz", None), (200, {"status": "ok"}))
            for client in ("other-hop", "route-a", "route-b"):
                self.assertEqual(self.request(backend, client=client)[0], 401)
                self.assertEqual(self.request(backend, "/healthz", None, client=client)[0], 401)
            with self.assertRaises((ssl.SSLError, OSError)):
                self.request(backend, client=None)
            for path in ("/evidence/route-a?url=https://evil", "/evidence/route-b?x=1", "/healthz?x=1", "/evidence/route-a/", "/evidence/%72oute-a", "https://evil/evidence/route-a", "/unknown"):
                self.assertEqual(self.request(backend, path)[0], 404)
            for extra in ((("Authorization", "Bearer duplicate"),), (("Content-Length", "1"),), (("Transfer-Encoding", "chunked"),)):
                self.assertIn(self.request(backend, extra=extra)[0], (400, 401))
            self.assertEqual(self.request(backend, token=None)[0], 401)
            for method in ("POST", "PUT", "DELETE", "OPTIONS", "PATCH"):
                self.assertEqual(self.request(backend, method=method)[0], 501)
            fetch.assert_not_called()

    def test_real_outbound_hostname_and_ca_are_verified_independently(self):
        for certificate in ("wrong-host", "provider"):
            with running(self.provider(certificate)) as provider, self.redirect_socket(provider):
                _, contexts, _ = app.create_contexts(self.fixture.files())
                context = contexts["route-a"]
                if certificate == "provider":
                    # Same valid hostname, no fixture CA trusted: independent CA rejection.
                    context = ssl.create_default_context()
                    context.load_cert_chain(self.fixture.path("route-a.crt"), self.fixture.path("route-a.key"))
                self.assertEqual(app.fetch_evidence("user-a", app.ROUTES["/evidence/route-a"], context)[0], 502)
                self.assertEqual(provider.observations, [])

    def test_missing_tls_material_fails_before_listener_creation(self):
        files = self.fixture.files()
        for field in files.__dataclass_fields__:
            with self.subTest(field=field), self.assertRaises((OSError, ValueError, ssl.SSLError)):
                app.create_server("127.0.0.1", 0, app.TLSFiles(**{**vars(files), field: self.fixture.path("missing")}))

    def test_private_unix_readiness_requires_live_loaded_configuration(self):
        with tempfile.TemporaryDirectory(prefix="backend-ready-") as directory:
            os.chmod(directory, 0o700)
            path = str(Path(directory) / "ready.sock")
            files = self.fixture.files()
            # Configuration and TLS listener are created before readiness starts.
            with running(app.create_server("127.0.0.1", 0, files)), running(app.ReadyServer(files, path)) as readiness, \
                 patch.object(app, "fetch_evidence") as fetch:
                status = app.check_ready(path)
                self.assertTrue(status["ready"])
                self.assertEqual(status["config_sha256"], app.public_config_hash(files))
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(set(status), {"schema_version", "ready", "generation", "config_sha256", "pid"})
                # Last identity is invalidated; a previously ready process must fail closed.
                readiness.files = app.TLSFiles(**{**vars(files), "route_b_key": self.fixture.path("missing")})
                with self.assertRaises(ValueError):
                    app.check_ready(path)
                fetch.assert_not_called()
            with self.assertRaises(OSError):
                app.check_ready(path)
            os.chmod(directory, 0o755)
            with self.assertRaises(ValueError):
                app.ReadyServer(files, str(Path(directory) / "other.sock"))

    def test_readiness_status_rejects_each_late_invalid_field(self):
        valid = {"schema_version": 1, "ready": True, "generation": "a" * 32,
                 "config_sha256": "b" * 64, "pid": 123}
        self.assertEqual(app.validate_ready_status(valid), valid)
        for field in valid:
            for invalid in (None, [], {}, False, "secret", 1.1):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    app.validate_ready_status({**valid, field: invalid})
        with patch.object(sys, "argv", ["app.py", "--check-ready"]), \
             patch.object(app, "check_ready", side_effect=OSError("private-secret")), \
             patch.object(app, "create_server") as server, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(app.main(), 1)
            self.assertEqual(out.getvalue(), "")
            server.assert_not_called()


class SemanticMutationTests(unittest.TestCase):
    def test_security_properties_kill_semantic_mutants(self):
        # Execute changed code only in memory. Each original behavioral test must
        # fail with an assertion (not an import/fixture error) for its mutant.
        source = (ROOT / "third-party-backend/app.py").read_text()
        cases = (
            ("auth_status_propagation", "return response.status, {\"error\": \"upstream_unauthorized\"}",
             "return 200, {\"error\": \"upstream_unauthorized\"}",
             ContractTests, "test_fixed_upstream_result_and_failures"),
            ("late_field_strict_type", 'if type(value) is not bool or (name != "header_claims_match" and value is not True):',
             'if name != "header_claims_match" and (type(value) is not bool or value is not True):',
             ContractTests, "test_every_schema_field_missing_or_invalid_including_last"),
            ("exact_peer_pin", "return bool(peer and pin and hmac.compare_digest(peer, pin))", "return bool(peer and pin)",
             ContractTests, "test_each_peer_pin_conjunct"),
            ("duplicate_authorization", "if len(values) != 1 or len(values[0]) > MAX_TOKEN_BYTES + 7:",
             "if not values or len(values[0]) > MAX_TOKEN_BYTES + 7:",
             ContractTests, "test_bearer_single_bounded_and_strict"),
            ("bounded_body", "if len(body) > MAX_RESPONSE_BYTES or (lengths and len(body) != int(lengths[0])):",
             "if lengths and len(body) != int(lengths[0]):",
             ContractTests, "test_fixed_upstream_result_and_failures"),
            ("hostname_verification", "context.load_cert_chain(certificate, key)\n        outbound[route] = context",
             "context.load_cert_chain(certificate, key)\n        context.check_hostname = False\n        outbound[route] = context",
             TLSContractTests, "test_real_outbound_hostname_and_ca_are_verified_independently"),
            ("route_context_isolation", '("route-b", files.route_b_certificate, files.route_b_key)',
             '("route-b", files.route_a_certificate, files.route_a_key)',
             TLSContractTests, "test_real_tls_concurrent_route_context_and_token_isolation"),
            ("minimal_outbound_headers", 'connection.putheader("Accept", "application/json")',
             'connection.putheader("Accept", "application/json")\n        connection.putheader("Cookie", "leaked-secret")',
             TLSContractTests, "test_real_tls_concurrent_route_context_and_token_isolation"),
        )
        original = globals()["app"]
        for name, before, after, test_class, test_name in cases:
            with self.subTest(property=name):
                self.assertEqual(source.count(before), 1, "mutation location must be unambiguous")
                mutant = types.ModuleType("backend_mutant_" + name)
                sys.modules[mutant.__name__] = mutant
                try:
                    exec(compile(source.replace(before, after), str(ROOT / "third-party-backend/app.py"), "exec"), mutant.__dict__)
                    globals()["app"] = mutant
                    result = unittest.TestResult()
                    unittest.TestSuite([test_class(test_name)]).run(result)
                    self.assertEqual(result.errors, [], "mutant must fail for the behavioral assertion, not setup/runtime error")
                    self.assertTrue(result.failures, "semantic mutant survived: " + name)
                    print("semantic mutation killed:", name)
                finally:
                    globals()["app"] = original
                    del sys.modules[mutant.__name__]


if __name__ == "__main__":
    unittest.main(verbosity=2)
