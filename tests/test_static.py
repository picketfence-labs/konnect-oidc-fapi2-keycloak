#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

state = (ROOT / "kong" / "kong.yaml").read_text()
assert state.count("name: fapi-mtls-service") == 1
assert state.count("name: fapi-pkj-mtls-service") == 1
assert state.count("name: fapi-mtls-route") == 1
assert state.count("name: fapi-pkj-mtls-route") == 1
assert "paths: [/api/fapi/mtls]" in state
assert "paths: [/api/fapi/pkj-mtls]" in state
assert state.count("require_pushed_authorization_requests: true") == 2
assert state.count("require_proof_key_for_code_exchange: true") == 2
assert state.count("scopes: [openid, profile]") == 2
assert "offline_access" not in state
assert state.count("tls_client_auth_ssl_verify: true") == 2
assert state.count('redirect_uri: ["https://localhost:8443/api/fapi/') == 2
assert "http://localhost:8000/api/fapi" not in state
assert state.count('origins: ["https://localhost:3443"]') == 2
assert state.count('login_redirect_uri: ["https://localhost:3443/') == 2
assert state.count('logout_redirect_uri: ["https://localhost:3443/') == 2
assert "http://localhost:3000" not in state
assert "client_auth: [tls_client_auth]" in state
assert "token_post_args_client: [client_assertion, client_assertion_type]" in state
assert "pushed_authorization_request_endpoint_auth_method: private_key_jwt" in state
assert "revocation_endpoint_auth_method: private_key_jwt" in state
assert "client_alg: [PS256]" in state
assert 'd: "{vault://env/route-b-jwk/d}"' in state
assert 'qi: "{vault://env/route-b-jwk/qi}"' in state
assert 'cert: "{vault://env/route-a-tls-cert}"' in state
assert 'key: "{vault://env/route-a-tls-key}"' in state
assert 'cert: "{vault://env/route-b-tls-cert}"' in state
assert 'key: "{vault://env/route-b-tls-key}"' in state
assert "DECK_FAPI_CA_CERT_YAML" in state
assert "DECK_ROUTE_B_JWK_N" in state
assert "DECK_ROUTE_B_JWK_E" in state
assert state.count("DECK_ROUTE_B_JWK_KID") == 2
assert '"n": ${{ env "DECK_ROUTE_B_JWK_N" }}' in state
assert "protocols: [grpc, grpcs, http, https]" in state
assert "session_cookie_name: fapi_route_a_session" in state
assert "session_cookie_name: fapi_route_b_session" in state
assert "DECK_ROUTE_A_SESSION_SECRET" in state
assert "DECK_ROUTE_B_SESSION_SECRET" in state
assert "client_certificate: 11111111-1111-4111-8111-111111111111" in state
assert "client_certificate: 22222222-2222-4222-8222-222222222222" in state
assert "headers: [Cookie, client_assertion, client_assertion_type" in state
assert "PRIVATE KEY" not in state

realm = json.loads((ROOT / "keycloak" / "realm-template.json").read_text())
clients = {client["clientId"]: client for client in realm["clients"]}
assert set(clients) == {"kong-fapi-mtls", "kong-fapi-pkj-mtls"}
assert clients["kong-fapi-mtls"]["clientAuthenticatorType"] == "client-x509"
assert clients["kong-fapi-pkj-mtls"]["clientAuthenticatorType"] == "client-jwt"
for client in clients.values():
    assert client["webOrigins"] == []
    attributes = client["attributes"]
    assert attributes["pkce.code.challenge.method"] == "S256"
    assert attributes["require.pushed.authorization.requests"] == "true"
    assert attributes["tls.client.certificate.bound.access.tokens"] == "true"
    routing_mappers = {
        mapper["name"]: mapper for mapper in client["protocolMappers"]
    }
    assert routing_mappers["department"]["config"]["claim.name"] == (
        "https://fapi-demo\\.example\\.com/department"
    )
    assert routing_mappers["logical-route"]["config"]["claim.name"] == (
        "https://fapi-demo\\.example\\.com/route"
    )
assert clients["kong-fapi-pkj-mtls"]["attributes"]["token.endpoint.auth.signing.alg"] == "PS256"
assert clients["kong-fapi-mtls"]["attributes"]["post.logout.redirect.uris"] == (
    "https://localhost:3443/?logout=route-a"
)
assert clients["kong-fapi-pkj-mtls"]["attributes"]["post.logout.redirect.uris"] == (
    "https://localhost:3443/?logout=route-b"
)
assert realm["accessCodeLifespan"] <= 60
assert realm["clientPolicies"]["policies"][0]["profiles"] == ["fapi-2-security-profile"]
assert {user["attributes"]["department"][0] for user in realm["users"]} == {
    "sales",
    "engineering",
}
assert all(user.get("firstName") and user.get("lastName") for user in realm["users"])

user_profile = json.loads((ROOT / "keycloak" / "user-profile.json").read_text())
profile_attributes = {attribute["name"] for attribute in user_profile["attributes"]}
assert {"department", "departement", "route"}.issubset(profile_attributes)
assert all(
    attribute["permissions"]["edit"] == ["admin"]
    for attribute in user_profile["attributes"]
)

bridge = (ROOT / "kong" / "plugins" / "fapi-client-auth-bridge" / "handler.lua").read_text()
bridge_schema = (ROOT / "kong" / "plugins" / "fapi-client-auth-bridge" / "schema.lua").read_text()
assert 'require "' not in bridge_schema
assert 'alg = "PS256"' in bridge
assert "RSA_PKCS1_PSS_PADDING" in bridge
assert "random.bytes(32, true)" in bridge
assert "aud = conf.issuer" in bridge
assert "iss = conf.client_id" in bridge
assert "sub = conf.client_id" in bridge
assert "client_assertion_type" in bridge
assert "supplied_by_client" in bridge
assert "verify_discovery_issuer" in bridge
assert "metadata.issuer ~= conf.issuer" in bridge
assert "ssl_verify = true" in bridge

verifier = (ROOT / "pop-verifier" / "app.py").read_text()
assert '"verify_nbf": True' in verifier
assert '"require": ["exp", "iat", "iss", "aud", "cnf"]' in verifier
assert "hmac.compare_digest" in verifier
assert 'claims.get("cnf", {}).get("x5t#S256")' in verifier
assert 'os.environ.get("OIDC_ALLOWED_ALGORITHMS", "PS256")' in verifier
assert "algorithms=list(ALLOWED_ALGORITHMS)" in verifier
assert "context.verify_mode = ssl.CERT_REQUIRED" in verifier
assert "context.verify_flags &= ~ssl.VERIFY_X509_STRICT" in verifier
assert "ssl_context=verified_ssl_context()" in verifier
assert "raw tokens" not in verifier.lower()
assert '"department_header": department_header' in verifier
assert '"logical_route_header": logical_route_header' in verifier
assert '"header_claims_match": header_claims_match' in verifier

compose = (ROOT / "docker-compose.yml").read_text()
assert "quay.io/keycloak/keycloak:26.7.4" in compose
assert "quay.io/keycloak/keycloak:26.7.4@sha256:" in compose
assert "KC_HTTPS_CLIENT_AUTH: request" in compose
assert "KONG_PLUGINS: bundled,fapi-client-auth-bridge" in compose
assert "KONG_LUA_SSL_TRUSTED_CERTIFICATE: system,/etc/kong/fapi/ca.crt" in compose
assert "KONG_SSL_CERT: /etc/kong/fapi/kong-proxy.crt" in compose
assert "KONG_SSL_CERT_KEY: /etc/kong/fapi/kong-proxy.key" in compose
assert "ROUTE_B_JWK: ${ROUTE_B_JWK}" in compose
assert "ROUTE_A_TLS_CERT: ${ROUTE_A_TLS_CERT}" in compose
assert "ROUTE_A_TLS_KEY: ${ROUTE_A_TLS_KEY}" in compose
assert "ROUTE_B_TLS_CERT: ${ROUTE_B_TLS_CERT}" in compose
assert "ROUTE_B_TLS_KEY: ${ROUTE_B_TLS_KEY}" in compose
assert "./keycloak/data:/opt/keycloak/data/h2" in compose
assert "./keycloak/data:/opt/keycloak/data\n" not in compose
assert "KONG_LICENSE_DATA" not in compose
assert "./ui/default.conf:/etc/nginx/conf.d/default.conf:ro" in compose
assert "./.generated/pki/ui.crt:/etc/nginx/tls/tls.crt:ro" in compose
assert '"3443:443"' in compose

ui = (ROOT / "ui" / "index.html").read_text()
assert ui.count("https://localhost:8443/api/fapi/") == 6
assert "http://localhost:8000/api/fapi" not in ui
assert 'id="department-header"' in ui
assert 'id="logical-route-header"' in ui
assert 'id="header-match"' in ui

makefile = (ROOT / "Makefile").read_text()
assert "./scripts/sync-keycloak-demo-data.py" in makefile

asset_script = (ROOT / "scripts" / "generate-dev-assets.sh").read_text()
assert 'issue_certificate kong-proxy localhost serverAuth "DNS:localhost,IP:127.0.0.1"' in asset_script
assert 'issue_certificate ui localhost serverAuth "DNS:localhost,IP:127.0.0.1"' in asset_script
assert '-addext "keyUsage=critical,keyCertSign,cRLSign"' in asset_script

versions = (ROOT / "infra" / "versions.tf").read_text()
assert "auth0/auth0" not in versions
assert not (ROOT / "infra" / "auth0.tf").exists()
assert not (ROOT / "kong" / "kong-par.yaml").exists()

workflow = (ROOT / ".github" / "workflows" / "images.yml").read_text()
assert "packages: write" in workflow
assert "sbom" in workflow.lower()
assert "trivy" in workflow.lower()
assert "sha-${{ github.sha }}" in workflow

schema_script = (ROOT / "scripts" / "plugin-schema.sh").read_text()
assert "core-entities/plugin-schemas" in schema_script
assert 'MODE" != "check"' in schema_script
assert 'MODE" != "sync"' in schema_script

private_key_markers = (
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN RSA " + "PRIVATE KEY-----",
)

for path in ROOT.rglob("*"):
    if not path.is_file() or any(part in {".git", ".generated", ".terraform"} for part in path.parts):
        continue
    if ".tfstate" in path.name:
        continue
    if path.suffix in {".html", ".png", ".jpg", ".woff", ".woff2"}:
        continue
    text = path.read_text(errors="ignore")
    for marker in private_key_markers:
        assert marker not in text, path

print("static checks: PASS")
