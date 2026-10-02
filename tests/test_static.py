#!/usr/bin/env python3
import json
import re
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
assert 'assertion_delivery = {' in bridge_schema
assert 'default = "header"' in bridge_schema
assert '"transport_delegate"' in bridge_schema

transport_schema = (ROOT / "kong" / "plugins" / "fapi-as-mtls-transport" / "schema.lua").read_text()
assert 'name = "fapi-as-mtls-transport"' in transport_schema
assert "require(" not in transport_schema and 'require "' not in transport_schema
assert "custom_validator = function(config)" in transport_schema
assert "exactly the fixed Route A and Route B entries are required" in transport_schema
assert "eq = ngx.null" in transport_schema

api_foundation = (ROOT / "kong" / "foundation" / "api.yaml").read_text()
third_party_foundation = (ROOT / "kong" / "foundation" / "third-party.yaml").read_text()
assert api_foundation.count("fapi2-foundation") == 4
assert "DECK_API_INTROSPECTION_KEY_YAML" not in api_foundation
assert "{vault://env/API_INTROSPECTION_KEY}" in api_foundation
assert "{vault://env/API_UPSTREAM_KEY}" in api_foundation
assert not re.search(r"^(?:services|routes):\s*$", api_foundation, re.MULTILINE)
assert "fapi-as-mtls-transport" not in api_foundation
assert "fapi-client-auth-bridge" not in api_foundation
for entity_id in (
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
    "77777777-7777-4777-8777-777777777777",
):
    assert entity_id in api_foundation
assert third_party_foundation.count("fapi2-foundation") == 5
assert not re.search(r"^(?:services|routes):\s*$", third_party_foundation, re.MULTILINE)
assert third_party_foundation.count("name: fapi-as-mtls-transport") == 1
assert "fapi-client-auth-bridge" not in third_party_foundation
assert "88888888-8888-4888-8888-888888888888" in third_party_foundation
assert third_party_foundation.count("enabled: true") == 1
assert "{vault://env/ROUTE_A_TLS_KEY}" in third_party_foundation
assert "{vault://env/ROUTE_B_TLS_KEY}" in third_party_foundation
assert "route_id: 754519ff-b0b9-5ed5-94c0-e453d260c6c4" in third_party_foundation
assert "route_id: 0f45debe-a3a6-5207-aea3-637227fb96f2" in third_party_foundation

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
pop_dockerfile = (ROOT / "pop-verifier" / "Dockerfile").read_text()
assert "FROM python:3.13-alpine AS build" in pop_dockerfile
assert "pip install --no-cache-dir --target=/opt/python-deps -r requirements.txt" in pop_dockerfile
runtime_image = pop_dockerfile.split("\nFROM python:3.13-alpine\n", 1)[1]
assert "COPY --from=build /opt/python-deps /opt/python-deps" in runtime_image
assert 'shutil.rmtree(stdlib / "ensurepip"' in runtime_image
assert '"pip-*.dist-info"' in runtime_image and '"setuptools-*.dist-info"' in runtime_image
assert "RUN pip install" not in runtime_image

compose = (ROOT / "docker-compose.yml").read_text()
assert "quay.io/keycloak/keycloak:26.7.4" in compose
assert "quay.io/keycloak/keycloak:26.7.4@sha256:" in compose
assert "KC_HTTPS_CLIENT_AUTH: request" in compose
assert "kong-api:" in compose and "kong-third-party:" in compose
assert "KONG_PLUGINS: bundled" in compose
assert "KONG_PLUGINS: bundled,fapi-as-mtls-transport,fapi-client-auth-bridge" in compose
assert "KONNECT_API_CP_HOST" in compose and "KONNECT_API_TP_HOST" in compose
assert "KONNECT_THIRD_PARTY_CP_HOST" in compose and "KONNECT_THIRD_PARTY_TP_HOST" in compose
assert "KONG_LUA_SSL_TRUSTED_CERTIFICATE: system,/etc/kong/fapi/ca.crt" in compose
assert ".generated/pki/third-party-metadata.crt:/etc/kong/fapi/third-party-metadata.crt:ro" in compose
assert ".generated/pki/api-introspection.key:/etc/kong/fapi/api-introspection.key:ro" in compose
assert "./.generated/pki:/etc/kong/fapi" not in compose
assert "./keycloak/data:/opt/keycloak/data/h2" in compose
assert "./keycloak/data:/opt/keycloak/data\n" not in compose
assert "KONG_LICENSE_DATA" not in compose
assert "./ui/default.conf:/etc/nginx/conf.d/default.conf:ro" in compose
assert "./.generated/pki/ui.crt:/etc/nginx/tls/tls.crt:ro" in compose
assert '"3443:443"' in compose
assert "profiles: [demo]" in compose
service_matches = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\s*$", compose, re.MULTILINE))
service_blocks = {
    match.group(1): compose[match.start() : (service_matches[index + 1].start() if index + 1 < len(service_matches) else len(compose))]
    for index, match in enumerate(service_matches)
}
for gateway_name in ("kong-api", "kong-third-party"):
    block = service_blocks[gateway_name]
    assert "ports:" not in block
api_mounts = service_blocks["kong-api"].split("volumes:", 1)[1]
third_party_mounts = service_blocks["kong-third-party"].split("volumes:", 1)[1]
assert ".generated/pki/api-introspection.key:/etc/kong/fapi/api-introspection.key:ro" in api_mounts
assert ".generated/pki/api-upstream.key:/etc/kong/fapi/api-upstream.key:ro" in api_mounts
assert ".generated/pki/route-a.key:/etc/kong/fapi/route-a.key:ro" not in api_mounts
assert ".generated/pki/api-introspection.key:/etc/kong/fapi/api-introspection.key:ro" not in third_party_mounts
assert ".generated/pki/route-a.key:/etc/kong/fapi/route-a.key:ro" in third_party_mounts
assert ".generated/pki/route-b-pkj.key:/etc/kong/fapi/route-b-pkj.key:ro" in third_party_mounts
assert "API_INTROSPECTION_KEY; env API_UPSTREAM_KEY" in service_blocks["kong-api"]
assert "ROUTE_A_TLS_KEY; env ROUTE_B_TLS_KEY" in service_blocks["kong-third-party"]
assert "FAPI_AS_TRANSPORT_ISSUER" in service_blocks["kong-third-party"]
assert "KONG_NGINX_MAIN_ENV" in service_blocks["kong-third-party"]
assert "path: ./.generated/runtime-api.env" in service_blocks["kong-api"]
assert "path: ./.generated/runtime-third-party.env" in service_blocks["kong-third-party"]

ui = (ROOT / "ui" / "index.html").read_text()
assert ui.count("https://localhost:8443/api/fapi/") == 6
assert "http://localhost:8000/api/fapi" not in ui
assert 'id="department-header"' in ui
assert 'id="logical-route-header"' in ui
assert 'id="header-match"' in ui

makefile = (ROOT / "Makefile").read_text()
assert "./scripts/sync-keycloak-demo-data.py" in makefile
assert "up:\n\t./scripts/require-wp5-readiness.sh" in makefile

asset_script = (ROOT / "scripts" / "generate-dev-assets.sh").read_text()
assert 'generate-pki.py' in asset_script
assert 'if [[ ! -f "$PKI/route-b-pkj.key" ]]' in asset_script
assert 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072' in asset_script
assert 'chmod 600 "$GENERATED/deck.env" "$GENERATED/runtime.env" "$GENERATED/runtime-api.json" "$GENERATED/runtime-third-party.json" "$GENERATED/runtime-api.env" "$GENERATED/runtime-third-party.env"' in asset_script
generator = (ROOT / "scripts" / "generate-pki.py").read_text()
assert 'rsa_keygen_bits:3072' in generator
assert '"third-party-metadata", "third-party-metadata", "clientAuth"' in generator
assert '"api-introspection", "api-gateway-introspection", "clientAuth"' in generator
assert '"api-upstream", "api-gateway-upstream", "clientAuth"' in generator

versions = (ROOT / "infra" / "versions.tf").read_text()
assert "auth0/auth0" not in versions
assert not (ROOT / "infra" / "auth0.tf").exists()
assert not (ROOT / "kong" / "kong-par.yaml").exists()

workflow = (ROOT / ".github" / "workflows" / "images.yml").read_text()
assert "packages: write" in workflow
assert "sbom" in workflow.lower()
assert "trivy" in workflow.lower()
assert "sha-${{ github.sha }}" in workflow
assert "python3 -m pip install --requirement requirements-dev.txt" in workflow
assert "python3 -m pip install --requirement requirements-dev.txt" in (ROOT / ".github" / "workflows" / "validate.yml").read_text()
assert "PyYAML==6.0.2" in (ROOT / "requirements-dev.txt").read_text()

schema_script = (ROOT / "scripts" / "plugin-schema.sh").read_text()
assert 'check) OPERATION="schema-check"' in schema_script
assert 'sync) OPERATION="schema-sync"' in schema_script
target_cli = (ROOT / "scripts" / "wp1_target.py").read_text()
assert "core-entities/plugin-schemas" in target_cli
assert "has_next_page" in target_cli and "next_cursor" in target_cli

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
