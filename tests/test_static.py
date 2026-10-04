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
assert set(clients) == {
    "third-party-fapi-mtls",
    "third-party-fapi-pkj-mtls",
    "api-gateway-introspection",
}
route_a = clients["third-party-fapi-mtls"]
route_b = clients["third-party-fapi-pkj-mtls"]
introspection = clients["api-gateway-introspection"]
assert route_a["clientAuthenticatorType"] == "client-x509"
assert route_a["attributes"]["x509.subjectdn"] == "CN=kong-fapi-mtls"
assert route_b["clientAuthenticatorType"] == "client-jwt"
assert route_b["attributes"]["jwt.credential.public.key"] == "__ROUTE_B_PUBLIC_KEY__"
assert route_b["attributes"]["token.endpoint.auth.signing.alg"] == "PS256"
assert route_b["attributes"]["token.endpoint.auth.signing.max.exp"] == "60"
assert introspection["clientAuthenticatorType"] == "client-x509"
assert introspection["attributes"]["x509.subjectdn"] == "CN=api-gateway-introspection"
assert introspection["attributes"]["tls.client.certificate.bound.access.tokens"] == "true"
assert introspection["attributes"]["allow.token.introspection.without.audience.check"] == "false"
assert introspection["attributes"]["x509.allow.regex.pattern.comparison"] == "false"
assert introspection["standardFlowEnabled"] is False
assert introspection["directAccessGrantsEnabled"] is False
assert introspection["serviceAccountsEnabled"] is False
assert introspection["redirectUris"] == []
for client in (route_a, route_b, introspection):
    assert client["consentRequired"] is True
    assert client["fullScopeAllowed"] is False
    assert client["webOrigins"] == []
for client in (route_a, route_b):
    attributes = client["attributes"]
    assert attributes["pkce.code.challenge.method"] == "S256"
    assert attributes["require.pushed.authorization.requests"] == "true"
    assert attributes["tls.client.certificate.bound.access.tokens"] == "true"
    if client is route_a:
        assert attributes["x509.allow.regex.pattern.comparison"] == "false"
    routing_mappers = {
        mapper["name"]: mapper for mapper in client["protocolMappers"]
    }
    assert routing_mappers["department"]["config"]["claim.name"] == (
        "https://fapi-demo\\.example\\.com/department"
    )
    assert routing_mappers["logical-route"]["config"]["claim.name"] == (
        "https://fapi-demo\\.example\\.com/route"
    )
    audience_mappers = {
        mapper["config"].get("included.custom.audience")
        for mapper in client["protocolMappers"]
        if mapper["protocolMapper"] == "oidc-audience-mapper"
    }
    assert audience_mappers == {"fapi-demo-api", "api-gateway-introspection"}
    assert all(
        mapper["config"].get("introspection.token.claim") == "true"
        for mapper in client["protocolMappers"]
    )
assert route_a["attributes"]["post.logout.redirect.uris"] == (
    "https://localhost:3443/?logout=route-a"
)
assert route_b["attributes"]["post.logout.redirect.uris"] == (
    "https://localhost:3443/?logout=route-b"
)
assert realm["accessCodeLifespan"] <= 60
assert realm["revokeRefreshToken"] is True
assert realm["refreshTokenMaxReuse"] == 0
assert realm["clientPolicies"]["policies"][0]["profiles"] == ["fapi-2-security-profile"]
identity_map = json.loads(
    (ROOT / "tests/fixtures/wp2-client-identity-map.json").read_text()
)
assert identity_map["third-party-fapi-mtls"]["certificate_subject"] == "CN=kong-fapi-mtls"

import yaml

def parse_deck_yaml(path):
    source = path.read_text()
    rendered = re.sub(
        r'\$\{\{\s*env\s+"([A-Z0-9_]+)"\s*\}\}',
        lambda match: f"deck-template:{match.group(1)}",
        source,
    )
    assert "${{" not in rendered
    return yaml.safe_load(rendered)


api_state = parse_deck_yaml(ROOT / "kong/api-gateway.yaml")
api_foundation = parse_deck_yaml(ROOT / "kong/foundation/api.yaml")
assert api_state["_format_version"] == "3.0"
assert api_state["_info"]["select_tags"] == ["fapi2-demo"]
foundation_certificates = {
    entity["id"]: entity for entity in api_foundation["certificates"]
}
runtime_certificates = {entity["id"]: entity for entity in api_state["certificates"]}
assert set(runtime_certificates) == set(foundation_certificates)
for certificate_id, foundation_certificate in foundation_certificates.items():
    assert runtime_certificates[certificate_id]["tags"] == foundation_certificate["tags"]
    assert runtime_certificates[certificate_id]["cert"] == foundation_certificate["cert"]
    assert runtime_certificates[certificate_id]["key"] == foundation_certificate["key"]
api_ca = api_state["ca_certificates"]
assert len(api_ca) == 1
assert api_ca[0]["id"] == "33333333-3333-4333-8333-333333333333"
assert api_ca[0]["tags"] == ["fapi2-demo"]
assert len(api_state["services"]) == 1
api_service = api_state["services"][0]
assert api_service["id"] == "a5fe77b4-93fd-4f84-bb31-71c245dedd09"
assert api_service["protocol"] == "https"
assert api_service["tls_verify"] is True
assert api_service["ca_certificates"] == [api_ca[0]["id"]]
assert api_service["client_certificate"] == "55555555-5555-4555-8555-555555555555"
assert len(api_service["routes"]) == 1
api_route = api_service["routes"][0]
assert api_route["id"] == "14d51ff4-613c-4769-96ce-330cd8075855"
assert api_route["paths"] == ["/fapi-api/evidence"]
assert api_route["protocols"] == ["https"]

api_plugins = {plugin["name"]: plugin for plugin in api_state["plugins"]}
assert set(api_plugins) == {
    "pre-function",
    "openid-connect",
    "tls-handshake-modifier",
    "tls-metadata-headers",
}
assert all(plugin.get("route") == api_route["name"] for plugin in api_plugins.values())
assert {name: plugin["id"] for name, plugin in api_plugins.items()} == {
    "pre-function": "4374b81d-77c4-4da1-9dfe-fbb0949a13ba",
    "openid-connect": "ed488e53-d29d-4db7-ba89-78b3bbf35df3",
    "tls-handshake-modifier": "6c3a195b-2fa7-4ed8-8ae4-72db3d2c537c",
    "tls-metadata-headers": "a6b8e2df-3612-47db-b863-b6dee55f2dc4",
}
assert api_plugins["pre-function"]["tags"] == ["fapi2-demo", "api"]
sanitizer = "\n".join(api_plugins["pre-function"]["config"]["access"])
assert "kong.request.get_headers(1000)" in sanitizer
assert 'if not headers or err then' in sanitizer
assert "count >= 1000" in sanitizer
assert "kong.response.exit(431" in sanitizer
assert 'string.lower(name):gsub("_", "-")' in sanitizer
assert 'normalized == "cookie"' in sanitizer
assert 'normalized:sub(1, 7) == "x-fapi-"' in sanitizer
assert 'normalized:sub(1, 13) == "x-client-cert"' in sanitizer
assert 'normalized:sub(1, 16) == "client-assertion"' in sanitizer
assert 'normalized:sub(1, 7) == "x-demo-"' in sanitizer
assert "kong.service.request.clear_header(name)" in sanitizer
assert "pcall(kong.request.get_query, 1000)" in sanitizer
assert 'normalized == "access-token"' in sanitizer
assert "query_error ~= nil" in sanitizer
assert "argument_count >= 1000" in sanitizer
assert "kong.response.exit(401" in sanitizer
assert 'Bearer error="invalid_token"' in sanitizer
assert "get_raw_query" not in sanitizer
assert "request.set_path" not in sanitizer
assert "kong.log" not in sanitizer
oidc = api_plugins["openid-connect"]["config"]
assert oidc["auth_methods"] == ["introspection"]
assert oidc["bearer_token_param_type"] == ["header"]
assert oidc["upstream_access_token_header"] == "authorization:bearer"
assert oidc["introspection_check_active"] is True
assert oidc["cache_introspection"] is False
assert oidc["cache_tokens"] is False
assert oidc["proof_of_possession_mtls"] == "strict"
assert oidc["proof_of_possession_auth_methods_validation"] is True
assert oidc["audience_required"] == ["fapi-demo-api"]
assert oidc["scopes_required"] == ["openid"]
assert oidc["issuer"] == "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration"
assert oidc["issuers_allowed"] == ["https://localhost:8444/realms/fapi-demo"]
assert oidc["upstream_headers"] == [
    {
        "header": "X-Demo-Department",
        "path": ["https://fapi-demo.example.com/department"],
    },
    {
        "header": "X-Demo-Route",
        "path": ["https://fapi-demo.example.com/route"],
    },
]
assert api_plugins["tls-handshake-modifier"]["config"]["tls_client_certificate"] == "REQUEST"
assert api_plugins["tls-metadata-headers"]["config"]["inject_client_cert_details"] is True
assert api_plugins["tls-metadata-headers"]["config"]["client_cert_header_name"] == "X-Client-Cert"
assert all(
    "fapi-as-mtls-transport" not in plugin["name"]
    and "fapi-client-auth-bridge" not in plugin["name"]
    for plugin in api_state["plugins"]
)

compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
api_compose = compose["services"]["kong-api"]
api_env = api_compose["environment"]
assert api_env["KONG_PROXY_LISTEN"] == "0.0.0.0:8443 ssl"
assert api_env["KONG_PROXY_ACCESS_LOG"] == "off"
assert api_env["KONG_SSL_PROTOCOLS"] == "TLSv1.2 TLSv1.3"
assert "KONG_NGINX_HTTP_UNDERSCORES_IN_HEADERS" not in api_env
wp3_compose = yaml.safe_load((ROOT / "tests/harness/docker-compose.wp3.yml").read_text())
assert "KONG_NGINX_HTTP_UNDERSCORES_IN_HEADERS" not in wp3_compose["services"]["kong-api"]["environment"]
assert api_env["KONG_SSL_CIPHER_SUITE"] == "modern"
assert api_env["KONG_LUA_SSL_PROTOCOLS"] == "TLSv1.2 TLSv1.3"
assert api_env["KONG_LUA_MAX_REQ_HEADERS"] == "1000"
assert api_env["KONG_NGINX_PROXY_PROXY_SSL_PROTOCOLS"] == "TLSv1.2 TLSv1.3"
assert api_env["KONG_NGINX_PROXY_PROXY_SSL_CIPHERS"] == "ECDHE+AESGCM:ECDHE+CHACHA20"
assert "ports" not in api_compose
assert api_env["KONG_PLUGINS"] == "bundled"
third_party_compose = compose["services"]["kong-third-party"]
assert third_party_compose["environment"]["KONG_PROXY_LISTEN"] == "${FAPI_DEMO_PROXY_LISTEN:-off}"
assert 'test "$$KONG_PLUGINS"' in third_party_compose["command"][0]
assert "exec /entrypoint.sh kong docker-start" in third_party_compose["command"][0]
assert "127.0.0.1:18443:8443" in third_party_compose["ports"]
assert "127.0.0.1:8443:8443" not in third_party_compose["ports"]
assert any("kong-proxy.crt:/etc/kong/fapi/kong-proxy.crt:ro" in volume for volume in third_party_compose["volumes"])
assert any("kong-proxy.key:/etc/kong/fapi/kong-proxy.key:ro" in volume for volume in third_party_compose["volumes"])
assert identity_map["third-party-fapi-pkj-mtls"]["certificate_subject"] == "CN=kong-fapi-pkj-mtls"
assert identity_map["api-gateway-introspection"]["certificate_subject"] == "CN=api-gateway-introspection"
pkigen = (ROOT / "scripts/generate-pki.py").read_text()
assert '("route-a", "kong-fapi-mtls", "clientAuth", "")' in pkigen
assert '("route-b", "kong-fapi-pkj-mtls", "clientAuth", "")' in pkigen
assert clients["third-party-fapi-mtls"]["attributes"]["x509.subjectdn"] == (
    identity_map["third-party-fapi-mtls"]["certificate_subject"]
)
assert {user["attributes"]["department"][0] for user in realm["users"]} == {
    "sales",
    "engineering",
}
assert all(user.get("firstName") and user.get("lastName") for user in realm["users"])
assert all(user.get("email") == user["username"] for user in realm["users"])

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
assert api_foundation.count("fapi2-foundation") == 3
assert "ca_certificates:" not in api_foundation
assert "DECK_API_INTROSPECTION_KEY_YAML" not in api_foundation
assert "{vault://env/API_INTROSPECTION_KEY}" in api_foundation
assert "{vault://env/API_UPSTREAM_KEY}" in api_foundation
assert not re.search(r"^(?:services|routes):\s*$", api_foundation, re.MULTILINE)
assert "fapi-as-mtls-transport" not in api_foundation
assert "fapi-client-auth-bridge" not in api_foundation
for entity_id in (
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
):
    assert entity_id in api_foundation
assert "77777777-7777-4777-8777-777777777777" not in api_foundation
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
assert '"require": ["exp", "iat", "iss", "aud", "cnf", "scope", "azp"]' in verifier
assert "hmac.compare_digest" in verifier
assert 'os.environ.get("OIDC_AUDIENCE", "fapi-demo-api")' in verifier
assert 'if AUDIENCE != "fapi-demo-api":' in verifier
assert 'if ALLOWED_ALGORITHMS != ("PS256",):' in verifier
assert 'API_UPSTREAM_COMMON_NAME = "api-gateway-upstream"' in verifier
assert '"third-party-fapi-mtls": ("route-a", "tls_client_auth")' in verifier
assert '"third-party-fapi-pkj-mtls": ("route-b", "private_key_jwt")' in verifier
assert "load_pinned_gateway_certificate" in verifier
assert "verify_api_gateway_peer" in verifier
assert 'headers.get_all("X-Client-Cert")' in verifier
assert "unquote_to_bytes(encoded)" in verifier
assert "constant_time_text_equal(token_thumbprint, forwarded_thumbprint)" in verifier
assert '"forwarded_client_certificate_thumbprint": forwarded_thumbprint' in verifier
assert '"api_gateway_tls_peer_certificate_thumbprint": tls_peer_thumbprint' in verifier
assert "algorithms=list(ALLOWED_ALGORITHMS)" in verifier
assert "context.verify_mode = ssl.CERT_REQUIRED" in verifier
assert "context.verify_flags &= ~ssl.VERIFY_X509_STRICT" in verifier
assert "ssl_context=verified_ssl_context()" in verifier
assert 'return\n\n\ndef create_server_context' in verifier
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
assert '"127.0.0.1:3000:80"' in compose
assert '"127.0.0.1:3443:443"' in compose
assert "profiles: [demo]" in compose
wp2_compose = (ROOT / "tests/harness/docker-compose.wp2.yml").read_text()
assert "quay.io/keycloak/keycloak:26.7.4@sha256:" in wp2_compose
assert '"127.0.0.1:18444:8443"' in wp2_compose
assert "wp2-isolated-keycloak-data" in wp2_compose
assert '    user: "0:0"' in wp2_compose
assert 'KC_SPI_LOGIN_PROTOCOL__OPENID_CONNECT__ALLOW_TOKEN_INTROSPECTION_WITHOUT_AUDIENCE_CHECK: "false"' in wp2_compose
service_matches = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\s*$", compose, re.MULTILINE))
service_blocks = {
    match.group(1): compose[match.start() : (service_matches[index + 1].start() if index + 1 < len(service_matches) else len(compose))]
    for index, match in enumerate(service_matches)
}
for gateway_name in ("kong-api", "kong-third-party"):
    block = service_blocks[gateway_name]
    if gateway_name == "kong-api":
        assert "ports:" not in block
    else:
        assert '      - "127.0.0.1:18443:8443"' in block
        assert '      - "127.0.0.1:8443:8443"' not in block
pop_verifier_block = service_blocks["pop-verifier"]
pop_verifier_mounts = pop_verifier_block.split("volumes:", 1)[1]
assert ".generated/pki/api-upstream.crt:/etc/fapi/api-upstream.crt:ro" in pop_verifier_mounts
assert ".generated/pki/api-upstream.key:" not in pop_verifier_mounts
assert "OIDC_AUDIENCE: fapi-demo-api" in pop_verifier_block
assert "OIDC_AUDIENCE: pop-verifier" not in pop_verifier_block
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
assert "python3 tests/test_pop_verifier.py" in makefile
assert "WP4_UPSTREAM01_RECEIPT ?= .generated/evidence/wp4-upstream01.json" in makefile
assert 'test-upstream01:\n\tpython3 tests/harness/upstream01.py --receipt "$(WP4_UPSTREAM01_RECEIPT)"' in makefile
assert "up:\n\t./scripts/require-wp5-readiness.sh" in makefile

upstream01 = (ROOT / "tests" / "harness" / "upstream01.py").read_text()
assert 'PORT = 19443' in upstream01
assert 'os.O_CREAT | os.O_EXCL | os.O_WRONLY' in upstream01
assert 'mode=0o600' in upstream01
assert 'os.chmod(fixture_dir, 0o700)' in upstream01
assert '"scenario": "UPSTREAM-01"' in upstream01
assert 'shutil.rmtree(fixture_dir)' in upstream01
assert '"protected_evidence_status": status' in upstream01
assert '"jwt_signature_verification_method": "actual PyJWT PS256 verification"' in upstream01
assert '"protected_evidence_validation": "not_run"' in upstream01
assert '"authorization_server_issued_token": False' in upstream01
assert '"keycloak_or_gateway_integration": "not exercised"' in upstream01
assert "x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier" in upstream01
assert '"same_cn_different_key_peer_status": same_cn_different_key_status' in upstream01
assert '"CERTIFICATE_REQUIRED" in reason or "HANDSHAKE_FAILURE" in reason' in upstream01
assert 'os.path.lexists(receipt_path)' in upstream01
assert 'os.fchmod(descriptor, 0o600)' in upstream01
assert 'thread.is_alive()' in upstream01
assert 'check_port_released()' in upstream01

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
assert '("route-a", "kong-fapi-mtls", "clientAuth", "")' in generator
assert '("route-b", "kong-fapi-pkj-mtls", "clientAuth", "")' in generator
assert "KC_SPI_LOGIN_PROTOCOL__OPENID_CONNECT__ALLOW_TOKEN_INTROSPECTION_WITHOUT_AUDIENCE_CHECK: \"false\"" in compose
assert "KEYCLOAK_REFRESH_TOKEN_ROTATION=true" in (ROOT / ".env.example").read_text()

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
assert "PyJWT[crypto]==2.14.0" in (ROOT / "requirements-dev.txt").read_text()

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
    if not path.is_file() or any(part in {".git", ".generated", ".terraform", "__pycache__"} for part in path.parts):
        continue
    if ".tfstate" in path.name:
        continue
    if path.suffix in {".html", ".png", ".jpg", ".woff", ".woff2"}:
        continue
    text = path.read_text(errors="ignore")
    for marker in private_key_markers:
        assert marker not in text, path

print("static checks: PASS")
