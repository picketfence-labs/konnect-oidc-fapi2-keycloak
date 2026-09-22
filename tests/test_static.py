#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for name in ("kong.yaml", "kong-par.yaml"):
    text = (ROOT / "kong" / name).read_text()
    assert "kong/kong-gateway:3.16" not in text  # image belongs only in Compose
    assert text.count("name: oidc-httpbin-service") == 1
    assert text.count("name: oidc-routing-demo-route") == 1
    assert "header: X-Demo-Department" in text
    assert "header: X-Demo-Route" in text
    assert "name: route-by-header" in text
    assert "X-Demo-Route: sales-route" in text
    assert "X-Demo-Route: engineering-route" in text
    assert "require_proof_key_for_code_exchange: true" in text
    assert "ssl_verify: true" in text
    assert 'cache_tokens_salt: ${{ env "DECK_CACHE_TOKENS_SALT" }}' in text
    assert 'redirect_uri: ["http://localhost:8000/api/demo"]' in text
    assert 'login_redirect_uri: ["http://localhost:3000/?authenticated=1"]' in text

base = (ROOT / "kong" / "kong.yaml").read_text()
par = (ROOT / "kong" / "kong-par.yaml").read_text()
assert "require_pushed_authorization_requests" not in base
assert "require_pushed_authorization_requests: true" in par
assert "pushed_authorization_request_endpoint" in par

compose = (ROOT / "docker-compose.yml").read_text()
assert "kong/kong-gateway:3.16.0.0" in compose
assert "KONG_ROLE: data_plane" in compose
assert "KONG_KONNECT_MODE" in compose
assert "KONG_LICENSE_DATA" not in compose

env_example = (ROOT / ".env.example").read_text()
assert "KONG_LICENSE_DATA" not in env_example

auth0 = (ROOT / "infra" / "auth0.tf").read_text()
assert "app.department || app.departement" in auth0
assert 'engineering: "engineering-route"' in auth0
assert 'grant_types                           = ["authorization_code", "refresh_token"]' in auth0
assert auth0.count("depends_on = [auth0_connection_clients.demo]") == 2
assert "enabled_clients = [auth0_client.gateway.id, var.auth0_management_client_id]" in auth0

with_env = (ROOT / "scripts" / "with-env.sh").read_text()
assert 'export TF_VAR_auth0_management_client_id="$AUTH0_CLIENT_ID"' in with_env

render = (ROOT / "scripts" / "render-runtime-env.sh").read_text()
assert "openssl dgst -sha256" in render
assert "DECK_CACHE_TOKENS_SALT=$cache_tokens_salt" in render

print("static checks: PASS")
