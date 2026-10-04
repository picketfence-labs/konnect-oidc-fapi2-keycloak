local cjson_values = {}
local encoded_values = {}
local network_calls = {}
local request_id = 0
local json_id = 0
local b64_id = 0
local next_http_status = 200
local active_route = nil
local exited = nil

local function fake_digest(value)
  local hash = 0
  for index = 1, #value do
    hash = (hash * 33 + value:byte(index)) % 251
  end
  local bytes = {}
  for index = 1, 32 do
    bytes[index] = string.char((hash + index * 7) % 256)
  end
  return table.concat(bytes)
end

package.preload["cjson.safe"] = function()
  local module = {}
  function module.encode(value)
    json_id = json_id + 1
    local key = "json_" .. tostring(json_id)
    cjson_values[key] = value
    return key
  end
  function module.decode(value)
    if value == "discovery" then
      return { issuer = "https://localhost:8444/realms/fapi-demo" }
    end
    return cjson_values[value]
  end
  return module
end

package.preload["resty.openssl.digest"] = function()
  return {
    new = function(name)
      assert(name == "sha256")
      return { final = function(_, value) return fake_digest(value) end }
    end,
  }
end

package.preload["resty.openssl.x509"] = function()
  local module = {}
  function module.new(pem)
    return {
      check_private_key = function() return true end,
      get_lifetime = function() return 900, 2000 end,
      get_extension = function(_, name)
        assert(name == "extendedKeyUsage")
        return { text = function() return "TLS Web Client Authentication" end }
      end,
      digest = function() return fake_digest(pem) end,
    }
  end
  function module.dup()
    return { digest = function() return fake_digest("stock") end }
  end
  return module
end

package.preload["resty.openssl.pkey"] = function()
  return { new = function() return { sign = function() return "signature" end } end }
end

package.preload["resty.openssl.x509.chain"] = function()
  return { dup = function() return { [1] = { ctx = {} }, __len = function() return 1 end } end }
end

package.preload["resty.random"] = function()
  return {
    bytes = function(length, strong)
      assert(strong == true)
      request_id = request_id + 1
      return string.rep(string.char(request_id % 250 + 1), length)
    end,
  }
end

package.preload["ngx.ssl"] = function()
  return {
    parse_pem_cert = function(pem) return { pem = pem } end,
    parse_pem_priv_key = function(pem) return { pem = pem } end,
  }
end

local fake_http
fake_http = {
  new = function()
    local client = {}
    function client:set_timeout(timeout) self.timeout = timeout end
    function client:request_uri(uri, options)
      return fake_http.request_uri(self, uri, options)
    end
    return client
  end,
  request_uri = function(self, uri, options)
    table.insert(network_calls, { self = self, uri = uri, options = options })
    return { status = next_http_status, body = "discovery" }
  end,
}
package.preload["resty.http"] = function() return fake_http end

ngx = {
  time = function() return 1000 end,
  now = function() return 1000 end,
  worker = { id = function() return 3 end, pid = function() return 44321 end },
  encode_base64 = function(value)
    b64_id = b64_id + 1
    local key = "b64" .. tostring(b64_id)
    encoded_values[key] = value
    return key
  end,
  decode_base64 = function(value) return encoded_values[value:gsub("=+$", "")] end,
  ctx = {},
}

kong = {
  ctx = { shared = {} },
  router = { get_route = function() return { id = active_route } end },
  response = {
    exit = function(status, body)
      exited = { status = status, body = body }
      return exited
    end,
  },
}

local ffi = require "ffi"
pcall(ffi.cdef, "int setenv(const char *name, const char *value, int overwrite);")
ffi.C.setenv("FAPI_AS_TRANSPORT_ISSUER", "https://localhost:8444/realms/fapi-demo", 1)
ffi.C.setenv("FAPI_AS_TRANSPORT_INTERNAL_ORIGIN", "https://keycloak:8443", 1)

local function temp_file(value)
  local path = os.tmpname()
  local file = assert(io.open(path, "wb"))
  assert(file:write(value))
  assert(file:close())
  return path
end

local metadata_cert = temp_file("metadata cert")
local metadata_key = temp_file("metadata key")
local route_a_cert = temp_file("route a cert")
local route_a_key = temp_file("route a key")
local route_b_cert = temp_file("route b cert")
local route_b_key = temp_file("route b key")
local real_io_open = io.open
local fixed_files = {
  ["/etc/kong/fapi/third-party-metadata.crt"] = metadata_cert,
  ["/etc/kong/fapi/third-party-metadata.key"] = metadata_key,
  ["/etc/kong/fapi/route-a.crt"] = route_a_cert,
  ["/etc/kong/fapi/route-a.key"] = route_a_key,
  ["/etc/kong/fapi/route-b.crt"] = route_b_cert,
  ["/etc/kong/fapi/route-b.key"] = route_b_key,
}
io.open = function(path, mode)
  return real_io_open(fixed_files[path] or path, mode)
end

local route_a_id = "754519ff-b0b9-5ed5-94c0-e453d260c6c4"
local route_b_id = "0f45debe-a3a6-5207-aea3-637227fb96f2"
local client_a = "third-party-fapi-mtls"
local client_b = "third-party-fapi-pkj-mtls"
local issuer = "https://localhost:8444/realms/fapi-demo"
local par = "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/ext/par/request"
local token = "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token"
local revoke = "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/revoke"
local assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

local config = {
  issuer = issuer,
  internal_origin = "https://keycloak:8443",
  discovery_url = "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration",
  jwks_url = "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/certs",
  par_url = par,
  token_url = token,
  revocation_url = revoke,
  metadata_certificate_file = "/etc/kong/fapi/third-party-metadata.crt",
  metadata_key_file = "/etc/kong/fapi/third-party-metadata.key",
  evidence_correlation_enabled = true,
  routes = {
    { route_id = route_a_id, logical_route = "A", client_id = client_a,
      certificate_file = "/etc/kong/fapi/route-a.crt", key_file = "/etc/kong/fapi/route-a.key" },
    { route_id = route_b_id, logical_route = "B", client_id = client_b,
      certificate_file = "/etc/kong/fapi/route-b.crt", key_file = "/etc/kong/fapi/route-b.key" },
  },
}

local transport = dofile("kong/plugins/fapi-as-mtls-transport/handler.lua")
transport:configure(nil)
assert(not transport.status_snapshot().registry_ready,
  "an initial nil configure waits for hybrid CP state without latching failure")
transport:configure({})
assert(not transport.status_snapshot().registry_ready,
  "an initial empty configure also waits for hybrid CP state")
transport:configure({ { config = config } })
local initial_snapshot = transport.status_snapshot()
local decorated_config = {}
for key, value in pairs(config) do decorated_config[key] = value end
decorated_config.ordering = 1100
decorated_config.route_id = route_a_id
decorated_config.service_id = "service-meta"
decorated_config.consumer_id = "consumer-meta"
decorated_config.consumer_group_id = "group-meta"
decorated_config.plugin_instance_name = "runtime-meta"
decorated_config.__plugin_id = "plugin-meta"
decorated_config.__ws_id = "workspace-meta"
decorated_config.__plugin_name = "fapi-as-mtls-transport"
decorated_config.__key__ = "entity-key-meta"
decorated_config.__seq__ = 1
decorated_config.__compiled_condition = {}
decorated_config.__compiled_expressions = {}
transport:configure({ decorated_config })
decorated_config.__seq__ = 2
transport:configure({ decorated_config })
local decorated_snapshot = transport.status_snapshot()
assert(decorated_snapshot.registry_ready)
assert(decorated_snapshot.config_hash == initial_snapshot.config_hash)
assert(decorated_snapshot.registry_epoch == initial_snapshot.registry_epoch,
  "Kong internal metadata and __seq__ must not alter the registry epoch")
transport:init_worker()
assert(transport.status_snapshot().wrapper_ready)
assert(transport.status_snapshot().registry_ready)
assert(transport.runtime_gate_ready(), "offline test mode should not require a runtime marker")

local function request(uri, method, body, headers)
  local client = fake_http.new()
  return client:request_uri(uri, { method = method, body = body, headers = headers or {} })
end

-- Context-free metadata is pinned to the internal locator and dedicated identity.
local response = request(issuer .. "/.well-known/openid-configuration", "GET")
assert(response.status == 200)
assert(network_calls[#network_calls].uri == config.discovery_url)
assert(network_calls[#network_calls].options.ssl_client_cert.pem == "metadata cert")
assert(network_calls[#network_calls].options.ssl_server_name == "keycloak")
assert(network_calls[#network_calls].options.ssl_verify == true)
assert(network_calls[#network_calls].options.follow_redirects == false)
assert(network_calls[#network_calls].options.keepalive == false)

-- A malformed context-free AS request must not bypass the bootstrap guard.
local before_invalid_method = #network_calls
assert(request(config.discovery_url, {}) == nil)
assert(#network_calls == before_invalid_method)

-- Non-AS traffic without a FAPI route context keeps the stock transport behavior.
local passthrough_before = #network_calls
request("https://example.test/health", "GET")
assert(#network_calls == passthrough_before + 1)
assert(network_calls[#network_calls].uri == "https://example.test/health")

-- A resolved Route A receives its own identity and can send one raw PAR only.
active_route = route_a_id
transport:access()
local a_context = kong.ctx.shared.fapi_as_transport
assert(a_context and a_context.client_id == client_a)
local original_body = "client_id=" .. client_a .. "&scope=openid"
local original_headers = {
  ["cOnTeNt-TyPe"] = "application/x-www-form-urlencoded",
  hOsT = "attacker.invalid",
  ["X-FAPI-DEMO-OBSERVATION-ID"] = "caller-value",
}
local before_par = #network_calls
response = request(par, "POST", original_body, original_headers)
assert(response.status == 200 and #network_calls == before_par + 1)
local par_call = network_calls[#network_calls]
assert(par_call.options.body == original_body, "stock PAR bytes must remain unchanged")
assert(par_call.options.ssl_client_cert.pem == "route a cert")
assert(par_call.options.ssl_client_priv_key.pem == "route a key")
assert(par_call.options.headers.Host == "keycloak:8443")
assert(par_call.options.headers.hOsT == nil)
assert(par_call.options.headers["X-Fapi-Demo-Observation-ID"] ~= "caller-value")
assert(par_call.options.pool:find("A", 1, true))
local par_observation = a_context.observations[#a_context.observations]
assert(par_observation.sent and not par_observation.not_sent)
assert(par_observation.endpoint_kind == "par" and par_observation.request_id)

local changed_par = original_body .. "&display=changed"
local after_first_par = #network_calls
local denied = request(par, "POST", changed_par, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(denied == nil and #network_calls == after_first_par,
  "form changes must not bypass one-PAR-per-context")

-- Assertions injected by a client are rejected for Route A.
transport:access()
local fresh_a = kong.ctx.shared.fapi_as_transport
local assertion_body = original_body .. "&client_assertion=external"
denied = request(par, "POST", assertion_body, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(denied == nil and #network_calls == after_first_par)

-- Route B code and refresh grants are single-send independently. Signing is
-- called only after the form passed guards and is marked before the network call.
active_route = route_b_id
transport:access()
local b_context = kong.ctx.shared.fapi_as_transport
local signer_calls = 0
local function make_assertion()
  local header = ngx.encode_base64(require("cjson.safe").encode({ alg = "PS256" }))
  local payload = ngx.encode_base64(require("cjson.safe").encode({
    aud = issuer, exp = 1060, iat = 1000, iss = client_b, sub = client_b, jti = "test-jti",
  }))
  return header .. "." .. payload .. "." .. ngx.encode_base64("signature")
end
b_context.signer_epoch = b_context.registry_epoch
b_context.sign_assertion = function()
  signer_calls = signer_calls + 1
  return make_assertion(), assertion_type
end

local before_b_token = #network_calls
denied = request(token, "POST", "client_id=wrong&grant_type=authorization_code", {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(denied == nil and signer_calls == 0 and #network_calls == before_b_token,
  "invalid client_id must fail before signer or network")

local code_form = "client_id=" .. client_b .. "&grant_type=authorization_code&code=code-1"
response = request(token, "POST", code_form, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(response.status == 200 and signer_calls == 1)
local code_call = network_calls[#network_calls]
assert(code_call.options.body:find("client_assertion=", 1, true))
assert(code_call.options.body ~= code_form)
assert(code_call.options.headers["Content-Length"] == tostring(#code_call.options.body))
local code_observation = b_context.observations[#b_context.observations]
assert(code_observation.sent and code_observation.claim_summary.alg == "PS256")
assert(code_observation.claim_summary.aud_is_issuer and code_observation.claim_summary.jti_present)
local code_digest
for key, digest in pairs(b_context.operation_digests) do
  if key:find("authorization_code", 1, true) then code_digest = digest end
end
assert(type(code_digest) == "string" and #code_digest == 64)
assert(not code_digest:find("code%-1"), "the operation ledger must not retain raw form data")

denied = request(token, "POST", code_form .. "&extra=1", {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(denied == nil and signer_calls == 1 and #network_calls == before_b_token + 1)

local refresh_form = "client_id=" .. client_b .. "&grant_type=refresh_token&refresh_token=refresh-1"
response = request(token, "POST", refresh_form, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(response.status == 200 and signer_calls == 2)

-- Route B PAR and revocation retain stock assertions and raw form bytes; missing
-- client_id is accepted only when iss/sub match the trusted Route B identity.
local function stock_assertion()
  local cjson = require "cjson.safe"
  local header = ngx.encode_base64(cjson.encode({ alg = "PS256" }))
  local payload = ngx.encode_base64(cjson.encode({
    aud = issuer, exp = 1060, iat = 1000, iss = client_b, sub = client_b, jti = "stock-jti",
  }))
  return header .. "." .. payload .. "." .. ngx.encode_base64("stock-signature")
end
local stock_jwt = stock_assertion()
local par_b_body = "scope=openid&client_assertion=" .. stock_jwt
  .. "&client_assertion_type=" .. assertion_type:gsub(":", "%%3A")
local before_b_par = #network_calls
response = request(par, "POST", par_b_body, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(response.status == 200 and #network_calls == before_b_par + 1)
assert(network_calls[#network_calls].options.body == par_b_body,
  "Route B stock PAR assertion and form must pass unchanged")

local revoke_body = "token=access-one&token_type_hint=access_token&client_assertion="
  .. stock_jwt .. "&client_assertion_type=" .. assertion_type:gsub(":", "%%3A")
response = request(revoke, "POST", revoke_body, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(response.status == 200 and network_calls[#network_calls].options.body == revoke_body)
local before_duplicate_revoke = #network_calls
denied = request(revoke, "POST", revoke_body:gsub("access_token", "refresh_token"), {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(denied == nil and #network_calls == before_duplicate_revoke,
  "changing revoke hint must not bypass per-token deduplication")
local distinct_revoke = revoke_body:gsub("access%-one", "refresh-one")
  :gsub("access_token", "refresh_token")
response = request(revoke, "POST", distinct_revoke, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(response.status == 200 and network_calls[#network_calls].options.body == distinct_revoke,
  "a distinct token may be revoked independently")

-- Unknown Keycloak endpoints and HTTP downgrade attempts are denied.
local before_unknown = #network_calls
denied = request("https://keycloak:8443/admin/", "GET")
assert(denied == nil and #network_calls == before_unknown)
denied = request("http://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token", "POST", code_form, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(denied == nil and #network_calls == before_unknown)

-- A 3xx is surfaced as a closed failure, not followed by resty-http.
next_http_status = 302
denied = request(config.discovery_url, "GET")
assert(denied == nil)
next_http_status = 200

-- Metadata identity drift must latch even when its configured paths are unchanged.
local metadata_replacement = assert(real_io_open(metadata_cert, "wb"))
assert(metadata_replacement:write("changed metadata cert"))
assert(metadata_replacement:close())
transport:configure({ { config = config } })
assert(not transport.status_snapshot().registry_ready,
  "metadata certificate replacement requires restart")

-- Nil configure is a restart-required latch and reserved routes fail before
-- stock OIDC can proceed with cached session metadata.
transport:configure(nil)
active_route = route_a_id
exited = nil
transport:access()
assert(exited and exited.status == 503)
local before_latched = #network_calls
denied = request(par, "POST", original_body, {
  ["Content-Type"] = "application/x-www-form-urlencoded",
})
assert(denied == nil and #network_calls == before_latched)

for _, path in ipairs({ metadata_cert, metadata_key, route_a_cert, route_a_key,
  route_b_cert, route_b_key }) do
  os.remove(path)
end
io.open = real_io_open
print("WP5 transport guard checks: PASS")
