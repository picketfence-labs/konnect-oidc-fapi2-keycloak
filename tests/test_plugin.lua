local discovery_issuer = "https://issuer.example/realms/fapi-demo"
local encoded_values = {}
local http_calls = {}
local request_headers = {}
local request_query = {}
local request_body = nil
local response_exit = nil
local set_headers = {}
local signing_call = nil
local delegate_context = nil
local transport_epoch = "transport-epoch-1"
local bridge_status = { loaded = false, ready = false }

package.preload["cjson.safe"] = function()
  return {
    encode = function(value)
      table.insert(encoded_values, value)
      return "{}"
    end,
    decode = function(_)
      return { issuer = discovery_issuer }
    end,
  }
end

package.preload["resty.http"] = function()
  return {
    new = function()
      local client = {}
      function client:set_timeout(timeout)
        self.timeout = timeout
      end
      function client:request_uri(uri, options)
        table.insert(http_calls, { uri = uri, options = options, timeout = self.timeout })
        return { status = 200, body = "{}" }
      end
      return client
    end,
  }
end

package.preload["resty.openssl.pkey"] = function()
  local module = {
    PADDINGS = { RSA_PKCS1_PSS_PADDING = 6 },
  }
  function module.new(_)
    return {
      sign = function(_, input, digest, padding, options)
        signing_call = {
          input = input,
          digest = digest,
          padding = padding,
          options = options,
        }
        return "signature"
      end,
    }
  end
  return module
end

package.preload["resty.random"] = function()
  return { bytes = function(length, strong) assert(length == 32 and strong); return string.rep("x", length) end }
end

package.preload["kong.plugins.fapi-as-mtls-transport.handler"] = function()
  return {
    mark_bridge_loaded = function() bridge_status.loaded = true end,
    mark_bridge_status = function(ready, epoch)
      bridge_status.ready = ready == true and epoch == transport_epoch
    end,
    current_registry_epoch = function() return transport_epoch end,
    route_manifest_matches = function(route_id, client_id, logical_route, epoch)
      return route_id == "0f45debe-a3a6-5207-aea3-637227fb96f2"
        and client_id == "third-party-fapi-pkj-mtls"
        and logical_route == "B" and epoch == transport_epoch
    end,
    route_certificate_matches = function(route_id, path)
      return route_id == "0f45debe-a3a6-5207-aea3-637227fb96f2"
        and path == "/etc/kong/fapi/route-b.crt"
    end,
    context_for_bridge = function() return delegate_context end,
    route_identity_matches = function(context, client_id, logical_route)
      return context == delegate_context and context.ready == true
        and context.client_id == client_id and context.logical_route == logical_route
        and context.registry_epoch == transport_epoch
    end,
  }
end

ngx = {
  encode_base64 = function(value, _) return "b64" .. tostring(#value) end,
  now = function() return 1000 end,
  time = function() return 1000 end,
  req = {
    set_header = function(name, value) set_headers[name] = value end,
  },
}

kong = {
  request = {
    get_header = function(name) return request_headers[name] end,
    get_query = function() return request_query end,
    get_body = function() return request_body end,
  },
  response = {
    exit = function(status, body)
      response_exit = { status = status, body = body }
      return response_exit
    end,
  },
  log = { err = function(...) end },
}

local function write_temporary(value)
  local path = os.tmpname()
  local file = assert(io.open(path, "wb"))
  assert(file:write(value))
  assert(file:close())
  return path
end

local private_key = write_temporary("test private key")
local tls_certificate = write_temporary("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
local bridge = dofile("kong/plugins/fapi-client-auth-bridge/handler.lua")
bridge:configure(nil)
assert(not bridge.status_snapshot().delegate_ready,
  "an initial nil configure waits for hybrid CP state without selecting header mode")
bridge:configure({})
assert(not bridge.status_snapshot().delegate_ready,
  "an initial empty configure also waits for hybrid CP state")
local conf = {
  issuer = discovery_issuer,
  discovery_endpoint = "https://keycloak.test/.well-known/openid-configuration",
  discovery_timeout = 3000,
  discovery_cache_ttl = 300,
  client_id = "kong-fapi-pkj-mtls",
  private_key_file = private_key,
  tls_certificate_file = tls_certificate,
  key_id = "route-b-pkj",
  assertion_ttl = 60,
}

local function reset_request()
  request_headers = {}
  request_query = {}
  request_body = nil
  response_exit = nil
  set_headers = {}
end

for _, supplied in ipairs({ "header", "query", "body" }) do
  reset_request()
  if supplied == "header" then request_headers.client_assertion = "external" end
  if supplied == "query" then request_query.client_assertion_type = "external" end
  if supplied == "body" then request_body = { client_assertion = "external" } end
  bridge:access(conf)
  assert(response_exit.status == 400)
end
assert(#http_calls == 0)

reset_request()
bridge:access(conf)
assert(response_exit == nil)
assert(#http_calls == 1)
assert(http_calls[1].uri == conf.discovery_endpoint)
assert(http_calls[1].timeout == conf.discovery_timeout)
assert(http_calls[1].options.ssl_verify == true)
assert(set_headers.client_assertion)
assert(set_headers.client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
assert(signing_call.digest == "sha256")
assert(signing_call.padding == 6)
assert(signing_call.options[1] == "rsa_pss_saltlen:digest")
assert(signing_call.options[2] == "rsa_mgf1_md:sha256")

local payload = encoded_values[#encoded_values]
assert(payload.iss == conf.client_id)
assert(payload.sub == conf.client_id)
assert(payload.aud == conf.issuer)
assert(payload.iat == 1000 and payload.exp == 1060)
assert(payload.jti)

reset_request()
bridge:access(conf)
assert(response_exit == nil)
assert(#http_calls == 1, "successful discovery should be cached")

reset_request()
local mismatched = {}
for key, value in pairs(conf) do mismatched[key] = value end
mismatched.issuer = "https://wrong.example/realms/fapi-demo"
bridge:access(mismatched)
assert(response_exit.status == 500)
assert(next(set_headers) == nil)

reset_request()
local missing_certificate = {}
for key, value in pairs(conf) do missing_certificate[key] = value end
missing_certificate.discovery_endpoint = "https://keycloak.test/other-discovery"
missing_certificate.tls_certificate_file = "/does/not/exist"
bridge:access(missing_certificate)
assert(response_exit.status == 500)
assert(next(set_headers) == nil)

-- Delegate mode validates fixed Route B config, binds the callback to the current
-- transport epoch, and generates no header assertion at access time.
local real_io_open = io.open
io.open = function(path, mode)
  if path == "/etc/kong/fapi/route-b-pkj.key" then
    return real_io_open(private_key, mode)
  end
  return real_io_open(path, mode)
end
local delegate_issuer = "https://localhost:8444/realms/fapi-demo"
discovery_issuer = delegate_issuer
delegate_context = {
  ready = true,
  registry_epoch = transport_epoch,
  signer_epoch = transport_epoch,
  logical_route = "B",
  client_id = "third-party-fapi-pkj-mtls",
}
local delegate_conf = {
  assertion_delivery = "transport_delegate",
  issuer = delegate_issuer,
  discovery_endpoint = "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration",
  client_id = "third-party-fapi-pkj-mtls",
  private_key_file = "/etc/kong/fapi/route-b-pkj.key",
  tls_certificate_file = "/etc/kong/fapi/route-b.crt",
  key_id = "fixture-route-b-kid",
  assertion_ttl = 60,
  discovery_timeout = 3000,
  discovery_cache_ttl = 300,
}
bridge:configure({ { config = delegate_conf } })
assert(bridge_status.loaded and bridge_status.ready)
reset_request()
signing_call = nil
bridge:access(delegate_conf)
assert(response_exit == nil and next(set_headers) == nil)
assert(signing_call == nil, "delegate mode must defer signing until transport send")
assert(type(delegate_context.sign_assertion) == "function")
local delegated_assertion, delegated_type = delegate_context.sign_assertion()
assert(delegated_assertion and delegated_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
assert(signing_call.digest == "sha256")
local delegated_payload = encoded_values[#encoded_values]
assert(delegated_payload.iss == delegate_conf.client_id)
assert(delegated_payload.sub == delegate_conf.client_id)
assert(delegated_payload.aud == delegate_issuer)
assert(delegated_payload.iat == 1000 and delegated_payload.exp == 1060)

transport_epoch = "transport-epoch-2"
assert(delegate_context.sign_assertion() == nil, "stale signer epoch must fail closed")
local changed_delegate_conf = {}
for key, value in pairs(delegate_conf) do changed_delegate_conf[key] = value end
changed_delegate_conf.key_id = "changed-kid"
bridge:configure({ { config = changed_delegate_conf } })
assert(not bridge_status.ready and not bridge.status_snapshot().delegate_ready)
reset_request()
bridge:access(changed_delegate_conf)
assert(response_exit.status == 500)
io.open = real_io_open
os.remove(private_key)
os.remove(tls_certificate)

print("plugin unit checks: PASS")
