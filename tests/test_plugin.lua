local discovery_issuer = "https://issuer.example/realms/fapi-demo"
local encoded_values = {}
local http_calls = {}
local request_headers = {}
local request_query = {}
local request_body = nil
local response_exit = nil
local set_headers = {}
local signing_call = nil

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

os.remove(private_key)
os.remove(tls_certificate)
print("plugin unit checks: PASS")
