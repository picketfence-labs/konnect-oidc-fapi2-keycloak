local cjson = require "cjson.safe"
local resty_http = require "resty.http"

local TOKEN_URL = "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token"
local MARKER = "WP5_STOCK_TOKEN_DIAG="
local MAX_OAUTH_ERRORS = {
  invalid_client = true,
  invalid_grant = true,
  invalid_request = true,
  invalid_scope = true,
  invalid_token = true,
  unauthorized_client = true,
  unsupported_grant_type = true,
  unsupported_response_type = true,
  access_denied = true,
  server_error = true,
  temporarily_unavailable = true,
}
local KEYWORDS = {
  "nonce", "state", "signature", "issuer", "audience", "algorithm", "jwt", "assertion",
  "credentials", "certificate", "key", "kid", "pkce", "verifier", "code", "token",
  "expired", "missing", "invalid", "unsupported", "authentication", "client", "session",
  "request", "discovery", "user", "mtls", "claim", "claims",
}
local wrapped = false

local function pack(...)
  return { n = select("#", ...), ... }
end

local function option_present(value)
  if value == nil then
    return false
  end
  local value_type = type(value)
  return value_type == "cdata" or (value_type == "string" and #value > 0)
end

local function has_form_field(body, name)
  if type(body) == "table" then
    return body[name] ~= nil
  end
  if type(body) ~= "string" then
    return false
  end
  local ok, fields = pcall(ngx.decode_args, body)
  return ok and type(fields) == "table" and fields[name] ~= nil or false
end

local function keyword_presence(description)
  local found = {}
  for _, word in ipairs(KEYWORDS) do
    found[word] = false
  end
  if type(description) ~= "string" then
    return found
  end
  local tokens = {}
  for word in description:lower():gsub("[^a-z0-9]+", " "):gmatch("[a-z0-9]+") do
    tokens[word] = true
  end
  for _, word in ipairs(KEYWORDS) do
    found[word] = tokens[word] == true
  end
  return found
end

local function safe_diagnostic(options, response)
  local status = 0
  local oauth_error = "unknown"
  local description
  if type(response) == "table" then
    local candidate = response.status
    if type(candidate) == "number" and candidate == math.floor(candidate)
        and candidate >= 100 and candidate <= 599 then
      status = candidate
    end
    if type(response.body) == "string" then
      local body = cjson.decode(response.body)
      if type(body) == "table" then
        description = body.error_description
        if type(body.error) == "string" and MAX_OAUTH_ERRORS[body.error] then
          oauth_error = body.error
        elseif status == 200 and body.error == nil then
          oauth_error = "none"
        end
      end
    end
  end
  return {
    v = 1,
    ssl_client_cert_present = option_present(options.ssl_client_cert),
    ssl_client_priv_key_present = option_present(options.ssl_client_priv_key),
    client_assertion_present = has_form_field(options.body, "client_assertion"),
    client_assertion_type_present = has_form_field(options.body, "client_assertion_type"),
    response_status = status,
    oauth_error_enum = oauth_error,
    error_description_keyword_presence = keyword_presence(description),
  }
end

local function emit_safe_diagnostic(options, response)
  local encoded = cjson.encode(safe_diagnostic(options, response))
  if type(encoded) ~= "string" then
    return
  end
  -- Timer context avoids attaching request-local URI/query details to the NGINX log line.
  ngx.timer.at(0, function(premature, safe_json)
    if premature then
      return
    end
    ngx.log(ngx.ERR, MARKER, safe_json)
  end, encoded)
end

local StockTokenDiagnostic = {
  PRIORITY = 1,
  VERSION = "0.1.0",
}

function StockTokenDiagnostic:init_worker()
  if wrapped then
    return
  end
  local original = resty_http.request_uri
  if type(original) ~= "function" then
    error("WP5 stock token diagnostic cannot wrap resty.http.request_uri")
  end
  resty_http.request_uri = function(...)
    local args = pack(...)
    local results = pack(original(unpack(args, 1, args.n)))
    if args[2] == TOKEN_URL and type(args[3]) == "table" and args[3].method == "POST" then
      pcall(emit_safe_diagnostic, args[3], results[1])
    end
    return unpack(results, 1, results.n)
  end
  wrapped = true
end

function StockTokenDiagnostic:access(_conf)
  return
end

return StockTokenDiagnostic
