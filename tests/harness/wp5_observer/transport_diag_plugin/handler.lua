local cjson = require "cjson.safe"
local resty_http = require "resty.http"
local digest_lib = require "resty.openssl.digest"

local ISSUER = "https://localhost:8444/realms/fapi-demo"
local ORIGIN = "https://keycloak:8443"
local CORRELATION = "X-Fapi-Demo-Observation-ID"
local WIRE_MARKER = "WP5_TRANSPORT_WIRE="
local CONTEXT_MARKER = "WP5_TRANSPORT_CONTEXT="
local MAX_FORM_BYTES = 65536
local MAX_CONTEXT_ROWS = 32
local MAX_JTIS = 128
local REFRESH_STATE_TTL = 120

local ENDPOINTS = {
  ["/realms/fapi-demo/.well-known/openid-configuration"] = { kind = "discovery", method = "GET" },
  ["/realms/fapi-demo/protocol/openid-connect/certs"] = { kind = "jwks", method = "GET" },
  ["/realms/fapi-demo/protocol/openid-connect/ext/par/request"] = { kind = "par", method = "POST" },
  ["/realms/fapi-demo/protocol/openid-connect/token"] = { kind = "token", method = "POST" },
  ["/realms/fapi-demo/protocol/openid-connect/revoke"] = { kind = "revocation", method = "POST" },
}
local OAUTH_ERRORS = {
  invalid_client = true, invalid_grant = true, invalid_request = true,
  invalid_scope = true, invalid_token = true, unauthorized_client = true,
  unsupported_grant_type = true, unsupported_response_type = true,
  access_denied = true, server_error = true, temporarily_unavailable = true,
}
local CONTEXT_ENDPOINTS = {
  discovery = true, jwks = true, par = true, token = true, revocation = true, unknown = true,
}
local CONTEXT_METHODS = { GET = true, POST = true }
local CONTEXT_IDENTITIES = { route_A = true, route_B = true, metadata = true }
local CONTEXT_AUTH = { tls_client_auth = true, private_key_jwt = true, none = true }
local CONTEXT_RESULTS = {
  not_sent = true, network_error = true, redirect_rejected = true, response_received = true,
}
local CONTEXT_REJECTIONS = { transport_guard = true, signer = true, network = true, transport_redirect = true }
local CONTEXT_REASONS = {
  invalid_method = true, context_external_url = true, unknown_as_endpoint = true,
  registry_not_ready = true, http_blocked = true, invalid_metadata_request = true,
  stale_context = true, missing_or_stale_route_context = true, transport_options_rejected = true,
  invalid_form_content_type = true, invalid_or_duplicate_post = true,
  signer_unavailable = true, observation_id_unavailable = true,
  bootstrap_marker_missing_or_stale = true,
}

local wrapped = false
local seen_jti = {}
local jti_count = 0

local function pack(...)
  return { n = select("#", ...), ... }
end

local function option_present(value)
  if value == nil then return false end
  local kind = type(value)
  return kind == "cdata" or (kind == "string" and #value > 0)
end

local function header_value(headers, wanted)
  if type(headers) ~= "table" then return nil end
  for name, value in pairs(headers) do
    if type(name) == "string" and name:lower() == wanted:lower()
      and type(value) == "string" then
      return value
    end
  end
end

local function parse_form(body)
  if type(body) ~= "string" or #body == 0 or #body > MAX_FORM_BYTES then return nil end
  local ok, fields = pcall(ngx.decode_args, body, 64)
  if not ok or type(fields) ~= "table" then return nil end
  return fields
end

local function one_field(fields, name)
  if type(fields) ~= "table" then return nil end
  local value = fields[name]
  if type(value) == "string" then return value end
  return nil
end

local function base64url_decode(value)
  if type(value) ~= "string" or #value > 32768
    or value:find("[^A-Za-z0-9_%-]", 1) then return nil end
  local encoded = value:gsub("-", "+"):gsub("_", "/")
  local remainder = #encoded % 4
  if remainder == 1 then return nil end
  if remainder > 0 then encoded = encoded .. string.rep("=", 4 - remainder) end
  local decoded = ngx.decode_base64(encoded)
  if type(decoded) ~= "string" then return nil end
  return decoded
end

local function hex(value)
  return (value:gsub(".", function(byte)
    return string.format("%02x", string.byte(byte))
  end))
end

local function safe_assertion(assertion, expected_client)
  local summary = {
    alg = "unknown", aud_is_issuer = false, iss_sub_match = false,
    ttl_seconds = 0, jti_present = false, jti_distinct = false,
  }
  if type(assertion) ~= "string" or #assertion > MAX_FORM_BYTES then return summary end
  local header_part, claims_part = assertion:match("^([^.]+)%.([^.]+)%.[^.]+$")
  if not header_part or not claims_part then return summary end
  local header_json = base64url_decode(header_part)
  local claims_json = base64url_decode(claims_part)
  if not header_json or not claims_json then return summary end
  local header = cjson.decode(header_json)
  local claims = cjson.decode(claims_json)
  if type(header) ~= "table" or type(claims) ~= "table" then return summary end
  if type(header.alg) == "string" and header.alg == "PS256" then summary.alg = "PS256" end
  summary.aud_is_issuer = claims.aud == ISSUER
  summary.iss_sub_match = type(expected_client) == "string"
    and claims.iss == expected_client and claims.sub == expected_client
  if type(claims.iat) == "number" and type(claims.exp) == "number"
    and claims.iat == math.floor(claims.iat) and claims.exp == math.floor(claims.exp) then
    local ttl = claims.exp - claims.iat
    if ttl > 0 and ttl <= 60 then summary.ttl_seconds = ttl end
  end
  if type(claims.jti) == "string" and #claims.jti > 0 and #claims.jti <= 256 then
    summary.jti_present = true
    local ok, digest = pcall(function()
      local context = digest_lib.new("sha256")
      if not context then return nil end
      return context:final(claims.jti)
    end)
    if ok and type(digest) == "string" and #digest == 32 and jti_count < MAX_JTIS then
      local key = hex(digest)
      summary.jti_distinct = not seen_jti[key]
      if summary.jti_distinct then
        seen_jti[key] = true
        jti_count = jti_count + 1
      end
    end
  end
  return summary
end

local function decode_jwt(value)
  if type(value) ~= "string" or #value > 262144 then return nil end
  local _, payload = value:match("^([^.]+)%.([^.]+)%.[^.]+$")
  if not payload then return nil end
  local json = base64url_decode(payload)
  if not json then return nil end
  local claims = cjson.decode(json)
  if type(claims) == "table" then return claims end
end

local function cnf_matches(access_token, certificate_fingerprint)
  if type(certificate_fingerprint) ~= "string"
    or #certificate_fingerprint ~= 64 or not certificate_fingerprint:match("^[a-f0-9]+$") then return false end
  local claims = decode_jwt(access_token)
  local cnf = claims and claims.cnf
  local thumbprint = type(cnf) == "table" and cnf["x5t#S256"] or nil
  if type(thumbprint) ~= "string" then return false end
  local decoded = base64url_decode(thumbprint)
  return type(decoded) == "string" and #decoded == 32
    and hex(decoded) == certificate_fingerprint
end

local function sha256_hex(value)
  if type(value) ~= "string" or #value == 0 or #value > 1048576 then return nil end
  local ok, digest = pcall(function()
    local context = digest_lib.new("sha256")
    if not context then return nil end
    return context:final(value)
  end)
  if not ok or type(digest) ~= "string" or #digest ~= 32 then return nil end
  return hex(digest)
end

local function route_callback(identity_kind)
  if identity_kind == "route_A" then return "https://localhost:8443/api/fapi/mtls" end
  if identity_kind == "route_B" then return "https://localhost:8443/api/fapi/pkj-mtls" end
end

local function par_evidence(form, identity_kind)
  local nonce = one_field(form, "nonce")
  local callback = route_callback(identity_kind)
  return {
    pkce_s256 = one_field(form, "code_challenge_method") == "S256",
    code_challenge_present = type(one_field(form, "code_challenge")) == "string"
      and #one_field(form, "code_challenge") > 0,
    nonce_present = type(nonce) == "string" and #nonce > 0,
    nonce_at_most_64 = type(nonce) == "string" and #nonce > 0 and #nonce <= 64,
    callback_uri_fixed = callback ~= nil and one_field(form, "redirect_uri") == callback,
  }
end

local function refresh_evidence(form, token_doc, identity_kind, grant_type, status)
  local evidence = {
    input_matches_previous = false,
    output_differs_from_input = false,
    second_uses_rotated = false,
  }
  if (identity_kind ~= "route_A" and identity_kind ~= "route_B") or status ~= 200
    or type(token_doc) ~= "table" then
    return evidence
  end
  local response_token_hash = sha256_hex(token_doc.refresh_token)
  if not response_token_hash then return evidence end
  local dictionary = type(ngx) == "table" and ngx.shared and ngx.shared.kong or nil
  if type(dictionary) ~= "table" and type(dictionary) ~= "userdata" then return evidence end
  local key = "wp5:fapi-refresh:" .. identity_kind
  if grant_type == "authorization_code" then
    pcall(dictionary.set, dictionary, key, "0:" .. response_token_hash, REFRESH_STATE_TTL)
    return evidence
  end
  if grant_type ~= "refresh_token" then return evidence end
  local request_token_hash = sha256_hex(one_field(form, "refresh_token"))
  if not request_token_hash then return evidence end
  local ok, prior = pcall(dictionary.get, dictionary, key)
  if not ok or type(prior) ~= "string" then return evidence end
  local prior_count, prior_hash = prior:match("^(%d):([a-f0-9]+)$")
  prior_count = tonumber(prior_count)
  if (prior_count ~= 0 and prior_count ~= 1) or type(prior_hash) ~= "string" then return evidence end
  evidence.input_matches_previous = request_token_hash == prior_hash
  evidence.output_differs_from_input = response_token_hash ~= request_token_hash
  evidence.second_uses_rotated = prior_count == 1 and evidence.input_matches_previous
    and evidence.output_differs_from_input
  pcall(dictionary.set, dictionary, key,
    tostring(prior_count + 1) .. ":" .. response_token_hash, REFRESH_STATE_TTL)
  return evidence
end

local function classify(uri, method)
  if type(uri) ~= "string" or #uri > 1024 then return nil end
  local prefix = ORIGIN
  if uri:sub(1, #prefix) ~= prefix then return nil end
  local path = uri:sub(#prefix + 1)
  local endpoint = ENDPOINTS[path]
  if not endpoint or endpoint.method ~= method then return nil end
  return endpoint
end

local function emit(encoded, marker)
  if type(encoded) ~= "string" or #encoded > 16384 then return end
  ngx.timer.at(0, function(premature, safe_json, safe_marker)
    if not premature then ngx.log(ngx.ERR, safe_marker, safe_json) end
  end, encoded, marker)
end

local function wire_row(uri, options, response)
  local method = type(options.method) == "string" and options.method or "GET"
  local endpoint = classify(uri, method)
  if not endpoint then return end
  local form = parse_form(options.body)
  local context
  pcall(function()
    local shared = type(kong) == "table" and kong.ctx and kong.ctx.shared or nil
    context = type(shared) == "table" and shared.fapi_as_transport or nil
  end)
  local correlation = header_value(options.headers, CORRELATION)
  if type(correlation) ~= "string" or #correlation ~= 32 or not correlation:match("^[a-f0-9]+$") then
    correlation = "none"
  end
  local observations = context and context.observations
  local transport_observation
  if type(observations) == "table" then
    for index = #observations, 1, -1 do
      local candidate = observations[index]
      if type(candidate) == "table" and candidate.request_id == correlation then
        transport_observation = candidate
        break
      end
    end
  end
  local identity_kind = transport_observation and transport_observation.identity_kind or "metadata"
  if identity_kind ~= "route_A" and identity_kind ~= "route_B" then identity_kind = "metadata" end
  local route = identity_kind == "route_A" and "A" or (identity_kind == "route_B" and "B" or nil)
  local client_id = route == "A" and "third-party-fapi-mtls"
    or (route == "B" and "third-party-fapi-pkj-mtls" or nil)
  local status = type(response) == "table" and response.status or 0
  if type(status) ~= "number" or status < 100 or status > 599 then status = 0 end
  local grant_type = one_field(form, "grant_type")
  if grant_type ~= "authorization_code" and grant_type ~= "refresh_token" then grant_type = "none" end
  local assertion = one_field(form, "client_assertion")
  local summary = safe_assertion(assertion, client_id)
  local token = one_field(form, "token")
  local token_kind = one_field(form, "token_type_hint")
  if token_kind ~= "access_token" and token_kind ~= "refresh_token" then token_kind = "unspecified" end
  local body = type(response) == "table" and response.body or nil
  local token_doc = type(body) == "string" and #body <= 1048576 and cjson.decode(body) or nil
  if type(token_doc) ~= "table" then token_doc = {} end
  local oauth_error = "unknown"
  if type(token_doc.error) == "string" and OAUTH_ERRORS[token_doc.error] then
    oauth_error = token_doc.error
  elseif status == 200 and token_doc.error == nil then
    oauth_error = "none"
  end
  local fingerprint = identity_kind ~= "metadata" and context
    and context.certificate_fingerprint or nil
  local par_summary = endpoint.kind == "par" and par_evidence(form, identity_kind) or nil
  local rotation_summary = endpoint.kind == "token"
    and refresh_evidence(form, token_doc, identity_kind, grant_type, status) or {
      input_matches_previous = false,
      output_differs_from_input = false,
      second_uses_rotated = false,
    }
  local row = {
    v = 1,
    request_id = correlation,
    endpoint_kind = endpoint.kind,
    method = method,
    logical_route = route == "A" and "A" or (route == "B" and "B" or "none"),
    identity_kind = identity_kind,
    status = status,
    client_cert_present = option_present(options.ssl_client_cert),
    client_key_present = option_present(options.ssl_client_priv_key),
    client_assertion_present = assertion ~= nil,
    client_assertion_type_present = one_field(form, "client_assertion_type") ~= nil,
    grant_type = grant_type,
    token_kind = token_kind,
    assertion = summary,
    par_evidence = par_summary or {
      pkce_s256 = false, code_challenge_present = false, nonce_present = false,
      nonce_at_most_64 = false, callback_uri_fixed = false,
    },
    refresh_evidence = rotation_summary,
    token_present = type(token_doc.access_token) == "string" and #token_doc.access_token > 0,
    refresh_token_present = type(token_doc.refresh_token) == "string" and #token_doc.refresh_token > 0,
    cnf_matches = cnf_matches(token_doc.access_token, fingerprint),
    revoke_token_present = type(token) == "string" and #token > 0,
    oauth_error_enum = oauth_error,
  }
  local encoded = cjson.encode(row)
  emit(encoded, WIRE_MARKER)
end

local function sanitize_context_observation(row)
  if type(row) ~= "table" then return nil end
  if not CONTEXT_ENDPOINTS[row.endpoint_kind] or not CONTEXT_METHODS[row.method]
    or not CONTEXT_IDENTITIES[row.identity_kind] or not CONTEXT_AUTH[row.oauth_auth_method]
    or not CONTEXT_RESULTS[row.result] then
    return nil
  end
  local route = row.identity_kind == "route_A" and "A"
    or (row.identity_kind == "route_B" and "B" or "none")
  local safe = {
    request_id = type(row.request_id) == "string" and #row.request_id == 32
      and row.request_id:match("^[a-f0-9]+$") and row.request_id or "none",
    logical_route = route,
    endpoint_kind = row.endpoint_kind,
    method = row.method,
    identity_kind = row.identity_kind,
    oauth_auth_method = row.oauth_auth_method,
    result = row.result,
    not_sent = row.not_sent == true,
  }
  if type(row.http_status) == "number" and row.http_status >= 100
    and row.http_status <= 599 and row.http_status == math.floor(row.http_status) then
    safe.http_status = row.http_status
  end
  if CONTEXT_REJECTIONS[row.rejection_layer] then safe.rejection_layer = row.rejection_layer end
  if CONTEXT_REASONS[row.reason_code] then safe.reason_code = row.reason_code end
  if row.grant_type == "authorization_code" or row.grant_type == "refresh_token" then
    safe.grant_type = row.grant_type
  end
  if row.token_kind == "access_token" or row.token_kind == "refresh_token"
    or row.token_kind == "unspecified" then
    safe.token_kind = row.token_kind
  end
  if type(row.claim_summary) == "table" then
    local claim = row.claim_summary
    safe.claim_summary = {
      alg = claim.alg == "PS256" and "PS256" or "unknown",
      aud_is_issuer = claim.aud_is_issuer == true,
      iss_sub_match = claim.iss_sub_match == true,
      ttl_seconds = type(claim.ttl_seconds) == "number" and claim.ttl_seconds >= 0
        and claim.ttl_seconds <= 60 and math.floor(claim.ttl_seconds) or 0,
      jti_present = claim.jti_present == true,
    }
  end
  return safe
end

local function emit_context_rows()
  local shared = type(kong) == "table" and kong.ctx and kong.ctx.shared
  local context = type(shared) == "table" and shared.fapi_as_transport or nil
  local observations = context and context.observations
  if type(observations) ~= "table" or #observations == 0 then return end
  local safe_rows = {}
  for index = 1, math.min(#observations, MAX_CONTEXT_ROWS) do
    local safe = sanitize_context_observation(observations[index])
    if safe then safe_rows[#safe_rows + 1] = safe end
  end
  local encoded = cjson.encode({ v = 1, observations = safe_rows, truncated = #observations > MAX_CONTEXT_ROWS })
  emit(encoded, CONTEXT_MARKER)
end

local TransportDiagnostic = { PRIORITY = 1200, VERSION = "0.1.0" }

function TransportDiagnostic:init_worker()
  if wrapped then return end
  local original = resty_http.request_uri
  if type(original) ~= "function" then error("WP5 transport diagnostic could not wrap request_uri") end
  resty_http.request_uri = function(...)
    local args = pack(...)
    local results = pack(original(unpack(args, 1, args.n)))
    pcall(wire_row, args[2], args[3] or {}, results[1])
    return unpack(results, 1, results.n)
  end
  wrapped = true
end

function TransportDiagnostic:access(_conf)
  return
end

function TransportDiagnostic:log(_conf)
  pcall(emit_context_rows)
end

return TransportDiagnostic
