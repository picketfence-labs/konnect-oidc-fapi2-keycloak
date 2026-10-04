local cjson = require "cjson.safe"
local http = require "resty.http"
local pkey_lib = require "resty.openssl.pkey"
local random = require "resty.random"

local ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
local ISSUER = "https://localhost:8444/realms/fapi-demo"
local DISCOVERY = "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration"
local ROUTE_B_ID = "0f45debe-a3a6-5207-aea3-637227fb96f2"
local ROUTE_B_CLIENT = "third-party-fapi-pkj-mtls"
local ROUTE_B_KEY = "/etc/kong/fapi/route-b-pkj.key"
local ROUTE_B_CERT = "/etc/kong/fapi/route-b.crt"

local discovery_cache = {}
local cached_keys = {}
local transport
local transport_ok, transport_module = pcall(require, "kong.plugins.fapi-as-mtls-transport.handler")
if transport_ok and type(transport_module) == "table" then
  transport = transport_module
end

local state = {
  loaded = true,
  delegate_ready = false,
  delegate_failed = false,
  configured_delivery = nil,
  config_signature = nil,
  delegate_conf = nil,
  signer_epoch = nil,
}

local function base64url(value)
  return ngx.encode_base64(value, true):gsub("%+", "-"):gsub("/", "_")
end

local function read_file(path, limit)
  local file = io.open(path, "rb")
  if not file then
    return nil
  end
  local value = file:read((limit or 262144) + 1)
  file:close()
  if type(value) ~= "string" or #value == 0 or #value > (limit or 262144) then
    return nil
  end
  return value
end

local function load_key(path, epoch)
  if type(epoch) ~= "string" or epoch == "" then
    return nil
  end
  local cache_key = epoch .. "\0" .. path
  if cached_keys[cache_key] then
    return cached_keys[cache_key]
  end

  local pem = read_file(path, 65536)
  if not pem then
    return nil
  end
  local key = pkey_lib.new(pem)
  if not key then
    return nil
  end
  cached_keys[cache_key] = key
  return key
end

local function verify_discovery_issuer(conf, epoch)
  local cache_key = epoch .. "\0" .. conf.discovery_endpoint .. "\0" .. conf.issuer
  local cached_until = discovery_cache[cache_key]
  if cached_until and cached_until > ngx.now() then
    return true
  end

  local client = http.new()
  client:set_timeout(conf.discovery_timeout)
  local response = client:request_uri(conf.discovery_endpoint, {
    method = "GET",
    ssl_verify = true,
    keepalive = true,
    headers = { Accept = "application/json" },
  })
  if not response or response.status ~= 200 then
    return nil
  end
  local metadata = cjson.decode(response.body)
  if type(metadata) ~= "table" or metadata.issuer ~= conf.issuer then
    return nil
  end

  discovery_cache[cache_key] = ngx.now() + conf.discovery_cache_ttl
  return true
end

local function supplied_by_client()
  if kong.request.get_header("client_assertion")
      or kong.request.get_header("client_assertion_type") then
    return true
  end

  local query = kong.request.get_query()
  if query.client_assertion or query.client_assertion_type then
    return true
  end

  local body = kong.request.get_body()
  return body and (body.client_assertion or body.client_assertion_type) or false
end

local function config_signature(conf)
  return table.concat({
    tostring(conf.issuer or ""),
    tostring(conf.discovery_endpoint or ""),
    tostring(conf.client_id or ""),
    tostring(conf.private_key_file or ""),
    tostring(conf.tls_certificate_file or ""),
    tostring(conf.key_id or ""),
    tostring(conf.assertion_ttl or ""),
    tostring(conf.discovery_timeout or ""),
    tostring(conf.discovery_cache_ttl or ""),
  }, "\0")
end

local function validate_delegate_config(conf)
  if type(conf) ~= "table"
    or conf.assertion_delivery ~= "transport_delegate"
    or conf.issuer ~= ISSUER
    or conf.discovery_endpoint ~= DISCOVERY
    or conf.client_id ~= ROUTE_B_CLIENT
    or conf.private_key_file ~= ROUTE_B_KEY
    or conf.tls_certificate_file ~= ROUTE_B_CERT
    or type(conf.key_id) ~= "string" or conf.key_id == "" or #conf.key_id > 128
    or conf.assertion_ttl ~= 60
    or type(conf.discovery_timeout) ~= "number"
    or conf.discovery_timeout < 100 or conf.discovery_timeout > 10000
    or type(conf.discovery_cache_ttl) ~= "number"
    or conf.discovery_cache_ttl < 1 or conf.discovery_cache_ttl > 3600 then
    return nil
  end
  return true
end

local function read_one_config(configs)
  if type(configs) ~= "table" or #configs ~= 1 or type(configs[1]) ~= "table" then
    return nil
  end
  local entry = configs[1]
  return type(entry.config) == "table" and entry.config or entry
end

local function copy_delegate_config(conf)
  return {
    assertion_delivery = "transport_delegate",
    issuer = conf.issuer,
    discovery_endpoint = conf.discovery_endpoint,
    client_id = conf.client_id,
    private_key_file = conf.private_key_file,
    tls_certificate_file = conf.tls_certificate_file,
    key_id = conf.key_id,
    assertion_ttl = conf.assertion_ttl,
    discovery_timeout = conf.discovery_timeout,
    discovery_cache_ttl = conf.discovery_cache_ttl,
  }
end

local function create_assertion(conf, epoch)
  local key = load_key(conf.private_key_file, epoch)
  if not key then
    return nil
  end

  local now = ngx.time()
  local nonce = random.bytes(32, true)
  if type(nonce) ~= "string" or #nonce ~= 32 then
    return nil
  end

  local header = cjson.encode({ alg = "PS256", kid = conf.key_id, typ = "JWT" })
  local payload = cjson.encode({
    aud = conf.issuer,
    exp = now + (conf.assertion_ttl or 60),
    iat = now,
    iss = conf.client_id,
    jti = base64url(nonce),
    sub = conf.client_id,
  })
  if not header or not payload then
    return nil
  end

  local signing_input = base64url(header) .. "." .. base64url(payload)
  local ok, signature = pcall(function()
    return key:sign(
      signing_input,
      "sha256",
      pkey_lib.PADDINGS.RSA_PKCS1_PSS_PADDING,
      { "rsa_pss_saltlen:digest", "rsa_mgf1_md:sha256" }
    )
  end)
  if not ok or type(signature) ~= "string" then
    return nil
  end
  return signing_input .. "." .. base64url(signature)
end

local function refresh_transport_status()
  state.delegate_ready = false
  state.signer_epoch = nil
  if not transport then
    return false
  end

  local epoch = transport.current_registry_epoch()
  local conf = state.delegate_conf
  local ready = not state.delegate_failed
    and state.configured_delivery == "transport_delegate"
    and conf ~= nil
    and type(epoch) == "string"
    and validate_delegate_config(conf) == true
    and transport.route_manifest_matches(ROUTE_B_ID, ROUTE_B_CLIENT, "B", epoch)
    and transport.route_certificate_matches(ROUTE_B_ID, ROUTE_B_CERT)
    and load_key(ROUTE_B_KEY, epoch) ~= nil

  state.delegate_ready = ready == true
  state.signer_epoch = state.delegate_ready and epoch or nil
  transport.mark_bridge_status(state.delegate_ready, state.signer_epoch)
  return state.delegate_ready
end

local function register_delegate(conf)
  if not transport or not refresh_transport_status() then
    return false
  end
  local context = transport.context_for_bridge()
  local epoch = state.signer_epoch
  if type(context) ~= "table"
    or context.registry_epoch ~= epoch
    or context.logical_route ~= "B"
    or context.client_id ~= ROUTE_B_CLIENT
    or not transport.route_identity_matches(context, ROUTE_B_CLIENT, "B") then
    return false
  end

  -- The token form is signed only after transport has canonicalized and marked the
  -- operation as sent, immediately before the single underlying request_uri call.
  context.signer_epoch = epoch
  context.sign_assertion = function()
    local current_epoch = transport.current_registry_epoch()
    if current_epoch ~= epoch
      or context.registry_epoch ~= current_epoch
      or context.signer_epoch ~= current_epoch
      or not transport.route_identity_matches(context, ROUTE_B_CLIENT, "B") then
      return nil
    end
    local assertion = create_assertion(conf, current_epoch)
    if not assertion then
      return nil
    end
    return assertion, ASSERTION_TYPE
  end
  return true
end

local Bridge = {
  PRIORITY = 1060,
  VERSION = "0.2.0",
}

function Bridge:init_worker()
  if transport then
    transport.mark_bridge_loaded()
    refresh_transport_status()
  end
end

function Bridge:configure(configs)
  local conf = read_one_config(configs)
  local delivery = conf and conf.assertion_delivery or "header"
  if state.configured_delivery ~= nil and state.configured_delivery ~= delivery then
    state.delegate_failed = true
    state.delegate_ready = false
    if transport then
      transport.mark_bridge_status(false, nil)
    end
    return
  end

  if delivery == "transport_delegate" then
    if not conf or validate_delegate_config(conf) ~= true then
      state.delegate_failed = true
      state.delegate_ready = false
      if transport then
        transport.mark_bridge_status(false, nil)
      end
      return
    end
    local signature = config_signature(conf)
    if state.config_signature and state.config_signature ~= signature then
      state.delegate_failed = true
      state.delegate_ready = false
      if transport then
        transport.mark_bridge_status(false, nil)
      end
      return
    end
    state.config_signature = signature
    state.delegate_conf = copy_delegate_config(conf)
  elseif delivery ~= "header" then
    state.delegate_failed = true
    state.delegate_ready = false
    if transport then
      transport.mark_bridge_status(false, nil)
    end
    return
  end

  state.configured_delivery = delivery
  if transport then
    transport.mark_bridge_loaded()
    refresh_transport_status()
  end
end

function Bridge:access(conf)
  if supplied_by_client() then
    return kong.response.exit(400, {
      error = "invalid_request",
      error_description = "client assertion parameters are generated by Kong Gateway",
    })
  end

  if conf.assertion_delivery == "transport_delegate" then
    if state.delegate_failed or not validate_delegate_config(conf)
      or not state.config_signature
      or config_signature(conf) ~= state.config_signature then
      state.delegate_failed = true
      state.delegate_ready = false
      if transport then
        transport.mark_bridge_status(false, nil)
      end
      return kong.response.exit(500, { error = "client_authentication_unavailable" })
    end
    local delegate_conf = state.delegate_conf
    if not register_delegate(delegate_conf) then
      return kong.response.exit(500, { error = "client_authentication_unavailable" })
    end
    if not verify_discovery_issuer(delegate_conf, state.signer_epoch) then
      return kong.response.exit(500, { error = "client_authentication_unavailable" })
    end
    return
  end

  -- Preserve the existing v1 header-delivery behavior for configurations which do
  -- not opt into the transport delegate.
  local legacy_conf = conf
  local epoch = "header-mode"
  local certificate = read_file(legacy_conf.tls_certificate_file, 262144)
  if not certificate or not certificate:find("BEGIN CERTIFICATE", 1, true) then
    kong.log.err("fapi-client-auth-bridge failed closed: TLS certificate unavailable")
    return kong.response.exit(500, { error = "client_authentication_unavailable" })
  end
  local issuer_valid = verify_discovery_issuer(legacy_conf, epoch)
  if not issuer_valid then
    kong.log.err("fapi-client-auth-bridge failed closed: OIDC discovery validation failed")
    return kong.response.exit(500, { error = "client_authentication_unavailable" })
  end

  local assertion = create_assertion(legacy_conf, epoch)
  if not assertion then
    kong.log.err("fapi-client-auth-bridge failed closed: signing key unavailable")
    return kong.response.exit(500, { error = "client_authentication_unavailable" })
  end

  ngx.req.set_header("client_assertion", assertion)
  ngx.req.set_header("client_assertion_type", ASSERTION_TYPE)
end

function Bridge.status_snapshot()
  return {
    bridge_loaded = state.loaded,
    delegate_ready = state.delegate_ready == true,
  }
end

Bridge.refresh_transport_status = refresh_transport_status

if transport then
  transport.mark_bridge_loaded()
end

return Bridge
