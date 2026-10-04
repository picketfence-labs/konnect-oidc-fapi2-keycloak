local cjson = require "cjson.safe"
local ffi = require "ffi"
local http = require "resty.http"
local random = require "resty.random"
local digest_lib = require "resty.openssl.digest"
local x509 = require "resty.openssl.x509"
local pkey = require "resty.openssl.pkey"
local x509_chain = require "resty.openssl.x509.chain"
local ngx_ssl = require "ngx.ssl"

local ISSUER = "https://localhost:8444/realms/fapi-demo"
local INTERNAL_ORIGIN = "https://keycloak:8443"
local DISCOVERY_PUBLIC = ISSUER .. "/.well-known/openid-configuration"
local DISCOVERY_INTERNAL = INTERNAL_ORIGIN .. "/realms/fapi-demo/.well-known/openid-configuration"
local JWKS = INTERNAL_ORIGIN .. "/realms/fapi-demo/protocol/openid-connect/certs"
local PAR = INTERNAL_ORIGIN .. "/realms/fapi-demo/protocol/openid-connect/ext/par/request"
local TOKEN = INTERNAL_ORIGIN .. "/realms/fapi-demo/protocol/openid-connect/token"
local REVOCATION = INTERNAL_ORIGIN .. "/realms/fapi-demo/protocol/openid-connect/revoke"
local CORRELATION_HEADER = "X-Fapi-Demo-Observation-ID"
local ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
local MAX_FORM_BYTES = 16384
local MAX_FORM_FIELDS = 64
local MAX_FORM_NAME_BYTES = 256
local MAX_FORM_VALUE_BYTES = 8192
local MAX_OBSERVATIONS = 32
local STATUS_DIR = "/run/kong/fapi-transport-ready"
local READY_MARKER = STATUS_DIR .. "/ready.json"
local MAX_READY_MARKER_BYTES = 16384
local MAX_WORKERS = 64

local MANIFEST = {
  ["754519ff-b0b9-5ed5-94c0-e453d260c6c4"] = {
    logical_route = "A",
    client_id = "third-party-fapi-mtls",
    certificate_file = "/etc/kong/fapi/route-a.crt",
    key_file = "/etc/kong/fapi/route-a.key",
  },
  ["0f45debe-a3a6-5207-aea3-637227fb96f2"] = {
    logical_route = "B",
    client_id = "third-party-fapi-pkj-mtls",
    certificate_file = "/etc/kong/fapi/route-b.crt",
    key_file = "/etc/kong/fapi/route-b.key",
  },
}

-- Kong 3.16 decorates plugin configure records with these runtime-only fields.
-- They are deliberately ignored at the boundary and never enter signatures,
-- route validation, or exported status.
local KONG_CONFIG_METADATA = {
  ordering = true,
  route_id = true,
  service_id = true,
  consumer_id = true,
  consumer_group_id = true,
  plugin_instance_name = true,
  __plugin_id = true,
  __ws_id = true,
  __plugin_name = true,
  __key__ = true,
  __seq__ = true,
  __compiled_condition = true,
  __compiled_expressions = true,
}

local state = {
  wrapper_ready = false,
  registry_ready = false,
  bridge_loaded = false,
  delegate_ready = false,
  failed = false,
  registry = nil,
  config_hash = nil,
  registry_epoch = nil,
  original_request_uri = nil,
  wrapped_request_uri = nil,
  observations = nil,
  status_export_failed = false,
  worker_initialized = false,
}

local config_signature
local chmod_declared = false

local function copy_table(source)
  local result = {}
  if type(source) == "table" then
    for key, value in pairs(source) do
      result[key] = value
    end
  end
  return result
end

local function hex(value)
  return (value:gsub(".", function(byte)
    return string.format("%02x", string.byte(byte))
  end))
end

local function sha256(value)
  if type(value) ~= "string" then
    return nil
  end
  local context = digest_lib.new("sha256")
  if not context then
    return nil
  end
  local result = context:final(value)
  if type(result) ~= "string" or #result ~= 32 then
    return nil
  end
  return hex(result)
end

local function read_limited(path, max_bytes)
  local file = io.open(path, "rb")
  if not file then
    return nil
  end
  local value = file:read(max_bytes + 1)
  file:close()
  if type(value) ~= "string" or #value == 0 or #value > max_bytes then
    return nil
  end
  return value
end

local function client_identity(cert_path, key_path)
  local cert_pem = read_limited(cert_path, 262144)
  local key_pem = read_limited(key_path, 65536)
  if not cert_pem or not key_pem then
    return nil
  end

  local cert = x509.new(cert_pem, "PEM")
  local private_key = pkey.new(key_pem)
  if not cert or not private_key then
    return nil
  end

  local matches = cert:check_private_key(private_key)
  if not matches then
    return nil
  end

  local not_before, not_after = cert:get_lifetime()
  local now = ngx.time()
  if type(not_before) ~= "number" or type(not_after) ~= "number"
    or not_before > now or not_after <= now then
    return nil
  end

  local eku = cert:get_extension("extendedKeyUsage")
  if not eku then
    return nil
  end
  local eku_text = eku:text()
  if type(eku_text) ~= "string"
    or eku_text:gsub("^%s+", ""):gsub("%s+$", "") ~= "TLS Web Client Authentication" then
    return nil
  end

  local fingerprint = cert:digest("sha256")
  if type(fingerprint) ~= "string" or #fingerprint ~= 32 then
    return nil
  end

  local cert_cdata = ngx_ssl.parse_pem_cert(cert_pem)
  local key_cdata = ngx_ssl.parse_pem_priv_key(key_pem)
  if not cert_cdata or not key_cdata then
    return nil
  end

  return {
    certificate_cdata = cert_cdata,
    key_cdata = key_cdata,
    certificate = cert,
    private_key = private_key,
    fingerprint = hex(fingerprint),
  }
end

local function stock_certificate_fingerprint(cert_cdata)
  if not cert_cdata then
    return nil
  end
  local ok, chain = pcall(function()
    return x509_chain.dup(ffi.cast("OPENSSL_STACK*", cert_cdata))
  end)
  if not ok or not chain or #chain < 1 then
    return nil
  end
  local leaf = x509.dup(chain[1].ctx)
  if not leaf then
    return nil
  end
  local fingerprint = leaf:digest("sha256")
  if type(fingerprint) ~= "string" or #fingerprint ~= 32 then
    return nil
  end
  return hex(fingerprint), leaf
end

local function stock_key_matches(cert, key_cdata)
  if not key_cdata then
    return true
  end
  local ok, key = pcall(function()
    return pkey.new(ffi.cast("EVP_PKEY*", key_cdata))
  end)
  if not ok or not key then
    return false
  end
  if key.ctx and ffi.gc then
    ffi.gc(key.ctx, nil)
  end
  local matches = cert:check_private_key(key)
  return matches == true
end

local function stock_identity_matches(options, identity)
  local supplied_cert = options.ssl_client_cert
  local supplied_key = options.ssl_client_priv_key
  if not supplied_cert and not supplied_key then
    return true
  end
  if not supplied_cert or not supplied_key then
    return false
  end
  local fingerprint, cert = stock_certificate_fingerprint(supplied_cert)
  if not fingerprint or fingerprint ~= identity.fingerprint then
    return false
  end
  return stock_key_matches(cert, supplied_key)
end

local function unwrap_plugin_config(configs)
  if type(configs) ~= "table" or #configs ~= 1 then
    return nil
  end
  local entry = configs[1]
  if type(entry) ~= "table" then
    return nil
  end
  if type(entry.config) == "table" then
    return entry.config
  end
  return entry
end

local function validate_config(config)
  if type(config) ~= "table" then
    return nil
  end
  local expected = {
    issuer = ISSUER,
    internal_origin = INTERNAL_ORIGIN,
    discovery_url = DISCOVERY_INTERNAL,
    jwks_url = JWKS,
    par_url = PAR,
    token_url = TOKEN,
    revocation_url = REVOCATION,
    metadata_certificate_file = "/etc/kong/fapi/third-party-metadata.crt",
    metadata_key_file = "/etc/kong/fapi/third-party-metadata.key",
  }
  for field, value in pairs(expected) do
    if config[field] ~= value then
      return nil
    end
  end
  if config.evidence_correlation_enabled ~= nil
    and type(config.evidence_correlation_enabled) ~= "boolean" then
    return nil
  end
  for field in pairs(config) do
    if expected[field] == nil and field ~= "routes" and field ~= "evidence_correlation_enabled"
      and KONG_CONFIG_METADATA[field] ~= true then
      return nil
    end
  end
  if type(config.routes) ~= "table" or #config.routes ~= 2 then
    return nil
  end

  local routes = {}
  for _, route in ipairs(config.routes) do
    if type(route) ~= "table" or type(route.route_id) ~= "string" then
      return nil
    end
    local expected_route = MANIFEST[route.route_id]
    if not expected_route or routes[route.route_id] then
      return nil
    end
    for field, value in pairs(expected_route) do
      if route[field] ~= value then
        return nil
      end
    end
    for field in pairs(route) do
      if field ~= "route_id" and expected_route[field] == nil then
        return nil
      end
    end
    routes[route.route_id] = copy_table(expected_route)
    routes[route.route_id].route_id = route.route_id
  end
  if not routes["754519ff-b0b9-5ed5-94c0-e453d260c6c4"]
    or not routes["0f45debe-a3a6-5207-aea3-637227fb96f2"] then
    return nil
  end

  local bootstrap_issuer = os.getenv("FAPI_AS_TRANSPORT_ISSUER")
  local bootstrap_origin = os.getenv("FAPI_AS_TRANSPORT_INTERNAL_ORIGIN")
  if bootstrap_issuer ~= ISSUER or bootstrap_origin ~= INTERNAL_ORIGIN then
    return nil
  end
  return routes
end

local function canonical_config_hash(config, routes, identities, metadata)
  local values = {
    ISSUER,
    INTERNAL_ORIGIN,
    DISCOVERY_INTERNAL,
    JWKS,
    PAR,
    TOKEN,
    REVOCATION,
    config.metadata_certificate_file,
    config.metadata_key_file,
    metadata.fingerprint,
    tostring(config.evidence_correlation_enabled == true),
  }
  local ordered_ids = {
    "0f45debe-a3a6-5207-aea3-637227fb96f2",
    "754519ff-b0b9-5ed5-94c0-e453d260c6c4",
  }
  for _, route_id in ipairs(ordered_ids) do
    local route = routes[route_id]
    table.insert(values, route.route_id)
    table.insert(values, route.logical_route)
    table.insert(values, route.client_id)
    table.insert(values, route.certificate_file)
    table.insert(values, route.key_file)
    table.insert(values, identities[route_id].fingerprint)
  end
  return sha256(table.concat(values, "\0"))
end

local function safe_worker_value(name, fallback)
  local worker = ngx.worker
  local getter = worker and worker[name]
  if type(getter) ~= "function" then
    return fallback
  end
  local ok, value = pcall(getter)
  if not ok or value == nil then
    return fallback
  end
  return value
end

local function ensure_worker_identity(force)
  if state.worker_id ~= nil and not force then
    return true
  end
  state.worker_id = safe_worker_value("id", 0)
  state.pid = safe_worker_value("pid", 0)
  state.startup_generation = os.getenv("FAPI_AS_TRANSPORT_GENERATION")
  local status_dir = os.getenv("FAPI_AS_TRANSPORT_STATUS_DIR")
  if status_dir and status_dir ~= "" then
    if status_dir ~= STATUS_DIR
      or type(state.startup_generation) ~= "string"
      or not state.startup_generation:match("^[%w._:-]+$")
      or #state.startup_generation > 128 then
      state.status_config_valid = false
    else
      state.status_config_valid = true
      state.status_dir = status_dir
    end
  else
    state.status_config_valid = true
    state.status_dir = nil
    state.startup_generation = state.startup_generation or "offline-test"
  end
  if type(state.startup_generation) ~= "string" then
    state.startup_generation = "unavailable"
  end
  return state.status_config_valid ~= false
end

local function refresh_registry_epoch()
  if not state.config_hash then
    return
  end
  state.registry_epoch = sha256(table.concat({
    tostring(state.worker_id),
    tostring(state.pid),
    state.startup_generation,
    state.config_hash,
  }, "\0"))
end

local function public_routes()
  local routes = {}
  if state.registry then
    for route_id, route in pairs(state.registry.routes) do
      table.insert(routes, {
        route_id = route_id,
        logical_route = route.logical_route,
        client_id = route.client_id,
      })
    end
  end
  table.sort(routes, function(left, right)
    return left.logical_route < right.logical_route
  end)
  return routes
end

local function status_snapshot()
  ensure_worker_identity()
  return {
    worker_id = state.worker_id,
    pid = state.pid,
    generation = state.startup_generation,
    config_hash = state.config_hash,
    registry_epoch = state.registry_epoch,
    wrapper_ready = state.wrapper_ready == true,
    registry_ready = state.registry_ready == true and not state.failed
      and state.status_export_failed ~= true,
    bridge_loaded = state.bridge_loaded == true,
    delegate_ready = state.delegate_ready == true and not state.failed
      and state.status_export_failed ~= true,
    routes = public_routes(),
  }
end

local function encode_status()
  local status = status_snapshot()
  return cjson.encode(status)
end

local function chmod_0600(path)
  if not chmod_declared then
    local ok = pcall(function()
      ffi.cdef("int chmod(const char *pathname, unsigned int mode);")
    end)
    if not ok then
      return false
    end
    chmod_declared = true
  end
  local result = ffi.C.chmod(path, 384)
  return result == 0
end

local function write_status_once(contents, temp_path, status_path)
  local file = io.open(temp_path, "wb")
  if not file then
    return false
  end
  local ok = file:write(contents)
  local closed = file:close()
  if not ok or not closed or not chmod_0600(temp_path) then
    os.remove(temp_path)
    return false
  end
  if not os.rename(temp_path, status_path) then
    os.remove(temp_path)
    return false
  end
  return true
end

local function remove_ready_marker()
  if state.status_dir == STATUS_DIR then
    os.remove(READY_MARKER)
  end
end

local function write_status()
  ensure_worker_identity()
  if not state.worker_initialized then
    return true
  end
  if state.failed or state.registry_ready ~= true then
    remove_ready_marker()
  end
  if not state.status_dir then
    return true
  end
  local filename = state.status_dir .. "/worker-" .. tostring(state.worker_id) .. ".json"
  local temp = filename .. ".tmp-" .. tostring(state.pid)
  state.status_export_failed = false
  local contents = encode_status()
  if contents and write_status_once(contents, temp, filename) then
    return true
  end
  state.status_export_failed = true
  remove_ready_marker()
  local fallback = encode_status()
  if fallback then
    write_status_once(fallback, temp, filename)
  end
  return false
end

local function has_exact_keys(value, allowed)
  if type(value) ~= "table" then
    return false
  end
  local count = 0
  for key in pairs(value) do
    if not allowed[key] then
      return false
    end
    count = count + 1
  end
  local expected = 0
  for _ in pairs(allowed) do
    expected = expected + 1
  end
  return count == expected
end

local function ready_marker_covers_worker()
  if not state.status_dir then
    -- Explicit offline/unit mode. Runtime sets the fixed status directory and is
    -- therefore held behind the all-worker launcher marker.
    return true
  end
  if state.status_dir ~= STATUS_DIR or not state.config_hash
    or not state.registry_epoch or state.status_config_valid == false
    or state.status_export_failed == true then
    return false
  end
  local contents = read_limited(READY_MARKER, MAX_READY_MARKER_BYTES)
  local marker = contents and cjson.decode(contents)
  if not has_exact_keys(marker, {
    generation = true,
    config_hash = true,
    workers = true,
  }) or marker.generation ~= state.startup_generation
    or marker.config_hash ~= state.config_hash or type(marker.workers) ~= "table" then
    return false
  end

  local count, found_self = 0, false
  local worker_ids, pids = {}, {}
  for key, worker in pairs(marker.workers) do
    if type(key) ~= "number" or key % 1 ~= 0 or key < 1 or key > MAX_WORKERS then
      return false
    end
    count = count + 1
    if count > MAX_WORKERS or not has_exact_keys(worker, {
      worker_id = true,
      pid = true,
      registry_epoch = true,
    }) or type(worker.worker_id) ~= "number" or worker.worker_id % 1 ~= 0
      or worker.worker_id < 0 or type(worker.pid) ~= "number"
      or worker.pid % 1 ~= 0 or worker.pid <= 0
      or type(worker.registry_epoch) ~= "string" or worker.registry_epoch == "" then
      return false
    end
    if worker_ids[worker.worker_id] or pids[worker.pid] then
      return false
    end
    worker_ids[worker.worker_id] = true
    pids[worker.pid] = true
    if worker.worker_id == state.worker_id and worker.pid == state.pid
      and worker.registry_epoch == state.registry_epoch then
      found_self = true
    end
  end
  return count > 0 and found_self
end

local function refresh_bridge_status()
  local bridge = package.loaded["kong.plugins.fapi-client-auth-bridge.handler"]
  if type(bridge) == "table" and type(bridge.refresh_transport_status) == "function" then
    pcall(bridge.refresh_transport_status)
  end
end

local function mark_bridge_loaded()
  state.bridge_loaded = true
  if state.worker_initialized then
    write_status()
  end
end

local function mark_bridge_status(ready, epoch)
  state.bridge_loaded = true
  state.delegate_ready = ready == true
    and not state.failed
    and state.registry_ready == true
    and type(epoch) == "string"
    and epoch == state.registry_epoch
  if state.worker_initialized then
    if not state.delegate_ready then
      remove_ready_marker()
    end
    write_status()
  end
  return state.delegate_ready
end

local function configure(configs)
  ensure_worker_identity()
  if state.failed then
    state.registry_ready = false
    state.delegate_ready = false
    write_status()
    return
  end

  local initial_config_absent = configs == nil
    or (type(configs) == "table" and next(configs) == nil)
  if initial_config_absent and not state.config_source and not state.config_hash then
    state.registry = nil
    state.registry_ready = false
    state.delegate_ready = false
    remove_ready_marker()
    write_status()
    refresh_bridge_status()
    return
  end

  local config = unwrap_plugin_config(configs)
  local routes = validate_config(config)
  if not routes then
    state.failed = true
    state.registry_ready = false
    state.delegate_ready = false
    state.registry = nil
    write_status()
    refresh_bridge_status()
    return
  end

  local signature = config_signature and config_signature(config)
  if not signature then
    state.failed = true
    state.registry_ready = false
    state.delegate_ready = false
    state.registry = nil
    write_status()
    refresh_bridge_status()
    return
  end
  if state.config_source and state.config_source ~= signature then
    state.failed = true
    state.registry_ready = false
    state.delegate_ready = false
    state.registry = nil
    write_status()
    refresh_bridge_status()
    return
  end

  local metadata = client_identity(config.metadata_certificate_file, config.metadata_key_file)
  if not metadata then
    state.failed = true
    state.registry_ready = false
    state.delegate_ready = false
    state.registry = nil
    write_status()
    refresh_bridge_status()
    return
  end

  local identities = {}
  for route_id, route in pairs(routes) do
    identities[route_id] = client_identity(route.certificate_file, route.key_file)
    if not identities[route_id] then
      state.failed = true
      state.registry_ready = false
      state.delegate_ready = false
      state.registry = nil
      write_status()
      refresh_bridge_status()
      return
    end
  end

  local config_hash = canonical_config_hash(config, routes, identities, metadata)
  if not config_hash then
    state.failed = true
    state.registry_ready = false
    state.delegate_ready = false
    state.registry = nil
    write_status()
    refresh_bridge_status()
    return
  end
  if state.config_hash and state.config_hash ~= config_hash then
    state.failed = true
    state.registry_ready = false
    state.delegate_ready = false
    state.registry = nil
    write_status()
    refresh_bridge_status()
    return
  end

  state.config_hash = config_hash
  state.config_source = signature
  state.startup_generation = state.startup_generation or "offline-test"
  refresh_registry_epoch()
  local registry_epoch = state.registry_epoch
  if not registry_epoch then
    state.failed = true
    state.registry_ready = false
    state.delegate_ready = false
    state.registry = nil
    write_status()
    refresh_bridge_status()
    return
  end

  local identities_with_routes = {}
  for route_id, route in pairs(routes) do
    identities_with_routes[route_id] = route
    for field, value in pairs(identities[route_id]) do
      identities_with_routes[route_id][field] = value
    end
  end
  state.registry = {
    config = {
      evidence_correlation_enabled = config.evidence_correlation_enabled == true,
    },
    metadata_identity = metadata,
    routes = identities_with_routes,
    by_logical_route = {
      A = identities_with_routes["754519ff-b0b9-5ed5-94c0-e453d260c6c4"],
      B = identities_with_routes["0f45debe-a3a6-5207-aea3-637227fb96f2"],
    },
  }
  state.registry_ready = state.status_config_valid ~= false
  state.delegate_ready = false
  write_status()
  refresh_bridge_status()
end

-- All configured values are fixed/public, so this signature contains no PEM or key data.
config_signature = function(config)
  if type(config) ~= "table" then
    return nil
  end
  local routes = {}
  for _, route in ipairs(config.routes or {}) do
    if type(route) ~= "table" then
      return nil
    end
    table.insert(routes, table.concat({
      tostring(route.route_id or ""),
      tostring(route.logical_route or ""),
      tostring(route.client_id or ""),
      tostring(route.certificate_file or ""),
      tostring(route.key_file or ""),
    }, "\0"))
  end
  table.sort(routes)
  local values = {
    tostring(config.issuer or ""),
    tostring(config.internal_origin or ""),
    tostring(config.discovery_url or ""),
    tostring(config.jwks_url or ""),
    tostring(config.par_url or ""),
    tostring(config.token_url or ""),
    tostring(config.revocation_url or ""),
    tostring(config.metadata_certificate_file or ""),
    tostring(config.metadata_key_file or ""),
    tostring(config.evidence_correlation_enabled == true),
    table.concat(routes, "\1"),
  }
  return sha256(table.concat(values, "\0"))
end

local function get_shared_context()
  -- PDK context access is request-phase only; metadata lookups can also originate
  -- in workers, timers, or light threads. Treat those as context-free metadata.
  local ok, context = pcall(function()
    if type(kong) == "table" and type(kong.ctx) == "table"
      and type(kong.ctx.shared) == "table" then
      return kong.ctx.shared.fapi_as_transport
    end
    return nil
  end)
  return ok and context or nil
end

local function context_is_valid(context)
  if type(context) ~= "table" or context.ready ~= true
    or type(state.registry) ~= "table" or state.registry_ready ~= true
    or state.failed or context.registry_epoch ~= state.registry_epoch then
    return nil
  end
  local identity = state.registry.routes[context.trusted_route_identity]
  if not identity or identity.client_id ~= context.client_id
    or identity.logical_route ~= context.logical_route then
    return nil
  end
  return identity
end

local function set_bridge_loaded()
  mark_bridge_loaded()
end

local function set_bridge_status(ready, epoch)
  return mark_bridge_status(ready, epoch)
end

local function current_registry_epoch()
  if state.registry_ready and not state.failed then
    return state.registry_epoch
  end
  return nil
end

local function route_manifest_matches(route_id, client_id, logical_route, epoch)
  if not state.registry_ready or state.failed or epoch ~= state.registry_epoch then
    return false
  end
  local route = state.registry and state.registry.routes[route_id]
  return route ~= nil and route.client_id == client_id
    and route.logical_route == logical_route
end

local function route_certificate_matches(route_id, path)
  if not state.registry_ready or state.failed then
    return false
  end
  local route = state.registry and state.registry.routes[route_id]
  if not route or path ~= route.certificate_file then
    return false
  end
  local cert_pem = read_limited(path, 262144)
  local cert = cert_pem and x509.new(cert_pem, "PEM")
  local fingerprint = cert and cert:digest("sha256")
  return type(fingerprint) == "string" and hex(fingerprint) == route.fingerprint
end

local function context_for_bridge()
  return get_shared_context()
end

local function set_header(headers, name, value)
  for key in pairs(headers) do
    if type(key) == "string" and key:lower() == name:lower() then
      headers[key] = nil
    end
  end
  if value ~= nil then
    headers[name] = value
  end
end

local function remove_named_header(headers, name)
  set_header(headers, name, nil)
end

local function url_origin(uri)
  if type(uri) ~= "string" then
    return nil, nil
  end
  local scheme, authority = uri:match("^([%a][%w+%.%-]*)://([^/?#]+)")
  if not scheme or not authority then
    return nil, nil
  end
  local hostport = authority:match(".*@(.+)$") or authority
  return scheme:lower(), hostport:lower()
end

local function protected_origin(uri)
  local scheme, authority = url_origin(uri)
  if authority == "localhost:8444" or authority == "keycloak:8443" then
    return true, scheme
  end
  return false, scheme
end

local function classify(uri, method)
  if method == "GET" and uri == DISCOVERY_PUBLIC then
    return "discovery", DISCOVERY_INTERNAL, "metadata"
  elseif method == "GET" and uri == DISCOVERY_INTERNAL then
    return "discovery", DISCOVERY_INTERNAL, "metadata"
  elseif method == "GET" and uri == JWKS then
    return "jwks", JWKS, "metadata"
  elseif method == "POST" and uri == PAR then
    return "par", PAR, "route"
  elseif method == "POST" and uri == TOKEN then
    return "token", TOKEN, "route"
  elseif method == "POST" and uri == REVOCATION then
    return "revocation", REVOCATION, "route"
  end
  return nil
end

local function decode_component(value)
  local output = {}
  local index = 1
  while index <= #value do
    local char = value:sub(index, index)
    if char == "+" then
      output[#output + 1] = " "
      index = index + 1
    elseif char == "%" then
      local pair = value:sub(index + 1, index + 2)
      if #pair ~= 2 or not pair:match("^[%x][%x]$") then
        return nil
      end
      output[#output + 1] = string.char(tonumber(pair, 16))
      index = index + 3
    else
      output[#output + 1] = char
      index = index + 1
    end
  end
  return table.concat(output)
end

local function parse_form(body)
  if type(body) ~= "string" or #body == 0 or #body > MAX_FORM_BYTES then
    return nil
  end
  local fields = {}
  local count = 0
  for pair in (body .. "&"):gmatch("(.-)&") do
    count = count + 1
    if count > MAX_FORM_FIELDS then
      return nil
    end
    local equals = pair:find("=", 1, true)
    if not equals then
      return nil
    end
    local name = decode_component(pair:sub(1, equals - 1))
    local value = decode_component(pair:sub(equals + 1))
    if not name or not value or name == "" or #name > MAX_FORM_NAME_BYTES
      or #value > MAX_FORM_VALUE_BYTES or fields[name] ~= nil
      or name:find("[%z\1-\31\127]") or value:find("[%z\1-\8\11\12\14-\31\127]") then
      return nil
    end
    fields[name] = value
  end
  return fields
end

local function form_digest(fields, excluded)
  local names = {}
  for name in pairs(fields) do
    if not (excluded and excluded[name]) then
      table.insert(names, name)
    end
  end
  table.sort(names)
  local canonical = {}
  for _, name in ipairs(names) do
    local value = fields[name]
    canonical[#canonical + 1] = #name .. ":" .. name .. #value .. ":" .. value
  end
  return sha256(table.concat(canonical, "\0"))
end

local function decode_base64url(value)
  if type(value) ~= "string" or value == "" or value:find("[^%w_%-]") then
    return nil
  end
  local padded = value:gsub("%-", "+"):gsub("_", "/")
  while #padded % 4 ~= 0 do
    padded = padded .. "="
  end
  return ngx.decode_base64(padded)
end

local function parse_jwt(assertion)
  if type(assertion) ~= "string" or #assertion > 16384 then
    return nil
  end
  local header_part, payload_part, signature = assertion:match("^([^.]+)%.([^.]+)%.([^.]+)$")
  if not header_part or not payload_part or signature == "" then
    return nil
  end
  local header_json = decode_base64url(header_part)
  local payload_json = decode_base64url(payload_part)
  if not header_json or not payload_json then
    return nil
  end
  local header = cjson.decode(header_json)
  local claims = cjson.decode(payload_json)
  if type(header) ~= "table" or type(claims) ~= "table" then
    return nil
  end
  return header, claims
end

local function assertion_summary(assertion, client_id, exact_ttl)
  local header, claims = parse_jwt(assertion)
  if not header or not claims then
    return nil
  end
  local now = ngx.time()
  local iat, exp = claims.iat, claims.exp
  if header.alg ~= "PS256" or claims.iss ~= client_id or claims.sub ~= client_id
    or claims.aud ~= ISSUER or type(claims.jti) ~= "string" or claims.jti == ""
    or type(iat) ~= "number" or iat % 1 ~= 0
    or type(exp) ~= "number" or exp % 1 ~= 0
    or exp <= iat or exp - iat > 60 or iat > now or now >= exp or exp - now < 5
    or (exact_ttl and exp - iat ~= 60) then
    return nil
  end
  return {
    alg = "PS256",
    aud_is_issuer = true,
    iss_sub_match = true,
    ttl_seconds = exp - iat,
    jti_present = true,
  }
end

local function content_type_is_form(headers)
  local value
  for key, candidate in pairs(headers) do
    if type(key) == "string" and key:lower() == "content-type" then
      value = candidate
      break
    end
  end
  if type(value) ~= "string" then
    return false
  end
  return value:lower():match("^%s*application/x%-www%-form%-urlencoded%s*;?%s*[%w%-_=%s]*$") ~= nil
end

local function urlencode(value)
  return (value:gsub("([^%w%-%._~])", function(char)
    return string.format("%%%02X", string.byte(char))
  end))
end

local function method_for(options)
  local method = type(options) == "table" and options.method or nil
  if method == nil then
    return "GET"
  end
  if type(method) ~= "string" then
    return nil
  end
  return method:upper()
end

local function headers_have_assertion(headers)
  for key in pairs(headers) do
    if type(key) == "string" then
      local lower = key:lower()
      if lower == "client_assertion" or lower == "client_assertion_type" then
        return true
      end
    end
  end
  return false
end

local function proxy_configured(self, options)
  local function has_proxy(value)
    return type(value) == "table"
      and (value.https_proxy ~= nil or value.http_proxy ~= nil)
  end
  return has_proxy(self and self.proxy_opts) or has_proxy(options and options.proxy_opts)
end

local function append_observation(context, entry)
  if type(context) ~= "table" or not state.registry
    or state.registry.config.evidence_correlation_enabled ~= true then
    return nil
  end
  context.observations = type(context.observations) == "table" and context.observations or {}
  if #context.observations >= MAX_OBSERVATIONS then
    context.observations_truncated = true
    return nil
  end
  table.insert(context.observations, entry)
  return entry
end

local function record_not_sent(context, endpoint_kind, method, reason)
  append_observation(context, {
    logical_route = context and context.logical_route or nil,
    endpoint_kind = endpoint_kind or "unknown",
    method = method,
    result = "not_sent",
    not_sent = true,
    rejection_layer = "transport_guard",
    reason_code = reason,
  })
end

local function observation_id()
  local bytes = random.bytes(16, true)
  if type(bytes) ~= "string" or #bytes ~= 16 then
    return nil
  end
  return hex(bytes)
end

local function set_mtls_options(self, options, identity, route_name, endpoint_kind)
  if options.path ~= nil or options.query ~= nil
    or (options.ssl_verify ~= nil and options.ssl_verify ~= true)
    or (options.ssl_server_name ~= nil and options.ssl_server_name ~= "keycloak")
    or options.ssl_session ~= nil
    or proxy_configured(self, options) then
    return false, nil
  end
  if not stock_identity_matches(options, identity) then
    return false, nil
  end

  local headers = copy_table(options.headers)
  remove_named_header(headers, "Host")
  remove_named_header(headers, CORRELATION_HEADER)
  if headers_have_assertion(headers) then
    return false, nil
  end
  set_header(headers, "Host", "keycloak:8443")

  local evidence_enabled = state.registry.config.evidence_correlation_enabled
  local id
  if evidence_enabled then
    id = observation_id()
    if not id then
      return false, nil
    end
    set_header(headers, CORRELATION_HEADER, id)
  end

  local pool = table.concat({
    "fapi-as-mtls-transport",
    route_name,
    state.registry_epoch,
    identity.fingerprint,
  }, ":")
  options.headers = headers
  options.ssl_client_cert = identity.certificate_cdata
  options.ssl_client_priv_key = identity.key_cdata
  options.ssl_verify = true
  options.ssl_server_name = "keycloak"
  options.ssl_reused_session = false
  options.keepalive = false
  options.pool = pool
  options.proxy_opts = nil
  options.follow_redirects = false

  return true, id
end

local function operation_key(context, endpoint_kind, grant_type, digest)
  -- PAR and each token grant type are single-send per request context, regardless
  -- of incidental form-field changes. Revocation is token-specific and excludes
  -- token_type_hint from its digest.
  return table.concat({
    context.logical_route,
    endpoint_kind,
    grant_type or "",
    endpoint_kind == "revocation" and digest or "single-send",
  }, "\0")
end

local function validate_form_for_operation(context, identity, endpoint, fields)
  local route = identity
  if fields.client_id ~= nil and fields.client_id ~= route.client_id then
    return false
  end
  local has_assertion = fields.client_assertion ~= nil
    or fields.client_assertion_type ~= nil
  if route.logical_route == "A" and has_assertion then
    return false
  end
  if endpoint.kind == "token" then
    if fields.client_id ~= route.client_id then
      return false
    end
    if fields.grant_type ~= "authorization_code" and fields.grant_type ~= "refresh_token" then
      return false
    end
    return true, nil
  elseif route.logical_route == "A" then
    if fields.client_id ~= route.client_id then
      return false
    end
    return true, nil
  elseif endpoint.kind == "par" or endpoint.kind == "revocation" then
    if fields.client_assertion_type ~= ASSERTION_TYPE or not fields.client_assertion then
      return false
    end
    local summary = assertion_summary(fields.client_assertion, route.client_id, false)
    if not summary then
      return false
    end
    if endpoint.kind == "revocation" and (type(fields.token) ~= "string" or fields.token == "") then
      return false
    end
    return true, summary
  end
  return false
end

local function operation_digest(context, endpoint, fields)
  if endpoint.kind == "revocation" then
    local token_digest = sha256(fields.token or "")
    if not token_digest then
      return nil
    end
    return sha256(context.client_id .. "\0" .. token_digest)
  end
  return form_digest(fields, {
    client_assertion = true,
    client_assertion_type = true,
  })
end

local function invoke_signer(context, identity)
  local current_epoch = state.registry_epoch
  if type(context.sign_assertion) ~= "function"
    or context.signer_epoch ~= current_epoch
    or context.registry_epoch ~= current_epoch
    or context.client_id ~= identity.client_id
    or context.logical_route ~= "B" then
    return nil
  end
  local ok, assertion, assertion_type = pcall(context.sign_assertion)
  if not ok or type(assertion) ~= "string"
    or assertion_type ~= ASSERTION_TYPE then
    return nil
  end
  local summary = assertion_summary(assertion, identity.client_id, true)
  if not summary then
    return nil
  end
  return assertion, assertion_type, summary
end

local function prepare_post(context, identity, endpoint, options, headers)
  if not content_type_is_form(headers) then
    return nil
  end
  local body = options.body
  if type(body) ~= "string" then
    return nil
  end
  local content_length
  for key, value in pairs(headers) do
    if type(key) == "string" and key:lower() == "content-length" then
      if content_length ~= nil then
        return nil
      end
      content_length = value
    end
  end
  if content_length ~= nil and tostring(content_length) ~= tostring(#body) then
    return nil
  end

  local fields = parse_form(body)
  if not fields then
    return nil
  end
  if endpoint.kind == "token" and context.logical_route == "B"
    and (fields.client_assertion or fields.client_assertion_type) then
    return nil
  end

  local valid, summary = validate_form_for_operation(context, identity, endpoint, fields)
  if not valid then
    return nil
  end

  local digest = operation_digest(context, endpoint, fields)
  if not digest then
    return nil
  end
  local grant_type = endpoint.kind == "token" and fields.grant_type or nil
  local replay_key = operation_key(context, endpoint.kind, grant_type, digest)
  context.sent_operations = type(context.sent_operations) == "table" and context.sent_operations or {}
  context.operation_digests = type(context.operation_digests) == "table"
    and context.operation_digests or {}
  if context.sent_operations[replay_key] then
    return nil
  end

  return {
    body = body,
    fields = fields,
    replay_key = replay_key,
    digest = digest,
    grant_type = grant_type,
    assertion_summary = summary,
  }
end

local function generic_error()
  return nil, "FAPI AS transport unavailable"
end

local function reject(context, endpoint_kind, method, reason)
  record_not_sent(context, endpoint_kind, method, reason)
  return generic_error()
end

local function wrap_request_uri(self, uri, options)
  options = type(options) == "table" and options or {}
  local context = get_shared_context()
  local method = method_for(options)
  if not method then
    if context or protected_origin(uri) then
      return reject(context, "unknown", nil, "invalid_method")
    end
    return state.original_request_uri(self, uri, options)
  end

  local endpoint_kind, mapped_uri, identity_kind = classify(uri, method)
  local is_as_origin, scheme = protected_origin(uri)
  if not endpoint_kind then
    if is_as_origin or (context and (context.ready or context.logical_route)) then
      return reject(context, "unknown", method, is_as_origin and "unknown_as_endpoint" or "context_external_url")
    end
    return state.original_request_uri(self, uri, options)
  end
  if not state.registry_ready or state.failed or not state.wrapper_ready then
    return reject(context, endpoint_kind, method, "registry_not_ready")
  end
  if not ready_marker_covers_worker() then
    return reject(context, endpoint_kind, method, "bootstrap_marker_missing_or_stale")
  end
  if scheme ~= "https" then
    return reject(context, endpoint_kind, method, "http_blocked")
  end

  local identity
  local route_name
  if identity_kind == "metadata" then
    identity = state.registry.metadata_identity
    route_name = "metadata"
    if method ~= "GET" or options.body ~= nil then
      return reject(context, endpoint_kind, method, "invalid_metadata_request")
    end
    if context and (context.ready or context.logical_route) and not context_is_valid(context) then
      return reject(context, endpoint_kind, method, "stale_context")
    end
  else
    identity = context_is_valid(context)
    if not identity then
      return reject(context, endpoint_kind, method, "missing_or_stale_route_context")
    end
    route_name = context.logical_route
  end

  local params = copy_table(options)
  params.headers = copy_table(options.headers)
  local options_ok, correlation_id = set_mtls_options(
    self, params, identity, route_name, endpoint_kind
  )
  if not options_ok then
    return reject(context, endpoint_kind, method, "transport_options_rejected")
  end
  params.path = nil
  params.query = nil

  local request_observation = {
    request_id = correlation_id,
    logical_route = context and context.logical_route or nil,
    endpoint_kind = endpoint_kind,
    method = method,
    identity_kind = identity_kind == "metadata" and "metadata" or ("route_" .. route_name),
    oauth_auth_method = identity_kind == "metadata" and "none"
      or (route_name == "A" and "tls_client_auth"
        or (endpoint_kind == "token" and "private_key_jwt" or "private_key_jwt")),
    result = "not_sent",
    sent = false,
    not_sent = true,
  }

  local prepared
  if identity_kind == "route" then
    if not content_type_is_form(params.headers) then
      return reject(context, endpoint_kind, method, "invalid_form_content_type")
    end
    prepared = prepare_post(context, identity, { kind = endpoint_kind }, params, params.headers)
    if not prepared then
      request_observation.rejection_layer = "transport_guard"
      request_observation.reason_code = "invalid_or_duplicate_post"
      append_observation(context, request_observation)
      return generic_error()
    end
    -- The digest is fixed before a signer is called or a network operation can yield.
    context.sent_operations[prepared.replay_key] = true
    context.operation_digests[prepared.replay_key] = prepared.digest
    request_observation.grant_type = prepared.grant_type
    request_observation.claim_summary = prepared.assertion_summary
    if endpoint_kind == "revocation" then
      request_observation.token_kind = prepared.fields.token_type_hint or "unspecified"
    end
  end

  if state.registry.config.evidence_correlation_enabled and not correlation_id then
    return reject(context, endpoint_kind, method, "observation_id_unavailable")
  end
  if correlation_id then
    request_observation.request_id = correlation_id
    if context then
      context.observation_id = correlation_id
    end
  end
  append_observation(context, request_observation)

  if endpoint_kind == "token" and route_name == "B" then
    local assertion, assertion_type, summary = invoke_signer(context, identity)
    if not assertion then
      request_observation.result = "not_sent"
      request_observation.not_sent = true
      request_observation.rejection_layer = "signer"
      request_observation.reason_code = "signer_unavailable"
      return generic_error()
    end
    params.body = prepared.body .. "&client_assertion=" .. urlencode(assertion)
      .. "&client_assertion_type=" .. urlencode(assertion_type)
    set_header(params.headers, "Content-Length", tostring(#params.body))
    request_observation.claim_summary = summary
    request_observation.oauth_auth_method = "private_key_jwt"
  end

  request_observation.sent = true
  request_observation.not_sent = false
  local call_ok, response = pcall(state.original_request_uri, self, mapped_uri, params)
  if not call_ok or not response then
    request_observation.result = "network_error"
    request_observation.not_sent = false
    request_observation.rejection_layer = "network"
    return generic_error()
  end
  if type(response.status) == "number" and response.status >= 300 and response.status < 400 then
    request_observation.result = "redirect_rejected"
    request_observation.not_sent = false
    request_observation.rejection_layer = "transport_redirect"
    request_observation.http_status = response.status
    return generic_error()
  end
  request_observation.result = "response_received"
  request_observation.not_sent = false
  request_observation.http_status = response.status
  return response
end

local function install_wrapper()
  if type(http) ~= "table" or type(http.request_uri) ~= "function" then
    return false
  end
  if http.__fapi_as_transport_wrapped then
    return false
  end
  state.original_request_uri = http.request_uri
  local wrapper = function(self, uri, options)
    return wrap_request_uri(self, uri, options)
  end
  http.__fapi_as_transport_wrapped = true
  http.__fapi_as_transport_original = state.original_request_uri
  http.request_uri = wrapper
  state.wrapped_request_uri = wrapper
  state.wrapper_ready = http.request_uri == wrapper
  return state.wrapper_ready
end

local function resolved_route_id()
  if type(kong) ~= "table" or type(kong.router) ~= "table"
    or type(kong.router.get_route) ~= "function" then
    return nil
  end
  local route = kong.router.get_route()
  return type(route) == "table" and route.id or nil
end

local Transport = {
  PRIORITY = 1100,
  VERSION = "0.2.0",
}

function Transport:init_worker()
  ensure_worker_identity(true)
  remove_ready_marker()
  state.worker_initialized = true
  refresh_registry_epoch()
  if state.registry then
    state.registry_ready = state.status_config_valid ~= false and not state.failed
  end
  if not install_wrapper() then
    state.failed = true
    state.registry_ready = false
  end
  write_status()
  refresh_bridge_status()
end

function Transport:configure(configs)
  configure(configs)
end

function Transport:access()
  local route_id = resolved_route_id()
  local reserved = MANIFEST[route_id]
  local route = state.registry and state.registry.routes[route_id]
  local shared
  pcall(function()
    shared = type(kong) == "table" and kong.ctx and kong.ctx.shared
  end)
  if type(shared) ~= "table" then
    if reserved then
      return kong.response.exit(503, { error = "client_authentication_unavailable" })
    end
    return
  end
  if not reserved then
    shared.fapi_as_transport = nil
    return
  end
  if not route or not state.registry_ready or state.failed or not state.wrapper_ready
    or state.status_export_failed == true or not ready_marker_covers_worker() then
    shared.fapi_as_transport = nil
    return kong.response.exit(503, { error = "client_authentication_unavailable" })
  end
  shared.fapi_as_transport = {
    ready = true,
    registry_epoch = state.registry_epoch,
    logical_route = route.logical_route,
    client_id = route.client_id,
    trusted_route_identity = route_id,
    certificate_fingerprint = route.fingerprint,
    sent_operations = {},
    observations = {},
  }
end

function Transport.status_snapshot()
  return status_snapshot()
end

function Transport.current_registry_epoch()
  return current_registry_epoch()
end

function Transport.runtime_gate_ready()
  return ready_marker_covers_worker()
end

function Transport.context_for_bridge()
  return context_for_bridge()
end

function Transport.mark_bridge_loaded()
  set_bridge_loaded()
end

function Transport.mark_bridge_status(ready, epoch)
  return set_bridge_status(ready, epoch)
end

function Transport.route_identity_matches(context, client_id, logical_route)
  local route = context_is_valid(context)
  return route ~= nil and route.client_id == client_id
    and route.logical_route == logical_route
end

function Transport.route_manifest_matches(route_id, client_id, logical_route, epoch)
  return route_manifest_matches(route_id, client_id, logical_route, epoch)
end

function Transport.route_certificate_matches(route_id, path)
  return route_certificate_matches(route_id, path)
end

return Transport
