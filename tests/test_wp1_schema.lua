local null = {}
ngx = { null = null }
local schema = dofile("kong/plugins/fapi-as-mtls-transport/schema.lua")
local bridge = dofile("kong/plugins/fapi-client-auth-bridge/schema.lua")

local function field(fields, name)
  for _, item in ipairs(fields) do
    if item[name] then
      return item[name]
    end
  end
  return nil
end

assert(schema.name == "fapi-as-mtls-transport")
local protocols = field(schema.fields, "protocols")
assert(protocols.type == "set")
assert(protocols.required == true)
assert(protocols.default[1] == "http" and protocols.default[2] == "https")
for _, scope in ipairs({ "consumer", "service", "route" }) do
  local constraint = field(schema.fields, scope)
  assert(constraint.type == "foreign" and constraint.eq == null)
end

local config = field(schema.fields, "config")
assert(type(config.custom_validator) == "function")
local valid = {
  {
    route_id = "754519ff-b0b9-5ed5-94c0-e453d260c6c4",
    logical_route = "A",
    client_id = "third-party-fapi-mtls",
    certificate_file = "/etc/kong/fapi/route-a.crt",
    key_file = "/etc/kong/fapi/route-a.key",
  },
  {
    route_id = "0f45debe-a3a6-5207-aea3-637227fb96f2",
    logical_route = "B",
    client_id = "third-party-fapi-pkj-mtls",
    certificate_file = "/etc/kong/fapi/route-b.crt",
    key_file = "/etc/kong/fapi/route-b.key",
  },
}
assert(config.custom_validator({ routes = valid }) == true)

local swapped = { valid[1], valid[2] }
swapped[1] = {
  route_id = valid[1].route_id,
  logical_route = valid[1].logical_route,
  client_id = valid[2].client_id,
  certificate_file = valid[1].certificate_file,
  key_file = valid[1].key_file,
}
assert(config.custom_validator({ routes = swapped }) == nil)
assert(config.custom_validator({ routes = { valid[1], valid[1] } }) == nil)
local unexpected = {
  route_id = valid[1].route_id,
  logical_route = "A",
  client_id = valid[1].client_id,
  certificate_file = valid[1].certificate_file,
  key_file = valid[1].key_file,
  extra = "forbidden",
}
assert(config.custom_validator({ routes = { unexpected, valid[2] } }) == nil)
assert(config.custom_validator({ routes = { valid[1] } }) == nil)
assert(config.custom_validator({}) == nil)
assert(config.custom_validator(nil) == nil)
assert(config.custom_validator({ routes = "not-an-array" }) == nil)
assert(config.custom_validator({ routes = {} }) == nil)
local no_id = {
  logical_route = "A",
  client_id = valid[1].client_id,
  certificate_file = valid[1].certificate_file,
  key_file = valid[1].key_file,
}
local no_id_ok, no_id_error = config.custom_validator({ routes = { no_id, valid[2] } })
assert(no_id_ok == nil and type(no_id_error) == "string")

local bridge_config = field(bridge.fields, "config")
local delivery = field(bridge_config.fields, "assertion_delivery")
assert(delivery.type == "string" and delivery.default == "header")
assert(delivery.one_of[1] == "header" and delivery.one_of[2] == "transport_delegate")

print("WP1 schema checks: PASS")
