local function validate_routes(routes)
  if type(routes) ~= "table" or #routes ~= 2 then
    return nil, "exactly the fixed Route A and Route B entries are required"
  end

  local expected = {
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
  local seen = {}
  for _, route in ipairs(routes) do
    if type(route) ~= "table" or type(route.route_id) ~= "string" or route.route_id == "" then
      return nil, "Route record requires a non-empty route_id"
    end
    if seen[route.route_id] then
      return nil, "Route identities must be present exactly once"
    end
    seen[route.route_id] = true
    local identity = expected[route.route_id]
    if not identity then
      return nil, "route_id is not in the fixed manifest"
    end
    for key, value in pairs(identity) do
      if route[key] ~= value then
        return nil, "Route identity fields do not match the fixed manifest"
      end
    end
    local count = 0
    for key in pairs(route) do
      if key ~= "route_id" and key ~= "logical_route" and key ~= "client_id"
        and key ~= "certificate_file" and key ~= "key_file" then
        return nil, "Route record contains an unexpected field"
      end
      count = count + 1
    end
    if count ~= 5 then
      return nil, "each Route record must contain exactly five fields"
    end
  end
  if not seen["754519ff-b0b9-5ed5-94c0-e453d260c6c4"]
    or not seen["0f45debe-a3a6-5207-aea3-637227fb96f2"] then
    return nil, "both fixed Route identities are required"
  end
  return true
end

return {
  name = "fapi-as-mtls-transport",
  fields = {
    {
      protocols = {
        type = "set",
        required = true,
        default = { "http", "https" },
        elements = { type = "string", one_of = { "http", "https" } },
      },
    },
    { consumer = { type = "foreign", reference = "consumers", eq = ngx.null } },
    { service = { type = "foreign", reference = "services", eq = ngx.null } },
    { route = { type = "foreign", reference = "routes", eq = ngx.null } },
    {
      config = {
        type = "record",
        custom_validator = function(config)
          if type(config) ~= "table" then
            return nil, "transport configuration is required"
          end
          return validate_routes(config.routes)
        end,
        fields = {
          {
            issuer = {
              type = "string",
              required = true,
              one_of = { "https://localhost:8444/realms/fapi-demo" },
            },
          },
          {
            internal_origin = {
              type = "string",
              required = true,
              one_of = { "https://keycloak:8443" },
            },
          },
          {
            discovery_url = {
              type = "string",
              required = true,
              one_of = {
                "https://keycloak:8443/realms/fapi-demo/.well-known/openid-configuration",
              },
            },
          },
          {
            jwks_url = {
              type = "string",
              required = true,
              one_of = {
                "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/certs",
              },
            },
          },
          {
            par_url = {
              type = "string",
              required = true,
              one_of = {
                "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/ext/par/request",
              },
            },
          },
          {
            token_url = {
              type = "string",
              required = true,
              one_of = {
                "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token",
              },
            },
          },
          {
            revocation_url = {
              type = "string",
              required = true,
              one_of = {
                "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/revoke",
              },
            },
          },
          {
            metadata_certificate_file = {
              type = "string",
              required = true,
              one_of = { "/etc/kong/fapi/third-party-metadata.crt" },
            },
          },
          {
            metadata_key_file = {
              type = "string",
              required = true,
              one_of = { "/etc/kong/fapi/third-party-metadata.key" },
            },
          },
          {
            routes = {
              type = "array",
              required = true,
              len_min = 2,
              len_max = 2,
              elements = {
                type = "record",
                fields = {
                  {
                    route_id = {
                      type = "string",
                      required = true,
                      one_of = {
                        "754519ff-b0b9-5ed5-94c0-e453d260c6c4",
                        "0f45debe-a3a6-5207-aea3-637227fb96f2",
                      },
                    },
                  },
                  {
                    logical_route = {
                      type = "string",
                      required = true,
                      one_of = { "A", "B" },
                    },
                  },
                  {
                    client_id = {
                      type = "string",
                      required = true,
                      one_of = {
                        "third-party-fapi-mtls",
                        "third-party-fapi-pkj-mtls",
                      },
                    },
                  },
                  {
                    certificate_file = {
                      type = "string",
                      required = true,
                      one_of = {
                        "/etc/kong/fapi/route-a.crt",
                        "/etc/kong/fapi/route-b.crt",
                      },
                    },
                  },
                  {
                    key_file = {
                      type = "string",
                      required = true,
                      one_of = {
                        "/etc/kong/fapi/route-a.key",
                        "/etc/kong/fapi/route-b.key",
                      },
                    },
                  },
                },
              },
            },
          },
          {
            evidence_correlation_enabled = {
              type = "boolean",
              default = false,
            },
          },
        },
      },
    },
  },
}
