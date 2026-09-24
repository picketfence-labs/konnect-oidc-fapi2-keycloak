return {
  name = "fapi-client-auth-bridge",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          { issuer = { type = "string", required = true } },
          { discovery_endpoint = { type = "string", required = true } },
          { client_id = { type = "string", required = true } },
          { private_key_file = { type = "string", required = true } },
          { tls_certificate_file = { type = "string", required = true } },
          { key_id = { type = "string", required = true } },
          {
            assertion_ttl = {
              type = "integer",
              default = 60,
              between = { 1, 60 },
            },
          },
          {
            discovery_timeout = {
              type = "integer",
              default = 3000,
              between = { 100, 10000 },
            },
          },
          {
            discovery_cache_ttl = {
              type = "integer",
              default = 300,
              between = { 1, 3600 },
            },
          },
        },
      },
    },
  },
}
