FROM kong/kong-gateway:3.16.0.0@sha256:e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4

USER root
# Patch Ubuntu TLS packages while retaining the reviewed Kong release. The
# Ubuntu base includes Pebble, but Kong's entrypoint starts OpenResty directly.
# This image does not use that process supervisor.
RUN apt-get update \
  && apt-get install --yes --no-install-recommends --only-upgrade \
    libssl3t64 openssl openssl-provider-legacy \
  && rm -f /usr/bin/pebble \
  && rm -rf /var/lib/apt/lists/*
COPY --chown=kong:0 plugins/fapi-client-auth-bridge \
  /usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge
COPY --chown=kong:0 plugins/fapi-as-mtls-transport \
  /usr/local/share/lua/5.1/kong/plugins/fapi-as-mtls-transport

# Catch an accidentally incomplete build before this image can be used by a
# Data Plane. The runtime gate separately checks that the selected image has
# both plugin trees before permitting a demo entrypoint.
RUN test -s /usr/local/share/lua/5.1/kong/plugins/fapi-as-mtls-transport/handler.lua \
  && test -s /usr/local/share/lua/5.1/kong/plugins/fapi-as-mtls-transport/schema.lua \
  && test -s /usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge/handler.lua \
  && test -s /usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge/schema.lua \
  && install -d -m 0700 -o kong -g 0 /run/kong/fapi-transport-ready
USER kong

ENV KONG_PLUGINS=bundled,fapi-as-mtls-transport,fapi-client-auth-bridge
