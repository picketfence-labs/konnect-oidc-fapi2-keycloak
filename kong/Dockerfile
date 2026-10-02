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
USER kong

ENV KONG_PLUGINS=bundled,fapi-client-auth-bridge
