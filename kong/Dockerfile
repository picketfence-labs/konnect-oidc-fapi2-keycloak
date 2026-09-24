FROM kong/kong-gateway:3.16.0.0

USER root
COPY --chown=kong:0 plugins/fapi-client-auth-bridge \
  /usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge
USER kong

ENV KONG_PLUGINS=bundled,fapi-client-auth-bridge
