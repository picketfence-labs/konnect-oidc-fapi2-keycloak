#!/bin/sh
set -eu

gateway_ip="$(awk '$2 == "as-host-gateway" { print $1; exit }' /etc/hosts)"
case "$gateway_ip" in
  ''|*[!0-9.]* ) exit 70 ;;
esac
printf '%s localhost\n' "$gateway_ip" > /tmp/wp5-stock-hosts
chmod 0600 /tmp/wp5-stock-hosts
export KONG_DNS_HOSTSFILE=/tmp/wp5-stock-hosts
exec /entrypoint.sh kong docker-start
