#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED="$ROOT/.generated"
PKI="$GENERATED/pki"
SECRETS="$GENERATED/secrets.env"

umask 077
mkdir -p "$PKI" "$GENERATED/keycloak"

python3 "$ROOT/scripts/generate-pki.py" "$PKI"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

if [[ ! -f "$PKI/route-b-pkj.key" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$PKI/route-b-pkj.key"
  openssl pkey -in "$PKI/route-b-pkj.key" -pubout -out "$PKI/route-b-pkj.pub"
fi

python3 "$ROOT/scripts/export-rsa-jwk.py" \
  "$PKI/route-b-pkj.key" \
  "$GENERATED/keycloak/route-b-private.jwk" \
  "$GENERATED/keycloak/route-b-jwk.env"

if [[ ! -f "$SECRETS" ]]; then
  {
    printf 'KEYCLOAK_ADMIN_USERNAME=admin\n'
    printf 'KEYCLOAK_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'SALES_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'ENGINEERING_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'DECK_ROUTE_A_SESSION_SECRET=%s\n' "$(openssl rand -hex 32)"
    printf 'DECK_ROUTE_B_SESSION_SECRET=%s\n' "$(openssl rand -hex 32)"
    printf 'DECK_ROUTE_A_CACHE_SALT=%s\n' "$(openssl rand -hex 32)"
    printf 'DECK_ROUTE_B_CACHE_SALT=%s\n' "$(openssl rand -hex 32)"
  } > "$SECRETS"
fi

set -a
# shellcheck disable=SC1090
source "$SECRETS"
# shellcheck disable=SC1090
source "$GENERATED/keycloak/route-b-jwk.env"
set +a

python3 "$ROOT/scripts/render-keycloak-realm.py" \
  "$ROOT/keycloak/realm-template.json" \
  "$GENERATED/keycloak/realm.json" \
  "$PKI/route-b-pkj.pub"

cat > "$GENERATED/deck.env" <<EOF
KONNECT_CONTROL_PLANE_NAME=${TF_VAR_control_plane_name:-keycloak-fapi2-demo}
DECK_ROUTE_B_JWK_KID=$DECK_ROUTE_B_JWK_KID
DECK_ROUTE_A_SESSION_SECRET=$DECK_ROUTE_A_SESSION_SECRET
DECK_ROUTE_B_SESSION_SECRET=$DECK_ROUTE_B_SESSION_SECRET
DECK_ROUTE_A_CACHE_SALT=$DECK_ROUTE_A_CACHE_SALT
DECK_ROUTE_B_CACHE_SALT=$DECK_ROUTE_B_CACHE_SALT
DECK_ROUTE_B_JWK_N=$DECK_ROUTE_B_JWK_N
DECK_ROUTE_B_JWK_E=$DECK_ROUTE_B_JWK_E
EOF

python3 "$ROOT/scripts/render-runtime-secrets.py" \
  "$SECRETS" \
  "$PKI" \
  "$GENERATED"

cat > "$GENERATED/demo-users.txt" <<EOF
sales.user@fapi-demo.invalid $SALES_PASSWORD
engineering.user@fapi-demo.invalid $ENGINEERING_PASSWORD
EOF

chmod 600 "$GENERATED/deck.env" "$GENERATED/runtime.env" "$GENERATED/runtime-api.json" "$GENERATED/runtime-third-party.json" "$GENERATED/runtime-api.env" "$GENERATED/runtime-third-party.env" "$GENERATED/demo-users.txt"
echo "Generated development PKI, Keycloak realm, and credentials under .generated/."
echo "Run 'sed -n 1,2p .generated/demo-users.txt' to display the demo credentials explicitly."
