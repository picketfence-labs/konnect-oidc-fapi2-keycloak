#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED="$ROOT/.generated"
PKI="$GENERATED/pki"
SECRETS="$GENERATED/secrets.env"

umask 077
mkdir -p "$PKI" "$GENERATED/keycloak"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

if [[ ! -f "$PKI/ca.key" ]]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 30 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -subj "/CN=FAPI demo development CA" \
    -keyout "$PKI/ca.key" -out "$PKI/ca.crt"
fi

issue_certificate() {
  local name="$1"
  local subject="$2"
  local usage="$3"
  local alt_names="${4:-}"
  local extension="$PKI/$name.ext"

  if [[ -f "$PKI/$name.crt" && -f "$PKI/$name.key" ]]; then
    return
  fi

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$PKI/$name.key"
  openssl req -new -key "$PKI/$name.key" -subj "/CN=$subject" -out "$PKI/$name.csr"
  {
    printf '%s\n' "basicConstraints=critical,CA:FALSE"
    printf '%s\n' "keyUsage=critical,digitalSignature,keyEncipherment"
    printf '%s\n' "extendedKeyUsage=$usage"
    if [[ -n "$alt_names" ]]; then
      printf '%s\n' "subjectAltName=$alt_names"
    fi
  } > "$extension"
  openssl x509 -req -in "$PKI/$name.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
    -CAcreateserial -days 30 -sha256 -extfile "$extension" -out "$PKI/$name.crt"
  rm -f "$PKI/$name.csr" "$extension"
}

issue_certificate keycloak keycloak serverAuth "DNS:keycloak,DNS:localhost,IP:127.0.0.1"
issue_certificate kong-proxy localhost serverAuth "DNS:localhost,IP:127.0.0.1"
issue_certificate ui localhost serverAuth "DNS:localhost,IP:127.0.0.1"
issue_certificate pop-verifier pop-verifier serverAuth "DNS:pop-verifier,DNS:localhost,IP:127.0.0.1"
issue_certificate route-a kong-fapi-mtls clientAuth
issue_certificate route-b kong-fapi-pkj-mtls clientAuth

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
  "$GENERATED/keycloak/route-b-private.jwk" \
  "$PKI" \
  "$GENERATED/runtime.env"

cat > "$GENERATED/demo-users.txt" <<EOF
sales.user@fapi-demo.invalid $SALES_PASSWORD
engineering.user@fapi-demo.invalid $ENGINEERING_PASSWORD
EOF

chmod 600 "$GENERATED/deck.env" "$GENERATED/runtime.env" "$GENERATED/demo-users.txt"
echo "Generated development PKI, Keycloak realm, and credentials under .generated/."
echo "Run 'sed -n 1,2p .generated/demo-users.txt' to display the demo credentials explicitly."
