resource "auth0_resource_server" "demo" {
  name        = "OIDC OIDC Demo API"
  identifier  = "https://oidc-demo.example.com/api"
  signing_alg = "RS256"
}

resource "auth0_client" "gateway" {
  name                                  = "OIDC Kong Gateway OIDC Demo"
  description                           = "Managed by Terraform; browser authorization-code client for Kong Gateway"
  app_type                              = "regular_web"
  is_first_party                        = true
  oidc_conformant                       = true
  callbacks                             = [var.gateway_callback_url]
  allowed_logout_urls                   = [var.ui_url]
  web_origins                           = [var.ui_url]
  grant_types                           = ["authorization_code", "refresh_token"]
  require_pushed_authorization_requests = var.enable_par

  # Kong verifies ID tokens with Auth0's JWKS; sign them asymmetrically.
  jwt_configuration {
    alg = "RS256"
  }
}

resource "auth0_client_credentials" "gateway" {
  client_id = auth0_client.gateway.id

  # Retained from Gateway 3.15 troubleshooting and verified with browser login on 3.16.
  # Reconsider client_secret_post only during a new requirements review; keep Auth0 and Kong
  # aligned. See docs/session-handoff.md.
  authentication_method = "client_secret_basic"
}

resource "auth0_connection" "demo" {
  name     = "oidc-routing-demo-users"
  strategy = "auth0"

  options {
    password_policy        = "good"
    brute_force_protection = true
    strategy_version       = 2
    disable_signup         = true
    requires_username      = false
  }
}

resource "auth0_connection_clients" "demo" {
  connection_id   = auth0_connection.demo.id
  enabled_clients = [auth0_client.gateway.id, var.auth0_management_client_id]
}

# Auth0 auto-enables this tenant default connection for every new regular_web client. Universal
# Login then offers it alongside oidc-routing-demo-users, and demo users fail with "Wrong email or
# password" because they only exist in oidc-routing-demo-users. Remove the gateway client from it
# without disturbing the tenant's other pre-existing apps.
#
# The auth0_connection data source's enabled_clients attribute under-reports this connection (it
# omitted the gateway client entirely against the live GET /connections/{id}/clients result), so
# the other clients are pinned explicitly here instead of derived from that attribute. See
# docs/troubleshooting-log.md.
data "auth0_connection" "default_db" {
  name = "Username-Password-Authentication"
}

resource "auth0_connection_clients" "default_db" {
  connection_id   = data.auth0_connection.default_db.id
  enabled_clients = var.default_db_existing_client_ids
}

resource "random_password" "sales" {
  length  = 24
  special = true
}

resource "random_password" "engineering" {
  length  = 24
  special = true
}

resource "random_password" "session" {
  length  = 64
  special = false
}

resource "auth0_user" "sales" {
  depends_on = [auth0_connection_clients.demo]

  connection_name = auth0_connection.demo.name
  email           = "sales.user@oidc-demo.invalid"
  email_verified  = true
  password        = random_password.sales.result
  app_metadata    = jsonencode({ department = "sales" })
}

resource "auth0_user" "engineering" {
  depends_on = [auth0_connection_clients.demo]

  connection_name = auth0_connection.demo.name
  email           = "engineering.user@oidc-demo.invalid"
  email_verified  = true
  password        = random_password.engineering.result
  app_metadata    = jsonencode({ department = "engineering" })
}

resource "auth0_action" "department_claim" {
  name    = "OIDC demo department claim"
  runtime = "node22"
  deploy  = true

  supported_triggers {
    id      = "post-login"
    version = "v3"
  }

  code = <<-JS
    exports.onExecutePostLogin = async (event, api) => {
      const namespace = "${var.claim_namespace}";
      const app = event.user.app_metadata || {};
      const user = event.user.user_metadata || {};
      const department = app.department || app.departement || user.department || user.departement;
      const route = ({ sales: "sales-route", engineering: "engineering-route" })[department] || "default-route";

      if (department) {
        api.idToken.setCustomClaim(`$${namespace}/department`, department);
        api.accessToken.setCustomClaim(`$${namespace}/department`, department);
        api.idToken.setCustomClaim(`$${namespace}/route`, route);
        api.accessToken.setCustomClaim(`$${namespace}/route`, route);
      }
    };
  JS
}

# Additive binding avoids taking ownership of every existing post-login Action in the tenant.
resource "auth0_trigger_action" "department_claim" {
  trigger   = "post-login"
  action_id = auth0_action.department_claim.id
}
