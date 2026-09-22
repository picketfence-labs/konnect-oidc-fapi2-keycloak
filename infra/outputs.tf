output "control_plane_id" {
  value = konnect_gateway_control_plane.demo.id
}

output "control_plane_name" {
  value = konnect_gateway_control_plane.demo.name
}

output "control_plane_endpoint" {
  value = konnect_gateway_control_plane.demo.config.control_plane_endpoint
}

output "telemetry_endpoint" {
  value = konnect_gateway_control_plane.demo.config.telemetry_endpoint
}

output "auth0_issuer" {
  value = "https://${var.auth0_domain}/"
}

output "auth0_client_id" {
  value = auth0_client.gateway.client_id
}

output "auth0_client_secret" {
  value     = auth0_client_credentials.gateway.client_secret
  sensitive = true
}

output "auth0_audience" {
  value = auth0_resource_server.demo.identifier
}

output "department_claim" {
  value = "${var.claim_namespace}/department"
}

output "route_claim" {
  value = "${var.claim_namespace}/route"
}

output "session_secret" {
  value     = random_password.session.result
  sensitive = true
}

output "par_enabled" {
  value = var.enable_par
}

output "demo_users" {
  sensitive = true
  value = {
    sales = {
      email      = auth0_user.sales.email
      password   = random_password.sales.result
      department = "sales"
    }
    engineering = {
      email      = auth0_user.engineering.email
      password   = random_password.engineering.result
      department = "engineering"
    }
  }
}
