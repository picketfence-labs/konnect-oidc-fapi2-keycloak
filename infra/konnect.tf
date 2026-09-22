resource "konnect_gateway_control_plane" "demo" {
  name         = var.control_plane_name
  description  = "Auth0 OIDC claim-to-header and identity-aware routing demo for OIDC"
  cluster_type = "CLUSTER_TYPE_CONTROL_PLANE"
  auth_type    = "pinned_client_certs"

  labels = {
    owner   = "picketfence-labs"
    purpose = "oidc-routing-demo"
  }

  proxy_urls = [{
    host     = "localhost"
    port     = 8000
    protocol = "http"
  }]
}

resource "tls_private_key" "dp" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_self_signed_cert" "dp" {
  private_key_pem       = tls_private_key.dp.private_key_pem
  validity_period_hours = 720
  early_renewal_hours   = 72
  is_ca_certificate     = false

  subject {
    common_name  = "${var.control_plane_name}-local-dp"
    organization = "Picketfence Labs demo"
  }

  allowed_uses = ["client_auth", "digital_signature", "key_encipherment"]
}

resource "konnect_gateway_data_plane_client_certificate" "dp" {
  control_plane_id = konnect_gateway_control_plane.demo.id
  cert             = tls_self_signed_cert.dp.cert_pem
  title            = "${var.control_plane_name}-local-dp"
}

resource "local_sensitive_file" "dp_cert" {
  filename        = "${path.module}/certs/tls.crt"
  content         = tls_self_signed_cert.dp.cert_pem
  file_permission = "0600"
}

resource "local_sensitive_file" "dp_key" {
  filename        = "${path.module}/certs/tls.key"
  content         = tls_private_key.dp.private_key_pem
  file_permission = "0600"
}
