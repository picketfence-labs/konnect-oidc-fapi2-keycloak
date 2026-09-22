variable "control_plane_name" {
  description = "Konnect control plane name and decK lookup key."
  type        = string
  default     = "oidc-routing-demo"
}

variable "auth0_domain" {
  description = "Auth0 tenant domain, without scheme. Supplied from AUTH0_DOMAIN by with-env.sh."
  type        = string
}

variable "auth0_management_client_id" {
  description = "Management API M2M client ID used by Terraform. Supplied from AUTH0_CLIENT_ID by with-env.sh."
  type        = string
}

variable "default_db_existing_client_ids" {
  description = "Existing Auth0 client IDs to retain on the tenant default database connection. Obtain the live list before managing a shared tenant; exclude the demo Gateway client."
  type        = list(string)
}

variable "claim_namespace" {
  description = "Collision-resistant namespace for custom OIDC claims."
  type        = string
  default     = "https://oidc-demo.example.com"
}

variable "enable_par" {
  description = "Require PAR for the Auth0 client and select the PAR decK state. Tenant PAR must already be enabled."
  type        = bool
  default     = false
}

variable "ui_url" {
  type    = string
  default = "http://localhost:3000"
}

variable "gateway_callback_url" {
  type    = string
  default = "http://localhost:8000/api/demo"
}
