variable "control_plane_name" {
  description = "Konnect control plane name and decK lookup key."
  type        = string
  default     = "keycloak-fapi2-demo"
}

variable "third_party_control_plane_name" {
  description = "Konnect control plane name for the third-party Gateway."
  type        = string
  default     = "keycloak-fapi2-third-party-demo"

  validation {
    condition     = trimspace(var.third_party_control_plane_name) != "" && var.third_party_control_plane_name != var.control_plane_name
    error_message = "third_party_control_plane_name must be non-empty and differ from control_plane_name."
  }
}
