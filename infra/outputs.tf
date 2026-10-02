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

output "gateway_targets" {
  value = {
    api = {
      control_plane_id       = konnect_gateway_control_plane.demo.id
      control_plane_name     = konnect_gateway_control_plane.demo.name
      control_plane_endpoint = konnect_gateway_control_plane.demo.config.control_plane_endpoint
      telemetry_endpoint     = konnect_gateway_control_plane.demo.config.telemetry_endpoint
    }
    "third-party" = {
      control_plane_id       = konnect_gateway_control_plane.third_party.id
      control_plane_name     = konnect_gateway_control_plane.third_party.name
      control_plane_endpoint = konnect_gateway_control_plane.third_party.config.control_plane_endpoint
      telemetry_endpoint     = konnect_gateway_control_plane.third_party.config.telemetry_endpoint
    }
  }
}
