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
