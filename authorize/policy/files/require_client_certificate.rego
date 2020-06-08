package pomerium.require_client_certificate

deny[status] {
    status := [495, "invalid client certificate"]
	not input.is_valid_client_certificate
}
