package config

// HashInclude keeps route checksums backward-compatible when optional route
// features are absent. PostgreSQL settings still participate in the checksum
// once configured, so credential and transport changes trigger config reloads.
func (o RouteOptions) HashInclude(field string, _ any) (bool, error) {
	if field == "Postgres" {
		return o.Postgres.IsSet, nil
	}
	return true, nil
}
