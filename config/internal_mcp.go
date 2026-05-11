package config

// InternalMCPOptions configures the in-process Model Context Protocol
// server that exposes pomerium's ConfigService as MCP tools. Local-only;
// not propagated via the config protobuf surface.
type InternalMCPOptions struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled,omitempty"`
	SocketPath string `mapstructure:"socket_path" yaml:"socket_path,omitempty"`
}
