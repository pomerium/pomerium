package config

// InternalMCPOptions configures the in-process Model Context Protocol
// server that exposes pomerium's ConfigService as MCP tools. The server
// listens on a Unix domain socket bound at startup; operators expose it
// externally by adding a regular pomerium route with `to: unix://<path>`.
//
// This option is local-only — it does not propagate via the config
// protobuf surface, because it describes a per-binary listener rather
// than cluster-shared state.
type InternalMCPOptions struct {
	// Enabled binds the listener at startup. When false (the default),
	// no socket is created.
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`

	// SocketPath overrides the default socket location. When unset,
	// the listener binds at $TMPDIR/pomerium-mcp-configapi.sock —
	// mirroring the convention used for the Envoy admin socket.
	SocketPath string `mapstructure:"socket_path" yaml:"socket_path,omitempty"`
}
