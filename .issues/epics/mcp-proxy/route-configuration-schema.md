---
id: route-configuration-schema
title: "MCP Proxy Route Configuration Schema"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: high
labels:
  - mcp
  - proxy
  - configuration
deps: []
---

# MCP Proxy Route Configuration Schema

## Summary

Extend the existing `mcp.server` route configuration to support proxying to remote MCP servers with automatic OAuth 2.1 discovery. When `upstream_oauth2` is omitted, Pomerium auto-discovers authorization requirements via RFC 9728/8414.

## Current State

The existing schema (`config/policy.go`, `pkg/grpc/config/config.proto`) defines:

```go
type MCP struct {
    Server *MCPServer `mapstructure:"server" yaml:"server,omitempty"`
    Client *MCPClient `mapstructure:"client" yaml:"client,omitempty"`
}

type MCPServer struct {
    UpstreamOAuth2  *UpstreamOAuth2 `mapstructure:"upstream_oauth2"`
    MaxRequestBytes *uint32         `mapstructure:"max_request_bytes"`
    Path            *string         `mapstructure:"path"`
}

type UpstreamOAuth2 struct {
    ClientID     string
    ClientSecret string
    Endpoint     OAuth2Endpoint
    Scopes       []string
}
```

Currently, `upstream_oauth2` requires explicit configuration of client credentials and endpoints.

## Proposed Changes

### 1. Auto-Discovery Mode

When `mcp.server` is configured but `upstream_oauth2` is **omitted**, Pomerium:
- Acts as an MCP proxy to the upstream
- Auto-discovers authorization requirements via RFC 9728 (Protected Resource Metadata)
- Auto-discovers AS endpoints via RFC 8414 (AS Metadata)
- Auto-generates and hosts a Client ID Metadata Document
- Handles OAuth 2.1 flows transparently

### 2. Add Token Binding Configuration

Add `upstream_token_binding` field to `MCPServer`:

```go
type MCPServer struct {
    UpstreamOAuth2       *UpstreamOAuth2       `mapstructure:"upstream_oauth2"`
    UpstreamTokenBinding *UpstreamTokenBinding `mapstructure:"upstream_token_binding"`  // NEW
    MaxRequestBytes      *uint32               `mapstructure:"max_request_bytes"`
    Path                 *string               `mapstructure:"path"`
}

type UpstreamTokenBinding string

const (
    UpstreamTokenBindingPerUser        UpstreamTokenBinding = "per_user"
    UpstreamTokenBindingServiceAccount UpstreamTokenBinding = "service_account"
)
```

Protobuf addition:

```protobuf
message MCPServer {
  optional UpstreamOAuth2       upstream_oauth2        = 1;
  optional uint32               max_request_bytes      = 2;
  optional string               path                   = 3;
  optional UpstreamTokenBinding upstream_token_binding = 4;  // NEW
}

enum UpstreamTokenBinding {
  UPSTREAM_TOKEN_BINDING_UNSPECIFIED     = 0;
  UPSTREAM_TOKEN_BINDING_PER_USER        = 1;
  UPSTREAM_TOKEN_BINDING_SERVICE_ACCOUNT = 2;
}
```

## Configuration Examples

### Zero-Configuration Proxy (Auto-Discovery)

```yaml
routes:
  - from: https://mcp.example.com
    to: https://remote-mcp.provider.com
    mcp:
      server: {}  # Empty server block triggers auto-discovery
```

Or with explicit token binding:

```yaml
routes:
  - from: https://mcp.example.com
    to: https://remote-mcp.provider.com
    mcp:
      server:
        upstream_token_binding: per_user  # per_user (default) | service_account
```

### Explicit OAuth Configuration (Current Behavior)

```yaml
routes:
  - from: https://mcp.example.com
    to: https://internal-mcp.example.com
    mcp:
      server:
        upstream_oauth2:
          client_id: "my-client-id"
          client_secret: "my-secret"
          endpoint:
            auth_url: "https://auth.example.com/authorize"
            token_url: "https://auth.example.com/token"
          scopes:
            - "mcp:read"
            - "mcp:write"
```

## Behavior Matrix

| `upstream_oauth2` | Behavior |
|-------------------|----------|
| Configured | Use explicit OAuth config (current behavior) |
| Omitted (or `server: {}`) | Auto-discover via RFC 9728/8414, generate CIMD |

## Token Binding Modes

| Mode | Key | Use Case |
|------|-----|----------|
| `per_user` (default) | `(user_id, route_id, upstream)` | Shared across sessions for same user |
| `service_account` | `(route_id, upstream)` | Single shared token, requires audit |

## Implementation Tasks

### Schema Changes
- [ ] Add `UpstreamTokenBinding` enum to protobuf
- [ ] Add `upstream_token_binding` field to `MCPServer` in protobuf
- [ ] Add `UpstreamTokenBinding` type to Go config
- [ ] Add `UpstreamTokenBinding` field to `MCPServer` struct
- [ ] Implement config validation (valid enum values)
- [ ] Add default value (`per_user`) when not specified

### Behavior Changes
- [ ] Detect "auto-discovery mode" when `upstream_oauth2` is nil
- [ ] Wire auto-discovery mode to upstream discovery component
- [ ] Ensure explicit `upstream_oauth2` still works unchanged
- [ ] Log warning when `service_account` binding is used

### Documentation
- [ ] Update config reference docs
- [ ] Add examples for both modes
- [ ] Document security implications of each binding mode

## Acceptance Criteria

1. `mcp.server` without `upstream_oauth2` triggers auto-discovery mode
2. `mcp.server` with `upstream_oauth2` works exactly as before (backward compatible)
3. `upstream_token_binding` defaults to `per_user` when not specified
4. Invalid `upstream_token_binding` values produce clear error messages
5. `service_account` mode logs appropriate warnings

## References

- Existing config: [config/policy.go:223-294](config/policy.go#L223-L294)
- Existing protobuf: [pkg/grpc/config/config.proto:226-267](pkg/grpc/config/config.proto#L226-L267)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-01-26: Simplified token binding to user-only (removed per_session option)
- 2026-01-26: Revised to align with existing `mcp.server` schema; auto-discovery triggered by omitting `upstream_oauth2`
- 2026-01-26: Issue created from epic breakdown
