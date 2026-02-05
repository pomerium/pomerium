---
id: route-configuration-schema
title: "MCP Proxy Route Configuration Schema"
status: implemented
created: 2026-01-26
updated: 2026-02-05
priority: high
labels:
  - mcp
  - proxy
  - configuration
deps: []
---

# MCP Proxy Route Configuration Schema

## Summary

✅ **ALREADY IMPLEMENTED** - The existing `mcp.server` route configuration fully supports proxying to remote MCP servers with automatic OAuth 2.1 discovery. When `upstream_oauth2` is omitted, Pomerium auto-discovers authorization requirements via RFC 9728/8414.

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

### Auto-Discovery Mode

When `mcp.server` is configured but `upstream_oauth2` is **omitted**, Pomerium:
- Acts as an MCP proxy to the upstream
- Auto-discovers authorization requirements via RFC 9728 (Protected Resource Metadata)
- Auto-discovers AS endpoints via RFC 8414 (AS Metadata)
- Auto-generates and hosts a Client ID Metadata Document
- Handles OAuth 2.1 flows transparently

No schema changes are required — the existing `MCPServer` struct already supports this:

```go
type MCPServer struct {
    UpstreamOAuth2  *UpstreamOAuth2 `mapstructure:"upstream_oauth2"`
    MaxRequestBytes *uint32         `mapstructure:"max_request_bytes"`
    Path            *string         `mapstructure:"path"`
}
```

When `UpstreamOAuth2` is nil, Pomerium enters auto-discovery mode.

## Configuration Examples

### Zero-Configuration Proxy (Auto-Discovery)

```yaml
routes:
  - from: https://mcp.example.com
    to: https://remote-mcp.provider.com
    mcp:
      server: {}  # Empty server block triggers auto-discovery
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

## Token Binding

Upstream tokens are always bound to the authenticated user: `(user_id, route_id, upstream_server)`.

This ensures:
- Tokens are never shared across users
- Each user maintains their own consent/authorization with the upstream
- Token revocation is scoped to individual users

## Already Implemented

### ✅ Auto-Discovery Detection (host_info.go:122-130)

```go
func (r *HostInfo) UsesAutoDiscovery(host string) bool {
    serverInfo, ok := r.servers[host]
    if !ok {
        return false
    }
    // Auto-discovery mode means NO upstream OAuth2 config
    return serverInfo.Config == nil
}
```

### ✅ Schema Support (policy.go:238-245)

```go
type MCPServer struct {
    UpstreamOAuth2  *UpstreamOAuth2  // nil = auto-discovery mode
    MaxRequestBytes *uint32
    Path            *string
}
```

### ✅ CIMD Hosting for Auto-Discovery (handler_cimd.go:73-76)

```go
// Check if this host uses auto-discovery mode (no upstream_oauth2)
if !h.hosts.UsesAutoDiscovery(hostname) {
    return nil, false  // 404 - not in auto-discovery mode
}
```

### ✅ Tests Validating Behavior (e2e/mcp_client_id_metadata_test.go:490)

- Routes without `upstream_oauth2` → CIMD served, auto-discovery mode
- Routes with `upstream_oauth2` → CIMD returns 404, explicit mode

## Remaining Work

### Documentation Only
- [ ] Update config reference docs with auto-discovery example in comments

## Acceptance Criteria

1. ✅ `mcp.server` without `upstream_oauth2` triggers auto-discovery mode (implemented)
2. ✅ `mcp.server` with `upstream_oauth2` works exactly as before (backward compatible, tested)

## References

- Existing config: [config/policy.go:223-294](config/policy.go#L223-L294)
- Existing protobuf: [pkg/grpc/config/config.proto:226-267](pkg/grpc/config/config.proto#L226-L267)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-02-05: Marked as **implemented** - schema already supports auto-discovery mode via nil `upstream_oauth2`; UsesAutoDiscovery(), CIMD hosting, and tests all exist
- 2026-02-04: Removed UpstreamTokenBinding configuration entirely; tokens are always bound to user
- 2026-01-26: Simplified token binding to user-only (removed per_session option)
- 2026-01-26: Revised to align with existing `mcp.server` schema; auto-discovery triggered by omitting `upstream_oauth2`
- 2026-01-26: Issue created from epic breakdown
