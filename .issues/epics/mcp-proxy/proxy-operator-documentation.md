---
id: proxy-operator-documentation
title: "MCP Proxy Operator Documentation"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: medium
labels:
  - mcp
  - proxy
  - documentation
deps:
  - route-configuration-schema
  - per-route-cimd-hosting
  - authorization-choreographer
---

# MCP Proxy Operator Documentation

## Summary

Create comprehensive documentation for operators configuring Pomerium to proxy to remote MCP servers. Documentation should emphasize the zero-configuration nature while explaining the underlying mechanics for troubleshooting.

## Documentation Sections

### 1. Quick Start

```yaml
# Minimal configuration to proxy to a remote MCP server
routes:
  - from: https://mcp.example.com
    to: https://remote-mcp.provider.com
    mcp:
      server: {}  # Empty server block enables auto-discovery proxy mode
```

That's it! Pomerium handles:
- Client registration with remote authorization server (auto-generated CIMD)
- User authentication and consent (redirect flow)
- Token management (acquisition, caching, refresh)
- Request transformation (token injection)

### 2. How It Works

Explain the flow without requiring deep OAuth knowledge:
- User connects to Pomerium
- Pomerium discovers remote server's auth requirements (RFC 9728/8414)
- User is redirected to remote authorization server for consent
- Pomerium acquires and manages tokens transparently
- Requests are forwarded with upstream-specific tokens

### 3. Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mcp.server` | object | - | Enable MCP server mode |
| `mcp.server.upstream_oauth2` | object | (omit for auto-discovery) | Explicit OAuth config; when omitted, auto-discovery is used |
| `mcp.server.upstream_token_binding` | string | `per_user` | Token isolation mode |

Token binding modes:
- `per_user`: Tokens shared across user's sessions (default)
- `per_session`: Tokens isolated per MCP session
- `service_account`: Single shared token (requires audit)

### 4. Troubleshooting

Common issues and solutions:

**"Authorization failed" errors**
- Check if remote server supports CIMD
- Verify network connectivity to remote AS
- Check Pomerium logs for discovery failures

**"Token expired" errors**
- Verify refresh token flow is working
- Check token lifecycle logs

**Performance issues**
- Review token caching behavior
- Check discovery cache hit rate

### 5. Security Considerations

- Token isolation guarantees
- Audit logging configuration
- Service account mode warnings
- Consent transparency

### 6. Monitoring and Observability

Metrics to monitor:
- Token cache hit rate
- Authorization flow duration
- Upstream request latency
- Error rates by type

Log entries to understand:
- Token acquisition events
- Token refresh events
- Authorization failures

### 7. Advanced Topics

- Multi-hop scenarios
- Custom scope handling (pass-through)
- Token storage backend details
- Cache invalidation behavior

## Implementation Tasks

- [ ] Write Quick Start guide
- [ ] Write How It Works explanation
- [ ] Document configuration reference
- [ ] Write troubleshooting guide
- [ ] Document security considerations
- [ ] Document monitoring/observability
- [ ] Write advanced topics
- [ ] Add architecture diagrams
- [ ] Include example configurations
- [ ] Review for accuracy and clarity

## Acceptance Criteria

1. Operator can configure proxy route from documentation alone
2. Zero-configuration nature is emphasized
3. Troubleshooting section covers common issues
4. Security implications are clearly explained
5. Documentation is consistent with implementation
6. Examples are tested and working

## References

- [MCP Proxy Epic](./index.md)
- [Pomerium Documentation](https://www.pomerium.com/docs)

## Log

- 2026-01-26: Issue created from epic breakdown
