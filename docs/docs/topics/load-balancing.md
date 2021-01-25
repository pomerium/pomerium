---
title: Upstream Load Balancing
description: >-
  This article covers Pomerium built-in load balancing capabilities in presence of multiple upstreams.
---

# Upstream Load Balancing

This article covers Pomerium built-in load balancing capabilities in presence of multiple upstreams.

## Multiple Upstreams

You may specify multiple servers for your upstream application, and Pomerium would load balance user requests between them.

```yaml
policy:
  - from: https://myapp.localhost.pomerium.io
    to:
      - http://myapp-srv-1:8080
      - http://myapp-srv-2:8080
```

::: tip

In presence of multiple upstreams, make sure to specify either an active or passive health check, or both, to avoid requests served to unhealthy backend.

:::

### Active Health Checks

Active health checks issue periodic requests to each upstream to determine its health.
See [Health Checking](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/health_checking) for a comprehensive overview.

```yaml
policy:
  - from: https://myapp.localhost.pomerium.io
    to:
      - http://myapp-srv-1:8080
      - http://myapp-srv-2:8080
    health_checks:
      - timeout: 10s
        interval: 60s
        healthy_threshold: 1
        unhealthy_threshold: 2
        http_health_check:
          path: "/"
```
### Passive Health Checks

Passive health check tries to deduce upstream server health based on recent observed responses. 
See [Outlier Detection](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/outlier) for comprehensive overview.

```yaml
policy:
  - from: https://myapp.localhost.pomerium.io
    to:
      - http://myapp-srv-1:8080
      - http://myapp-srv-2:8080
    outlier_detection: {}
```

## Load Balancing Method

`lb_policy` should be set to [one of the values](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers):

- [`ROUND_ROBIN`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#weighted-round-robin) (default)
- [`LEAST_REQUEST`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#weighted-least-request) and may be further configured using [``](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-msg-config-cluster-v3-cluster-leastrequestlbconfig)
- [`RING_HASH`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#ring-hash) and may be further configured using [`ring_hash_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#config-cluster-v3-cluster-ringhashlbconfig) option
- [`RANDOM`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#random)
- [`MAGLEV`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#maglev) and may be further configured using [`maglev_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-msg-config-cluster-v3-cluster-maglevlbconfig) option

## Further reading

- [Introduction to modern network load balancing and proxying](https://blog.envoyproxy.io/introduction-to-modern-network-load-balancing-and-proxying-a57f6ff80236)