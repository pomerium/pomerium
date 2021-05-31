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

In the presence of multiple upstreams, make sure to specify either an active or passive health check, or both, to avoid requests being served to an unhealthy backend.

:::

## Active Health Checks

Active health checks issue periodic requests to each upstream to determine its health.
See [Health Checking](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/health_checking) for a comprehensive overview.

### HTTP Example

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

### TCP Example

```yaml
policy:
  - from: tcp+https://tcp-service.localhost.pomerium.io
    to:
      - tcp://tcp-1.local
      - tcp://tcp-2.local
    health_checks:
      - timeout: 1s
        interval: 5s
        unhealthy_threshold: 3
        healthy_threshold: 1
        tcp_health_check:
          send:
            text: "50494E47" #PING
          receive:
            text: "504F4E47" #PONG
```

## Passive Health Checks

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
- [`LEAST_REQUEST`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#weighted-least-request) and may be further configured using [`least_request_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-msg-config-cluster-v3-cluster-leastrequestlbconfig)
- [`RING_HASH`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#ring-hash) and may be further configured using [`ring_hash_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#config-cluster-v3-cluster-ringhashlbconfig) option
- [`RANDOM`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#random)
- [`MAGLEV`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#maglev) and may be further configured using [`maglev_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-msg-config-cluster-v3-cluster-maglevlbconfig) option

### Example

```yaml
policy:
  - from: https://myapp.localhost.pomerium.io
    to:
      - http://myapp-srv-1:8080
      - http://myapp-srv-2:8080
      - http://myapp-srv-3:8080
      - http://myapp-srv-4:8080
      - http://myapp-srv-5:8080
    lb_policy: LEAST_REQUEST
    least_request_lb_config:
      choice_count: 2 # current envoy default
```

## Load Balancing Weight

When a list of upstream URLs is specified in the `to` field, you may append an optional load balancing weight parameter. The individual [`lb_policy`](#load-balancing-method) settings will take this weighting into account when making routing decisions.

### Example

This configuration uses the default `round_robin` load balancer policy but specifies different frequency of selection be applied to the upstreams.

```yaml
policy:
  - from: https://myapp.localhost.pomerium.io
    to:
      - http://myapp-srv-1:8080,10
      - http://myapp-srv-2:8080,20
      - http://myapp-srv-3:8080,30
      - http://myapp-srv-4:8080,20
      - http://myapp-srv-5:8080,10
```

## Further reading

- [Introduction to modern network load balancing and proxying](https://blog.envoyproxy.io/introduction-to-modern-network-load-balancing-and-proxying-a57f6ff80236)
