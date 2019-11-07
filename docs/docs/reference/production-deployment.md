---
title: Production Deployment
description: >-
  This article covers production deployment requirements and concerns
---

# Production Deployment

This page covers the topic of running Pomerium in a production configuration. See the [quick start section](../quick-start/) for canned example configurations.

Please also see [architecture](../#architecture) for information on component interactions.

## Service Mode

For configuration of the service mode, see [Service Mode](../reference/reference.md#service-mode).

### All in One

In smaller deployments or while testing, it may be desirable to run in "all-in-one" mode. This reduces resource footprint and simplifies DNS configuration. All URLs point at the same pomerium service instance.

### Discrete Services

In larger footprints, it is recommended to run Pomerium as a collection of discrete service clusters. This limits blast radius in the event of vulnerabilities and allows for per-service [scaling](#scaling) and monitoring.

In more complicated deployments, you may also choose to share aspects of the control plane across multiple logical Proxy clusters. Examples:

1. You want central AuthN and AuthZ but need to support a number of independently configured Proxy clusters
2. You want central AuthZ but different Proxy clusters need different IDPs

In both configurations, you must ensure the [Shared Secret](../reference/reference.md#shared-secret) matches across services. You must also ensure Proxy and Authenticate external names sit within the same domain.

## Scaling

In dedicated service mode, you have the opportunity to scale the components of Pomerium independently.

Pomerium's components are stateless, and may all be scaled horizontally or vertically. In general, horizontal scaling is recommended.

### Proxy

Proxy service, as the name implies, is responsible for proxying all user traffic, in addition to performing Authentication and Authorization checks. The proxy is directly in path for user traffic.

Proxy will need resources scaled in conjunction with request count and may need average request size accounted for. The heavier your user traffic, the more resources the Proxy service should have provisioned.

### Authorize

The Authorize service is responsible for policy checks during requests. It is in the hot path for user requests but does not directly handle user traffic.

Authorize will need resources scaled in conjunction with request count. Request size and type should be of a constant complexity.

### Authenticate

The Authenticate service handles session token renewal, creation, and interaction with your Identity Provider. The Authenticate service between a successful session setup or renewal and session expiration.

Authenticate requires significantly fewer resources than other components due to the only-occasional requirement to establish/renew sessions. Add resources to the Authenticate service if you have a high session churn rate. The requests should be constant time and complexity, but may vary by Identity Provider implementation.

## Load Balancing

In any production deployment, running multiple replicas of each Pomerium service is strongly recommended. Each service has slightly different concerns about utilizing the replicas for HA and scaling, enumerated below.

### Proxy

You should provide a TCP or HTTP(s) load balancer between end users and the Proxy services.

Proxy can handle its own SSL termination but is not a full web server. If you need any special capabilities such as redirects, sticky sessions, etc, it is typical to put Pomerium behind an L7 load balancer or ingress controller.

### Authenticate

You should provide a TCP or HTTP(s) load balancer between end users and the Authorize services.

Authenticate is compatible with any L4 or L7/HTTP load balancer. Session stickiness should not be required and it is typical to have Authenticate be a named vhost on the same L7 load balancer as the Proxy service.

### Authorize

You do **not** need to provide a load balancer between the Proxy and the Authorize services. Authorize utilizes GRPC and thus has special requirements if you should chose to use an external load balancer. GRPC can perform client based load balancing, and in most configurations is the best architecture.

By default, the Proxy will automatically connect to all IPs returned by a DNS query for the name of the Authorize service. Proxy will then regularly re-query DNS for changes to the Authorize service cluster. Health checks and failover are automatic.

**Many load balancers do not support HTTP2 yet. Please verify with your hardware, software or cloud provider**

If you choose to use an external proxying load balancer instead of the default client implementation:

- L7 mode requires HTTP2 support or Authorize requests will fail
- L4 (TCP) mode, GRPC/HTTP2 traffic from a Proxy instance will be pinned to a single Authorize instance due to the way HTTP2 multiplexes requests over a single established connection
- Due to the above limitations it is highly desirable to only use a load balancer which supports HTTP2 at Layer 7

## High Availability

As mentioned in [scaling](#scaling), Pomerium components themselves are stateless and support horizontal scale out for both availability and performance reasons.

A given service type does not require communication with its peer instances to provide high availability. Eg, a proxy service does not communicate with other proxies.

Regardless of the service mode, it is recommended you run 2+ instances of Pomerium with as much physical and logical separation as possible. For example, in Cloud environments, you should deploy instances of each service to at least 2 different zones. On-prem environments should deploy 2+ instances to independent hardware.

Ensure that you have enough spare capacity to handle the scope of your failure domains.

## SSL/TLS Certificates

Pomerium utilizes TLS end to end, so the placement, certificate authorities and covered subjects are critical to align correctly.

In a typical deployment, a minimum of two certs are required:

- A wildcard certificate which covers the external `from` names, the Proxy service's external name and the Authenticate service's external name
  - Must be trusted by user browsers or clients
  - Must cover subject names from the user perspective
- A certificate which covers the Authorize service's name
  - Must be trusted by the Proxy
  - Must cover the subject name from the Proxy's perspective

If you have L7 load balancing in front of the Proxy/Authenticate:

- Your wildcard certificate should live on the load balancer
- Your Authenticate and Proxy services will need a certificate accepted by the load balancer
- Your load balancer can be configured to verify the identity of the Authenticate and Proxy certificates

If you have TLS enabled applications behind the proxy:

- you may provide a client certificate for the Proxy service to connect to downstream services with and verify
- the Proxy may be configured to verify the name and certificate authority of downstream services with either the standard Root CA bundle or a custom CA
