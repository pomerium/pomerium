---
title: Production Deployment
description: >-
 This article covers production deployment requirements and concerns
meta:
  - name: keywords
    content: pomerium, identity access proxy, production, deployment, scale, scaling, horizontal,
---


# Production Deployment

This page covers the topic of running Pomerium in a production configuration.

Before deploying Pomerium to Production, you should have already tested Pomerium in one or more demo environments and confirmed:

 - A working connection to your [IdP](/docs/glossary.md#identity-provider).
 - Working test routes to your upstream services, including [JWT verification] where applicable.
 - For Pomerium Enterprise, a working demo of the Pomerium Enterprise Console, with confirmed access for your [Admins and Managers][rbac].


## Service Mode

Pomerium is designed to be run in two modes: All-In-One or Split Service. These modes are not mutually exclusive, meaning you can run one or multiple instances of Pomerium in all-in-one mode, and spin up additional instances for specific components as needed.

Each instance of Pomerium runs in all-in-one mode unless specified to run as a specific component by the `services` key. See [All-In-One vs Split Service mode](/reference/readme.md#all-in-one-vs-split-service-mode) for more details.

It's important to note that any production deployment with more than one instance of Pomerium (in any combination of modes) should be configured to use Redis as the [`databroker_storage_type`](/reference/readme.md#data-broker-storage-type). See [Data Storage - Backends](/docs/topics/data-storage.md#backends) for more details.

### All-in-One

It may be desirable to run in "all-in-one" mode in smaller deployments or while testing. This reduces the resource footprint and simplifies DNS configuration. All URLs point at the same Pomerium service instance.

### Discrete Services

In larger footprints, it is recommended to run Pomerium as a collection of discrete service clusters. This limits blast radius in the event of vulnerabilities and allows for per-service [scaling](#scaling) and monitoring.

Please also see [Architecture](/docs/architecture.md) for information on component interactions.

## Scaling

In split service mode, you have the opportunity to scale the components of Pomerium independently.

All of Pomerium's components are designed to be [stateless](/docs/glossary.md#stateless), and may all be scaled horizontally or vertically. In general, horizontal scaling is recommended. Vertical scaling will lead to diminished returns after ~8 vCPUs.

The Databroker service, which is responsible for session and identity related data, must be [configured for external persistence](/docs/topics/data-storage.md) to be fully stateless.

Pomerium's individual components can be divided into two categories; the data plane and control plane. Regardless of which mode you run Pomerium in, we strongly recommend multiple instances of each service for fault tolerance.

::: tip
Our [Helm deployment](/docs/k8s/helm.md) supports [Horizontal Pod Autoscaling](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/).
:::

### Data Plane

#### Proxy

The Proxy service, as the name implies, is responsible for proxying all user traffic, in addition to performing checks to the Authorization service. The proxy is directly in path for user traffic.

Proxy will need resources scaled in conjunction with request count and may need average request size accounted for. The heavier your user traffic, the more resources the Proxy service should have provisioned.

#### Authorize

The Authorize service is responsible for policy checks during requests. It is in the hot path for user requests but does not directly handle user traffic.

Authorize will need resources scaled in conjunction with request count. Request size and type should be of a constant complexity. In most environments, Authorize and Proxy will scale linearly with request volume (user traffic).

Note that the compute cost of each request is about two times (2x) greater for the Authorize service compared to Proxy; if Proxy utilizes 5% of CPU resources, Authorize would likely use 10%.

### Control Plane

#### Authenticate

The Authenticate service handles session cookie setup, session storage, and authentication with your Identity Provider.

Authenticate requires significantly fewer resources than other components due to the only-occasional requirement to establish new sessions. This happens when users first sign in, and when their authentication expires (determined by your IdP).

Add resources to the Authenticate service if you have a high session/user churn rate. The requests should be constant time and complexity, but may vary by Identity Provider implementation. Resources for the Authenticate service should scale *roughly* with your total user count.

Regardless of the low resource utilization, we recommend running no less than 2 instances for resiliency and fault tolerance.

### Databroker

The Databroker service is responsible for background identity data retrieval and storage. It is in the hot path for user authentication. However, it does not directly handle user traffic and is not in-path for authorization decisions.

The Databroker service does not require significant resources, as it provides streaming updates of state changes to the other services. There will be utilization spikes when Authorize services are restarted and perform an initial synchronization.

Databroker resource requirements scale with the number of replicated services in the [data plane](#data-plane). That is to say, additional instances of the Proxy and Authorize services will increase demand on Databroker. Additionally, the size of the user directory contributes to the resource requirements for the data storage, Redis.

The eBook Redis in Action has a chapter on [Scaling Redis](https://redis.com/ebook/part-3-next-steps/chapter-10-scaling-redis/). Pomerium is compatible with both Redis HA and Redis cluster scaling.

In many deployments, 2 replicas of Databroker is enough to provide resilient service.

::: warning
In a production configuration, Databroker CPU/IO utilization also translates to IO load on the [underlying storage system](/docs/topics/data-storage.md). Ensure it is scaled accordingly!
:::

## Load Balancing

In any production deployment, running multiple replicas of each Pomerium service is strongly recommended. Each service has slightly different concerns about utilizing the replicas for high availability and scaling, enumerated below.

### Proxy

You should deploy Layer 4 load balancing between end users and Pomerium Proxy services to provide high availability and horizontal scaling. Do not use L7 load balancers, since the Proxy service handles redirects, sticky sessions, etc.

Note that deployments on Kubernetes can utilize The [Pomerium Ingress Controller](/docs/k8s/ingress.md) to simplify configuration.

### Authenticate

The suggested practice is to use the Pomerium Proxy service to load-balance Authenticate. Alternately, you could use an independent Layer 4 or Layer 7 load balancer, but this increases complexity.


### Authorize and Databroker

You do **not** need to provide a load balancer in front of Authorize and Databroker services. Both utilize GRPC and have special requirements if you should choose to use an external load balancer. GRPC can perform client based load balancing and is the best architecture for most configurations.

By default, Pomerium gRPC clients will automatically connect to all IPs returned by a DNS query for the name of an upstream service. They will then regularly re-query DNS for changes to the Authorize or Databroker service cluster. Health checks and failover are automatic.

You can also define multiple domain names for Databroker or Authorize services with the [`databroker_service_url`](/reference/readme.md#data-broker-service-url) and [`authorize_service_urls`](/reference/readme.md#authorize-service-url) shared config keys.

## High Availability

As mentioned in [scaling](#scaling), Pomerium components themselves are stateless and support horizontal scale out for both availability and performance reasons.

A given service type does not require communication with its peer instances to provide high availability. E.g., a Proxy service instance does not communicate with Proxy instances.

Regardless of the service mode, it is recommended you run at least 2 instances of Pomerium with as much physical and logical separation as possible. For example, in Cloud environments, you should deploy instances of each service to at least 2 different zones. On-prem environments should deploy >=2 instances to independent hardware.

Ensure that you have enough spare capacity to handle the scope of your failure domains.

::: warning
Multiple replicas of Databroker or all-in-one service are only supported with [external storage](/docs/topics/data-storage.md) configured
:::

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


[JWT verification]: /docs/topics/mutual-auth.md#jwt-verification-application-based-mutual-authentication
[rbac]: /enterprise/concepts.md#rbac-for-enterprise-console-users
