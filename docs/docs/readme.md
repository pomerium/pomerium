---
title: What is Pomerium?
lang: en-US
sidebarDepth: 0
meta:
  - name: keywords
    content: >-
      pomerium overview identity-access-proxy beyondcorp zero-trust
      reverse-proxy ztn zero-trust-networks
---

# What is Pomerium

## Overview?

Pomerium is an identity-aware proxy that enables secure access to internal applications. Pomerium provides a standardized interface to add access control to applications regardless of whether the application itself has authorization or authentication baked-in. Pomerium gateways both internal and external requests, and can be used in situations where you'd typically reach for a VPN.

Pomerium can be used to:

- provide a **single-sign-on gateway** to internal applications.
- enforce **dynamic access policy** based on **context**, **identity**, and **device state**.
- aggregate access logs and telemetry data.
- perform delegated user authorization for service-based authorization systems:
  - [Istio](/guides/istio.md)
  - [Google Cloud](/guides/cloud-run.md)
- provide unified identity attestation for upstream services:
  - [Kubernetes](/guides/kubernetes.md)
  - [Grafana](/guides/istio.md#pomerium-configuration)
  - [Custom applications](/docs/topics/getting-users-identity.md)
- provide a **VPN alternative**.

## Demo

To make this a bit more concrete, click the image thumbnail to see a short youtube demo:

[![demo](https://img.youtube.com/vi/ddmrkvBSO60/0.jpg)](https://www.youtube.com/watch?v=ddmrkvBSO60 "Pomerium demo")

The above video shows the flow for both an unauthorized and authorized user.

1. An **unauthorized** user authenticates with their corporate single-sign-on provider.
2. The **unauthorized** user is blocked from a protected resource.
3. The **unauthorized** user signs out from their session.
4. An **authorized** user authenticates with their corporate single-sign-on provider.
5. Pomerium delegates and grants access to the requested resource.
6. The **authorized** user inspects their user details including group membership.
