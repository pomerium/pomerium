---
title: Overview
lang: en-US
sidebarDepth: 0
meta:
  - name: keywords
    content: pomerium overview identity-access-proxy beyondcorp zero-trust reverse-proxy ztn zero-trust-networks
---

# Overview

## What is Pomerium?

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

## Architecture

### System Level

Pomerium sits between end users and services requiring strong authentication. After verifying identity with your identity provider (IdP), Pomerium uses a configurable policy to decide how to route your user's request and if they are authorized to access the service.

<img alt="pomerium architecture diagram" src="./img/pomerium-system-context.svg" width="65%">

### Component Level

Pomerium is composed of 4 logical components:

- Proxy Service
  - All user traffic flows through the proxy
  - Verifies all requests with Authentication service
  - Directs users to Authentication service to establish session identity
  - Processes policy to determine external/internal route mappings
- Authentication Service
  - Handles authentication flow to your IdP as needed
  - Handles identity verification after initial Authentication
  - Establishes user session cookie
  - Stores user OIDC tokens in cache service
- Authorization Service
  - Processes policy to determine permissions for each service
  - Handles authorization check for all user sessions
  - Directs Proxy service to initiate Authentication flow as required
  - Provides additional security releated headers for upstream services to consume
- Cache Service
  - Retrieves identity provider related data such as group membership
  - Stores and refreshes identity provider access and refresh tokens
  - Provides streaming authoritative session and identity data to Authorize service
  - Stores session and identity data in persistent storage

In production deployments, it is recommended that you deploy each component separately. This allows you to limit external attack surface, as well as scale and manage the services independently.

In test deployments, all four components may run from a single binary and configuration.

<img alt="pomerium architecture diagram" src="./img/pomerium-container-context.svg" width="65%">

### Authentication Flow

Pomerium's internal and external component interactions during full authentication from a fresh user are diagramed below.

After initial authentication to provide a session token, only the authorization check interactions occur.

<a href="/pomerium-auth-flow.svg">
<img alt="pomerium architecture diagram" src="./img/pomerium-auth-flow.svg">
</a>

## In action

To make this a bit more concrete, see the following short video which demonstrates:

1. An **unauthorized** user authenticating with their corporate single-sign-on provider (in this case Google)
2. The **unauthorized** user being blocked from a protected resource.
3. The **unauthorized** user signing out from their session.
4. An **authorized** user authenticating with their corporate single-sign-on provider.
5. Pomerium delegating and granting access to the requested resource.
6. The **authorized** user inspecting their user details including group membership.

<video autoplay="" loop="" muted="" playsinline="" width="100%" height="600" control=""><source src="/pomerium-in-action-800-600.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>
