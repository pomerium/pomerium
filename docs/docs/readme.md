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
- a **VPN alternative**.

## Architecture

<img alt="pomerium architecture diagram" src="/pomerium-diagram.svg" width="100%">

## In action

To make this a bit more concrete, see the following short video which demonstrates:

1. An **unauthorized** user authenticating with their corporate single-sign-on provider (in this case Google)
2. The **unauthorized** user being blocked from a protected resource.
3. The **unauthorized** user signing out from their session.
4. An **authorized** user authenticating with their corporate single-sign-on provider.
5. Pomerium delegating and grating access to the requested resource.
6. The **authorized** user inspecting their user details including group membership.

<video autoplay="" loop="" muted="" playsinline="" width="100%" height="600" control=""><source src="/pomerium-in-action-800-600.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>
