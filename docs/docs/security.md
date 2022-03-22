---
title: Securing Pomerium
description: >-
  This page is an index for security-related pages throughout Pomerium's documentation.
---

# Securing Pomerium

Pomerium is a tool for securing your infrastructure while adhering to the principles of [Zero Trust](/docs/background.md#zero-trust). But that doesn't mean that your stack is "secure" right out of the box. Additionally, security is a battle of give and take; more security often comes at the cost of more complexity, both for the administrator and the end-user. What layers of security you choose to apply (and how you configure them) is highly dependent on your use case.

While we can't tell you what tools and technologies are right for you, we've compiled a list of all the security-related documentation we have, organized to help you discover what path to take.

## Background and Concepts

If you're just getting started, we suggest reviewing the following pages:

- [Background](/docs/background.md) - A quick primer on the failures of legacy models of "perimeter security" and an introduction to the concept of Zero Trust.
- [Architecture](/docs/architecture.md) - Learn how Pomerium is broken down into component services. How you choose to deploy Pomerium will set the stage for the kind of security practices that apply to your stack.
- [Mutual Authentication: A Component of Zero Trust](/docs/topics/mutual-auth.md) - Zero Trust's core principle could be said as "trust nothing without first (and continuously) verifying it". Mutual authentication is a big part of bringing that principle to bear. This page explains the concept and how it's achieved across several different layers of the network stack.
- [Glossary](/docs/glossary.md) - Keep this page handy for when you run into new or unfamiliar terminology.

## TLS Certificates

The long-time standard for server identity verification, the use of TLS certificates has exploded ever since [Let's Encrypt](https://letsencrypt.org/) made it possible for anyone to get a trusted certificate for free.

- The [Certificates](/docs/topics/certificates.md) topic page covers several basic methods for generating trusted or testing certificates.
- Our article on [Installing Pomerium Using Helm](/docs/k8s/helm.md) touches [briefly](/docs/k8s/helm.md#install-and-configure-cert-manager) on using [cert-manager](https://cert-manager.io/docs/) to manage certificates in Kubernetes environments. We also wrote a guide for their docs site covering integration of the [Pomerium Ingress](https://cert-manager.io/docs/tutorials/acme/pomerium-ingress/) Controller with cert-manager.
- The [Upstream mTLS With Pomerium](/guides/upstream-mtls.md) guide demonstrates mTLS between Pomerium and upstream services.
- Depending on your environment's needs, you may choose to verify some of all of your end users with [Client-Side mTLS](/guides/mtls.md).

## User Identity and Context

Part of Pomerium's strength comes from the ability to pass user identity and context to your upstream service. This enables repeated verification of authorization throughout a system.

- [Getting the user's identity](/docs/topics/getting-users-identity.md) details the JWT Pomerium creates to identify the user in any given request.
- [Original User Context](/docs/topics/original-request-context.md) explains how to pass along the user context when upstream services communicate with each other to complete a request.
- Many applications support native JWT verification. See [Enable jWT Authentication in Grafana](/guides/grafana.md#enable-jwt-authentication-in-grafana) for an example. For those that don't, you can perform [JWT Verification](/guides/jwt-verification.md) with a sidecar.


## Device Identity

Often overlooked or confused with multi-factor authentication (MFA), device identity (and posture) is one of the most important and under-utilized aspects of a strong zero trust security model.

- [Device Identity](/docs/topics/device-identity.md) provides background on the concept, and points the reader on how to configure policies that use device identity, and enroll devices in both open-source and Enterprise environments.

## Service Mesh

If you've read through all the docs linked above, first of all *wow*. That's a lot to absorb, kudos to you. But if you got this far and you're overwhelmed thinking about how to manage mutual authentication, user context verification, etc, between all your various applications, then you're primed and ready for a **service mesh**. A service mesh is a software component that acts as an infrastructure layer to facilitate the communication (and authentication) between services.

- Our [Istio](/guides/istio.md) guide covers integration between Pomerium and Istio, the most common service mesh.