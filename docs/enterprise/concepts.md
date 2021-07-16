---
title: Concepts
sidebarDepth: 1
description: Learn how the Pomerium Enterprise Console works.
---

# Concepts

## Namespaces

In the Pomerium Enterprise Console, a namespace is where you can define an organizational unit of users and groups with fine-grained access management. This enables teams to self-service the routes and policies pertinent to them. Namespaces can optionally inherit from their parent units.

## Service Accounts

Service accounts handle machine-to-machine communication from Pomerium to your Identity Provider (**IdP**) in order to retrieve and establish group membership. Configuration is largely dependent on the IdP, but is usually an API acccess token with sufficient privlidges to read users and groups.

## Routes

Unlike the open-source Pomerium configuration, access is not defined alongside routing. Instead, authorization is configured by attaching [policies](#policies) to a route.

## Policies

In the open-source Pomerium config, routes and policies are configured in a single block, under `policy`:

```yaml
policy:
  - from: https://code.corp.domain.example
    to: http://codeserver:8080
    allowed_users:
      - some.user@domain.example
    allow_websockets: true
```

In the Pomerium Enterprise Console, [routes](#routes) and policies are separate entities. This allows for both easier and more fine-grained access control, as policies can be defined once, optionally associated under a [Namespace](#namespaces), and attached to one or more routes. Routes can also inherit policies from their parent Namespace <!-- @Travis please confirm -->.

### Authorization Policy