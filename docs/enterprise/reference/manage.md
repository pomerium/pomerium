---
title: Manage
lang: en-US
sidebarDepth: 2
meta:
    - name: keywords
      content: configuration options settings Pomerium enterprise console
---

# Manage

## Routes

A Route provides access to a service through Pomerium.

### General

The **General** tab defines the route path, both from the internet and to the internal service, and the policies attached. Note that policies enforced on a Namespace the Route resides in will also be applied.

#### Name

#### From

#### To

#### Redirect

#### Policies

#### Pass Identity Headers

#### Enable Google Cloud Serverless Authentication

### Matchers

### Rewrite

### Timeouts

### Headers

### Load Balancer

## Policies

A Policy defines what permissions a set of users or groups has. Policies are applied to [Namespaces] or [Routes] to associate the set of permissions with a service or set of service, completing the authentication model.

::: tip
This is a separate concept from [policies](../reference/#policy) in the non-enterprise model. In open-source Pomerium, the `policy` block defines both routes and access.
:::

Policies can be constructed three ways:

#### Web UI

From the **BUILDER** tab, users can add allow or deny blocks to a policy, containing and/or/not/nor logic to allow or deny sets of users and groups.

![A policy being constructed in Pomerium Enterprise console allowing a single user access](../img/example-policy-single-user.png)

#### Pomerium Policy Language

From the **EDITOR** tab users can write policies in Pomerium Policy Language (**PPL**), a YAML-based notation.

![A policy as viewed from the editor tab](../img/example-policy-editor.png)

#### Rego

For those using [OPA](https://www.openpolicyagent.org/), the **REGO** tab will accept policies written in Rego.

::: tip
A policy can only support PPL or Rego. Once one is set, the other tab is disabled.
:::

#### Overrides
- **Any Authenticated User**: This setting will allow access to a route with this policy attached to any user who can authenticate to your Identity Provider (**IdP**).
- **CORS Preflight**: 
- **Public Access**: This setting allows complete, unrestricted access to an associated route. Use this setting with caution.

## Certificates

