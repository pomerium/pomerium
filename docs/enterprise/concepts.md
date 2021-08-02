---
title: Concepts
sidebarDepth: 2
description: Learn how the Pomerium Enterprise Console works.
---

# Concepts

## Namespaces

In the Pomerium Enterprise Console, a **Namespace** is a cornerstone organization unit. They are container objects, that behave similar to a unix directory structure.

In each Namespace, you can define an organizational unit of users and groups with fine-grained access management. This enables teams to self-service the routes and policies pertinent to them. Namespaces can optionally inherit from their parent units.

Namespaces enable:

- Self-Service.
- Hierarchical policy enforcement (both enforced, and optional),
- Policy organization.
- RBAC for the Enterprise Console itself.

Each of these sub-concepts are related and build on each other to form a unified security model.

### Self-Service Capabilities

One of the benefits of an identity-aware access proxy is that, once in place, developers and owners of enterprise applications have an incentive to configure their services to be accessible via the proxy.

Self-service has [several benefits](https://www.usenix.org/system/files/login/articles/login_winter16_05_cittadini.pdf):

- Frees global administrators from continuously modifying the configuration per user requests
- Encourages service owners to own their configuration fragment
- Ensures a reasonable compromise between development velocity and security controls

Unlike with a VPN, or network driven access control mechanisms, application owners (with limited access permissions managed through namespaces) can maintain route and policy configuration for their own services, while  higher level operations, security, and identity teams are able to enforce higher level authorization and access policies.

### Hierarchical Policy Enforcement

Hierarchical policy lets administrators enforce high level authorization policy. Policies can be optional (self-select), or mandatory.

Identity and access is organized and controlled with Identity and Access Management (**IAM**) teams via your Identity Provider (**IdP**). These users and groups are read by Pomerium from your IdP, and used to determine top-level Namespace organization.

Consider this scenario: your organization has a security team managing high-level, course grain authorization controls. For example, they want to ensure that everyone with access to internal resources:

   - has a `yourcompany.com` email account,
   - isn't coming from a known bad actor IP address,

From there, the security team delegates management of child [Namespaces](#namespaces) to application teams, providing flexibility to self-manage their own application [Routes](#routes) and [Policies](#policies).

For example, a developer group can be given control to determine who has access to their Namespace, and create or edit Routes within it. They can provide authentication to their WiP app without writing new authorization code.

### RBAC for Enterprise Console Users

- Namespaces are also used to achieve Role Based Access Control (**RBAC**) in the console itself.
- There are three different roles:

#### Guest (no role)

Users who are authenticated by your IdP but do not have a role assigned in the Pomerium Console can still view the list of Namespaces, but nothing else.

#### Viewer

A user with the Viewer role can:

- view all resources in a Namespace (Routes, Policies, Certificates), including child Namespaces
- view traffic dashboard for routes in the Namespace, including child Namespaces
- view the activity log for a namespace.

#### Manager

In addition to the access provided by the Viewer role, the Manager can create, read, update, and delete routes, policies, and certificates in a Namespace (as wel as its children). A Manager may also reference policies and certificates in the parent Namespace.

#### Admin

An Admin user has permissions across all Namespaces. They can manage global settings, sessions, and service accounts, as well as view events and runtime data.

## Service Accounts

Service accounts provides bearer token based authentication for machine-to-machine communication through Pomerium to your protected endpoints. They can provide auth for monitoring services, create API integrations, etc.

Service accounts can represent identities from your IdP or be Pomerium-only identities.

## Routes

Routes define the connection pathway and configuration from the internet to your internal service. As a very basic level, a route sends traffic from `external-address.company.com` to `internalService-address.localdomain`, restricted by the policies associated with it, and encrypted by your TLS certificates. But more advanced configurations allow identity header pass-through, path and prefix rewrites, request and response header modification, load balancer services, and more.

### Protected Endpoints

This term refers to the system or service the route provides or restricts access to.

## Policies

A Policy defines what permissions a set of users or groups has.

Policies can be applied to [Routes](#routes) directly, or enforced within a [Namespace](#namespaces). This associates the set of permissions with a service or set of services, completing the authentication model.

To learn more about how to create Policies in Pomerium Enterprise Console, see [Reference: Policies].

## Access control

Authentication and authorization are similar concepts that are often used interchangeably.

**Authentication** is the process of determining if you are who you say you are.

**Authorization** is the process of determining if you are allowed to do the thing you are trying to do.

Pomerium provides a standardized interface to add access control, regardless if an application itself has authorization or authentication baked in, so developers can focus on their app's functionality, not reinventing access control.

### Authentication

Pomerium provides authentication via your existing identity provider (Pomerium supports all major [single sign-on](/docs/identity-providers/) providers (Okta, G Suite, Azure, AD, Ping, Github and so on).

### Authorization

Authorization policy can be expressed in a high-level, [declarative language](/enterprise/reference/manage.html#pomerium-policy-language) or [as code](/enterprise/reference/manage.html#rego) that can be used to enforce ABAC, RBAC, or any other governance policy controls. Pomerium can make holistic policy and authorization decisions using external data and request context factors such as user groups, roles, time, day, location and vulnerability status.

Trust flows from identity, device-state, and context, not network location. Every device, user, and application's communication should be authenticated, authorized, and encrypted.

Authorization is where Pomerium's value proposition really lies. With Pomerium:

- requests are continuously re-evaluated on a per-request basis.
- authorization is identity and context aware; pomerium can be used to integrate data from any source into authorization policy decisions.
- trust flows from identity, device-state, and context, not network location. Every device, user, and application's communication should be authenticated, authorized, and encrypted.
- Pomerium provides detailed audit logs for all activity in your environment. Quickly detect anomalies to mitigate bad actors and revoke access with a click of a button. Simplify life-cycle management and access reviews.

[Reference: Policies]: /enterprise/reference/manage.md#policies-2