---
title: Concepts
sidebarDepth: 1
description: Learn how Pomerium Enterprise works.
---

# Concepts

## Namespaces

In Pomerium Enterprise, a **Namespace** is a cornerstone organization unit. They are container objects that behave similar to a unix directory structure.

In each Namespace, administrators can create organizational units where users and groups can be added. Namespaces enable fine-grained role based access control and management (**RBAC**) to managing Pomerium. The structure and hierarchy of namespaces empower teams to self-service the routes and policies pertinent to them. Namespaces can can also be used to optionally or mandatorily inherit from their parent permission or policies.

Namespaces enable:

- Self-Service.
- Hierarchical policy enforcement (both enforced, and optional),
- Policy organization.
- [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control) for the Enterprise Console itself.

Each of these sub-concepts are related and build on each other to form a unified security model.

See [Reference: Namespace] for more information.

### Self-Service Capabilities

One of the benefits of an identity-aware access proxy is that, once in place, developers and owners of enterprise applications have an incentive to configure their services to be accessible via the proxy.

Self-service has [several benefits](https://www.usenix.org/system/files/login/articles/login_winter16_05_cittadini.pdf):

- Frees global administrators from continuously modifying the configuration per user requests
- Encourages service owners to own their own route configuration and policy
- Ensures a reasonable compromise between development velocity and security controls

Unlike with a VPN, or network driven access control mechanisms, application owners (with limited access permissions managed through namespaces) can maintain route and policy configuration for their own services, while higher level operations, security, and identity teams are able to enforce higher level authorization and access policies.

### Hierarchical Policy Enforcement

Hierarchical policy lets administrators enforce inheritable authorization policy. Policies can be optional (self-select), or mandatory.

Identities and their group memberships are defined by your Identity Provider (**IdP**). Pomerium looks to your IdP for identity information, so policies defined using groups are always up-to-date with the access management defined upstream.

Consider this scenario: you want to enable your security team to manage high level corporate policy while enabling application owners to set finer grained user access to their specific applications. Pomerium can help you do that!

Your security team can enact top level security policies to ensure, everyone:

   - has a `yourcompany.com` email account,
   - isn't coming from a known bad actor IP address,

From there, the security team delegates management of child [Namespaces](#namespaces) to application teams, providing flexibility to self-manage their own application [Routes](#routes) and [Policies](#policies).

For example, a developer group can be given control to determine who has access to their Namespace, and create or edit Routes within it. They can provide authentication and authorization to their WiP app without writing new authorization code.

Meanwhile, the CFO is given [manager](#manager) permissions over the "Accounting" Namespace, and can set enforced or optional policies for the services within.

### RBAC for Enterprise Console Users

- Namespaces are also used to achieve Role Based Access Control (**RBAC**) in the console itself.
- There are three different roles:

#### Guest (no role)

Users who are authenticated by your IdP but do not have a role assigned in Pomerium Enterprise can still view the list of Namespaces, but nothing else.

#### Viewer

A user with the Viewer role can:

- view all resources in a Namespace (Routes, Policies, Certificates), including child Namespaces
- view traffic dashboard for routes in the Namespace, including child Namespaces
- view the activity log for a namespace.

#### Manager

In addition to the access provided by the Viewer role, a Manager can create, read, update, and delete routes, policies, and certificates in a Namespace (as well as its children). A Manager may also reference policies and certificates in the parent Namespace.

#### Admin

An Admin user has permissions across all Namespaces. They can manage global settings, sessions, and service accounts, as well as view events and runtime data.

## Users and Groups

Pomerium populates users and groups from your IdP. This data is cached to prevent hitting API rate-limits, ensure policy enforcement performance, and provides look-ahead support when adding users or groups to [Namespaces](#namespaces) and [Policies](#policies).

### Non-Domain Users

You may encounter a situation where you may want to add users that are not directly associated with your corporate identity provider service. For example, if you have a corporate GSuite account and want to add a contractor with a gmail account. In this case, there are two workarounds:

- Create a group within your identity provider directly with the non-domain users in it. This group can be found and added to Namespaces and Policies.
- Manually add the user's unique ID. Identify the ID from a user's Session Details page, or the [Sessions](/enterprise/reference/reports.md#sessions) page in Pomerium Enterprise.

   A user can see their session ID by navigating to the special `/.pomerium` URL endpoint from any Pomerium managed route. The unique ID is listed as "sub" under User Claims:

   ![The Session Details page, showing the "sub" data](./img/session-details.png)

## Service Accounts

Service accounts provides bearer token based authentication for machine-to-machine communication through Pomerium to your protected endpoints. They can provide auth for monitoring services, create API integrations, and other non-human driven scripts or services.

A service account identity can either be based on a user entry in your IdP Directory, or exist as a custom identity managed in a Pomerium Console [Namespace](#namespaces).

## Routes

Routes define the connection pathway and configuration from the internet to your internal service. As a very basic level, a route sends traffic from `external-address.company.com` to `internalService-address.localdomain`, restricted by the policies associated with it, and encrypted by your TLS certificates. But more advanced configurations allow identity header pass-through, path and prefix rewrites, request and response header modification, load balancer services, and other full featured ingress capabilities.

For more information, see [Reference: Routes]

### Protected Endpoints

This term refers to the system or service the route provides or restricts access to.

### Moving Routes

When moving a Route from one [Namespace](#namespaces) to another, enforced policies will automatically be removed or applied. Optional policies available in the source Namespace but not the target will prevent the move. This is intentional to prevent unassociated policies.

## Policies

A Policy defines who has access to what based on the identity of the user, their device, and the associated request context.

Policies can be applied to [Routes](#routes) directly, or enforced within a [Namespace](#namespaces). Policies allow operators to add authorization and access control to a single, or collection of routes.

To learn more about how to create Policies in Pomerium Enterprise, see [Reference: Policies].

## Access control

Authentication and authorization are similar concepts that are often used interchangeably.

**Authentication** is the process of determining if you are who you say you are.

**Authorization** is the process of determining if you are allowed to do the thing you are trying to do.

Pomerium provides a standardized interface to add access control, regardless if an application itself has authorization or authentication baked in, so developers can focus on their app's functionality, not reinventing access control.

### Authentication

Pomerium provides authentication via your existing identity provider (Pomerium supports all major [single sign-on](/docs/identity-providers/readme.md) providers (Okta, G Suite, Azure, AD, Ping, Github and so on).

### Authorization

Authorization policy can be expressed in a high-level, [declarative language](/enterprise/reference/manage.md#pomerium-policy-language) or [as code](/enterprise/reference/manage.md#rego) that can be used to enforce ABAC, RBAC, or any other governance policy controls. Pomerium can make holistic policy and authorization decisions using external data and request context factors such as user groups, roles, time, day, location and vulnerability status.

Pomerium enables zero-trust based access in which trust flows from identity, device-state, and context, not network location. Every device, user, and application's communication should be authenticated, authorized, and encrypted.

With Pomerium:

- requests are continuously re-evaluated on a per-request basis.
- authorization is identity and context aware; pomerium can be used to integrate data from any source into authorization policy decisions.
- trust flows from user and device identity, not network location. Every device, user, and application's communication should be authenticated, authorized, and encrypted.
- Pomerium provides detailed audit logs for all activity in your environment. Quickly detect anomalies to mitigate bad actors and revoke access with a click of a button. Simplify life-cycle management and access reviews.

[Reference: Policies]: /enterprise/reference/manage.md#policies-2
[Reference: Namespace]: /enterprise/reference/configure.md#namespaces
[Reference: Routes]: /enterprise/reference/manage.md#routes