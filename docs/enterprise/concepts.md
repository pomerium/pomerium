---
title: Concepts
sidebarDepth: 1
description: Learn how the Pomerium Enterprise Console works.
---

# Concepts

## Namespaces

In the Pomerium Enterprise Console, a namespace is where you can define an organizational unit of users and groups with fine-grained access management. This enables teams to self-service the routes and policies pertinent to them. Namespaces can optionally inherit from their parent units.

<!-- @alexfornuto This is rough but the high level points; some are repeats of what you've already said -->

**Namespaces** are the cornerstone organizational unit in Pomerium Enterprise. Namespaces enable:

- self-service
- hierarchical policy enforcement (both enforced, and optional)
- policy organization
- RBAC for the Enterprise Console itself

<!-- you'll notice that each of these sub-concepts are related and more or less build on eachother -->
### Self-Service Capabilities

One of the benefits of an identity-aware access proxy is that, once in place, developers and owners of enterprise applications have an incentive to configure their services to be accessible via the proxy.

Self-service has [several benefits](https://www.usenix.org/system/files/login/articles/login_winter16_05_cittadini.pdf):

- Frees global administrators from continuously modifying the configuration per user requests
- Encourages service owners to own their configuration fragment
- Ensures a reasonable compromise between development velocity and security controls

Unlike with a VPN, or network driven access control mechanisms, application owners (with limited access permissions managed through namespaces) can maintain route and policy configuration for their own services, while  higher level operations, security, and identity teams are able to enforce higher level authorization and access policies.

### Hierarchical Policy Enforcement

<!-- @alexfornuto this but prosier-er
Hierarchical policy lets administrators enforce high level authorization policy. Policies can be optional (self-select), or mandatory. This goes hand in hand with self-service as mentioned above. I usually explain this concept from the point of view of multiple teams within an organization. A security team managing very high level, coarse grain authorization controls (e.g. you know that everyone touching internal resource at least has a `foo.com` email account, and isn't coming from North Korea), allows identity and access management teams (IAM) to say what groups or organizational units should have access to what resources, apps, and services, and finally application owners who -- because of policy enforcement -- can be given enough flexibility to self-manage their own route (application) and policy via self service.
 -->

### RBAC for Enterprise Console Users

<!-- @alexfornuto this needs to be made into better prose. See https://www.notion.so/pomerium/Permissions-Access-Control-e32ff518f1564b3698d13611c449b436#c82026f2a45b48a9a16c47d6e5fefea3 for a good background doc by @travisgroth

- Namespaces are also used to achieve Role Based Access Control (RBAC) in the console itself .
- There are three different roles (viewer, manager, and admin). Maybe an explanation of each as described here: https://www.notion.so/pomerium/Permissions-Access-Control-e32ff518f1564b3698d13611c449b436#58da053dbc4d452ca4d202664b1626b9

 -->

## Service Accounts

Service accounts handle machine-to-machine communication from Pomerium to your Identity Provider (**IdP**) in order to retrieve and establish group membership. Configuration is largely dependent on the IdP, but is usually an API access token with sufficient privileges to read users and groups.

<!-- @travisgroth -- could you add some context in here? I think your PRD on service accounts would be super helpful and you know this concept best-->

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

In the Pomerium Enterprise Console, [routes](#routes) and policies are separate entities. This allows for both easier and more fine-grained access control, as policies can be defined once, optionally associated under a [Namespace](#namespaces), and attached to one or more routes. Routes can also inherit policies from their parent Namespace <!-- @Travis please confirm --> .


<!-- @alexfornuto this but prosier
## Access control


Authentication and authorization are similar concepts that are often used interchangeably. Authentication is the process of determining if you are who you say you are. Authorization is the process of determining if you are allowed to do the thing you are trying to do. A silly analogy is, authentication is the bouncer checking your ID; authorization is the bouncer seeing if your name is on the list.

Pomerium provides a standardized interface to add access control whether an application itself has authorization or authentication baked-in so that developers can focus on their apps, not reinventing access control.

### Authentication

Pomerium provides authentication vis-a-via your existing identity provider (Pomerium support [all the major single sign-on](https://www.pomerium.io/docs/identity-providers/) on providers (Okta, Gsuite, Azure, AD, Ping, Github and so on).
### Authorization

Authorization policy can be expressed in a high-level, declarative language (link to ppl docs) or as code (link to Rego docs) that can be used to enforce ABAC, RBAC, or any other governance policy controls. Pomerium can make holistic policy and authorization decisions using external data and request context factors such as user groups, roles, time, day, location and vulnerability status

Trust flows from identity, device-state, and context, not network location. Every device, user, and application's communication should be authenticated, authorized, and encrypted.



Authorization is where Pomerium's value proposition really lies. Pomerium:
- ability to express authorization policy as declarative policy (PPL) or as code (rego)
- requests are continuously re-evaluated on a per-request basis.
- authorization is identity and context aware; pomerium can be used to integrate data from any source into authorization policy decisions
- Trust flows from identity, device-state, and context, not network location. Every device, user, and application's communication should be authenticated, authorized, and encrypted.
- Pomerium provides detailed audit logs for all activity in your environment. Quickly detect anomalies to mitigate bad actors and revoke access with a click of a button. Simplify lifecycle management and access reviews. -->
