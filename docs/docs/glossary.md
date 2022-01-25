---
title: Glossary
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy beyondcorp zero-trust reverse-proxy ztn zta
description: A quick reference of commonly used terms.
---

# Glossary

Pomerium's documentation uses a lot of terminology specific to the networking and security space. This glossary defines common terms readers may be unfamiliar with. If you come across an unfamiliar term not listed in this page, please let us know in our [Discuss support forum][support] and we'll add it.

[[toc]]

## General

### Access Token
This general term refers to a string that validates the holder to have a specific set of permissions, issued by an identifying service like an [identity provider]. Most of the access tokens discussed in our docs are [JSON Web Tokens (**JWTs**)][JWT] formatted following the [Oauth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749#section-7.1).

### Identity Provider
An identity provider (**IdP**) is used to [authenticate] a user, i.e. confirm their identity. Pomerium uses external IdPs to better integrate into existing environments and to achieve strong separation of services. Pomerium provides [single sign-on] from your IdP to your entire network infrastructure from a single location.

### Identity-aware Proxy
A [proxy](https://en.wikipedia.org/wiki/Proxy_server) is an intermediate service between one or more clients or servers. Most of the proxies discussed in our docs are technically [reverse proxies](https://en.wikipedia.org/wiki/Reverse_proxy), sitting between one or more servers and all clients, providing a single point of ingress into a system.

An identity-aware proxy can provide contextual access to specific services based on the identity of the client. In Pomerium's case, identity is provided by the client in the form of a [JWT] issued by the [identity provider].

### JavaScript Object Notation
Commonly shortened to **JSON**, [JavaScript object notation](https://en.wikipedia.org/wiki/JSON) is a common format used to represent and share structured sets of data as arrays of key-value pairs.

### JSON Web Key Sets
Usually abbreviate as **JWKS**, this is a [JSON]-formatted set of one or more keys provided by a trusted issuer and used by service to verify [JWTs] provided by a client. Formatting is defined by the [JSON Web Key RFC](https://datatracker.ietf.org/doc/html/rfc7517).

### JSON Web Token
Often referred to as **JWTs**, a JSON web token is a [JSON]-formatted string provided to a user by an [identity provider], which validates the user's identity to subsequent services (such as an [identity-aware proxy]). JWTs are formatted according to the [JSON Web Token RFC](https://datatracker.ietf.org/doc/html/rfc7519)

### Namespace
"Namespaces" is an over-saturated term, having different meanings in different contexts. [Pomerium Enterprise][pom-namespace] uses Namespaces to provide separation of access and control to [routes]. Kubernetes uses their [namespaces][k8s-namespace] to isolate groups of resources within a cluster.

### Perimeter
The term "Perimeter" in the context of Pomerium and general networking usually refers to your internal network, and common tools like firewalls used to restrict access to it. [Historically](/docs/background.md#history), most security models used the perimeter as the main layer of protection to a network system. The principles of [zero trust] assume that the perimeter can be (and likely is) compromised, and require security between each connection, including those between internal services.

### Policy
Pomerium allows administrators to define authorization policies dictating what combination of users, groups, devices, etc, have access to protected services. Open-source Pomerium defines a unique policy to every [route], while Pomerium Enterprise can define reusable policies at the global and [namespace] level.

### Route
Specific to Pomerium, a route is a defined path from outside the network (via a public domain) to an internal service. Routes can be defined in the [configuration](/reference/readme.md#routes) for open-source Pomerium or the [Pomerium Enterprise Console][pom-routes].

### Single Sign-On
Single Sign-On (**SSO**) is the most frequently asked for requirement by enterprise organizations looking to adopt new SaaS applications. SSO enables authentication via an organization’s [identity provider], such as [Google Workspace](/docs/identity-providers/google.md) or [Okta](/docs/identity-providers/okta.md), as opposed to users or IT admins managing hundreds, if not thousands, of usernames and passwords.

## Networking

### Custom Resource Definition
A custom resource definition (**CRD**) defines a custom resource that extends the Kubernetes API to provide additional functionality specific to a custom software set. For example, [cert-manager](https://cert-manager.io/) defines certificate issuers [using a CRD](https://github.com/cert-manager/sample-external-issuer/blob/main/config/crd/bases/sample-issuer.example.com_issuers.yaml).

### East-west Traffic
[East-west traffic](https://en.wikipedia.org/wiki/East-west_traffic) refers to network communication between services within an internal network, Kubernetes cluster, private cloud network, etc. This term differentiates this communication from [north-south traffic].

### HTTP Strict Transport Security
Usually shortened to **HSTS**, this is a policy whereby a site secured with [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) provides a response header defining a period of time (usually set to a year or more) during which the browser should only access the server over TLS, and only when it provides the same certificate. This policy helps mitigate man-in-the-middle (**MiTM**) attacks. We suggest only defining an HSTS policy after a service has been fully configured and tested to avoid issues when switching from development to production certificates.

### North-south Traffic
[North-south traffic](https://en.wikipedia.org/wiki/North-south_traffic) refers to network communication from end users to services within an internal network, Kubernetes cluster, private cloud network, etc. This term differentiates this communication from [east-west traffic].

### Upstream / Downstream
When discussing traffic between end users and services, we use "upstream" to refer to the services and/or service mesh that Pomerium protects & secures. Inversely, "downstream" refers to traffic between Pomerium and end users, or any other party connecting from the Internet.

## Security

### Authentication
Abbreviated as **AuthN**, this refers to the validation of a user's identity. It can also refer to validation of an user's [device](/docs/topics/device-identity.md). Access to a protected resource is usually granted only after a client's authentication and [authorization] are validated. This is usually done by verifying the [JWT] provided by the client.

### Authorization
Abbreviated as **AuthZ**, authorization is the process of validating a client's access to a protected resource. This is usually done after a client as been [authenticated], and is determined by comparing the contents of the clients [JWT] against the [policies] present for the [route].

### Least User Privilege
"Least user privilege" is a core concept of the [zero trust] model. It's the practice of only providing a user as much access to protected systems as is required for them to operate in their job's function. This is a risk-mitigation strategy; since compromised user credentials can only be used to access services they are granted access to, users that do not need access to highly sensitive services should not have them.

### Mutual Authentication
Mutual authentication is the security strategy of having both sides of a connection validate the identity of the other. This reduces the possibility of bad actors to impersonate valid communication endpoints. This topic is discussed in detail in [Mutual Authentication: A Component of Zero Trust](/docs/topics/mutual-auth.md).

### Secure Enclave
A Secure Enclave is a sub-component or device physically bound to a specific device that can safely store sensitive data used to validate [device identity](/docs/topics/device-identity.md).

### Security Keys
Security keys are often used to provide a physical resource to perform multi-factor authentication (**MFA**). Common examples include Yubico's Yubikey and Google's Titan Security Key.

### Trusted Execution Environment
A **TEE** is a physical method of executing cryptographic functions using data that cannot be accessed by the rest of the physical device. This is a core part of [device identity](/docs/topics/device-identity.md) validation.

### Zero Trust
Zero trust is a philosophy and/or framework for security models that includes several facets. We go into detail in our [Background](/docs/background.md#zero-trust) page, but briefly: zero-trust assumes that any one method of security is fallible, and defines a set of security principles that work in concert to provide the highest security without over-burdening administrators, end users, or network devices with extraneous overhead.

[authenticate]: #authentication
[authenticated]: #authentication
[authorization]: #authorization
[east-west traffic]: #east-west-traffic
[identity provider]: #identity-provider
[identity-aware proxy]: #identity-aware-proxy
[JSON]: #javascript-object-notation
[JWT]: #json-web-token
[JWTs]: #json-web-token
[k8s-namespace]: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
[namespace]: #namespace
[north-south traffic]: #north-south-traffic
[policies]: #policy
[Pomerium Enterprise]: /enterprise/about.md
[pom-namespace]: /enterprise/concepts.md#namespaces
[pom-routes]: /enterprise/concepts.md#routes
[route]: #route
[routes]: #route
[single sign-on]: #single-sign-on
[support]: https://discuss.pomerium.com/c/support/9
[zero trust]: #zero-trust