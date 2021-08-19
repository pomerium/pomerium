---
title: Overview
description: >-
  This article describes how to connect Pomerium to third-party identity
  providers / single-sign-on services. You will need to generate keys, copy
  these into your Pomerium settings, and enable the connection.
---

# Identity Provider Configuration

Pomerium helps provide a zero-trust security model by verifying that every request to your upstream applications are from an authenticated and authorized user. User and group information is sourced from your Identity Provider (**IdP**). Pomerium communicates with IdPs following the [OpenID Connect][openid connect] (**OIDC**) standard for user identity, and a service account and/or API token for group/directory information. The steps for integrating Pomerium with an IdP are specific to each provider, but they generally share the same base requirements:

- A **[Redirect URL](https://www.oauth.com/oauth2-servers/redirect-uris/)** pointing back to Pomerium. For example, `https://${authenticate_service_url}/oauth2/callback`.
- A **[Client ID]** and **[Client Secret]**.
- A **[Service Account]** for additional IdP Data. This is enables Pomerium administrators to write policies around groups, or any other data that doesn't uniquely identify an end-user, as defined in the IdP.
   - Depending on the IdP, a service account may have its own client id and secret, or require an API token. Pomerium handles this by accepting values for `idp_service_account` as a base64-encoded json object with the correct key/value pairs for each IdP supported.

The subsequent pages in this section provide specific instructions for the IdPs Pomerium supports.

[client id]: ../../reference/readme.md#identity-provider-client-id
[client secret]: ../../reference/readme.md#identity-provider-client-secret
[environmental variables]: https://en.wikipedia.org/wiki/Environment_variable
[oauth2]: https://oauth.net/2/
[openid connect]: https://en.wikipedia.org/wiki/OpenID_Connect
[service account]: ../../reference/readme.md#identity-provider-service-account


