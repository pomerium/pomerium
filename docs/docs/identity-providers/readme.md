---
title: Overview
description: >-
  This article describes how to connect Pomerium to third-party identity
  providers / single-sign-on services. You will need to generate keys, copy
  these into your Pomerium settings, and enable the connection.
---

# Identity Provider Configuration

This article describes how to configure Pomerium to use a third-party identity service for single-sign-on.

There are a few configuration steps required for identity provider integration. Most providers support [OpenID Connect] which provides a standardized identity and authentication interface.

In this guide we'll cover how to do the following for each identity provider:

1. Set a **[Redirect URL](https://www.oauth.com/oauth2-servers/redirect-uris/)** pointing back to Pomerium. For example, `https://${authenticate_service_url}/oauth2/callback`.
2. Generate a **[Client ID]** and **[Client Secret]**.
3. Generate a **[Service Account]** for additional IdP Data.
4. Configure Pomerium to use the **[Client ID]** and **[Client Secret]** keys.
5. Configure Pomerium to synchronize directory data from your identity provider (e.g. groups membership), by setting a service account. 

:::warning

You must configure an IdP **[Service Account]** to write policy against group membership, or any other data that does not uniquely identify an end-user.

[client id]: ../../configuration/readme.md#identity-provider-client-id
[client secret]: ../../configuration/readme.md#identity-provider-client-secret
[environmental variables]: https://en.wikipedia.org/wiki/Environment_variable
[oauth2]: https://oauth.net/2/
[openid connect]: https://en.wikipedia.org/wiki/OpenID_Connect
[service account]: ../../configuration/#identity-provider-service-account

