---
title: Programmatic access
description: >-
  This article describes how to configure pomerium to be used to enable
  machine-to-machine programmatic access.
---

# Programmatic access

This page describes how to access Pomerium endpoints programmatically.

## Configuration

Every identity provider has slightly different methods for issuing OAuth 2.0 access tokens [suitable][proof key for code exchange] for machine-to-machine use, please review your identity provider's documentation. For example:

- [Google Oauth2 2.0 for Desktop Apps](https://developers.google.com/identity/protocols/OAuth2InstalledApp)
- [Okta PKCE Flow](https://developer.okta.com/docs/concepts/auth-overview/#authorization-code-flow)
- [Azure Active Directory using the OAuth 2.0 code grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code)

For the sake of illustration, this guide and example scripts will use Google as the underlying identity provider.

### Identity Provider Configuration

To configure programmatic access for Pomerium we'll need to set up **an additional** OAuth 2.0 client ID that can issue `id_tokens` whose [audience](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) matches the Client ID of Pomerium. Follow these instructions adapted from [Google's documentation](https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_a_desktop_app):

1. Go to the [Credentials page](https://console.cloud.google.com/apis/credentials).
2. Select the project with the Pomerium secured resource.
3. Click **Create credentials**, then select **OAuth Client ID**.
4. Under **Application type**, select **Other**, add a **Name**, then click **Create**.
5. On the OAuth client window that appears, note the **client ID** and **client secret**.
6. On the **Credentials** window, your new **Other** credentials appear along with the primary client ID that's used to access your application.

### High level flow

The application interacting with Pomerium will roughly have to manage the following access flow.

1. A user authenticates with the OpenID Connect identity provider. This typically requires handling the [Proof Key for Code Exchange] process.
2. Exchange the code from the [Proof Key for Code Exchange] for a valid `refresh_token`.
3. Using the `refresh_token` from the last step, request the identity provider issue a new `id_token` which has our Pomerium app's `client_id` as the `audience`.
4. Exchange the identity provider issued `id_token` for a `pomerium` token (e.g. `https://authenticate.{your-domain}/api/v1/token`).
5. Use the pomerium issued `Token` [authorization bearer token] for all requests to Pomerium protected endpoints until it's `Expiry`. Authorization policy will be tied to the user as normal.

### Expiration and revocation

Your application should handle token expiration. If the session expires before work is done, the identity provider issued `refresh_token` can be used to create a new valid session by repeating steps 3 and on.

Also, you should write your code to anticipate the possibility that a granted `refresh_token` may stop working. For example, a refresh token might stop working if the underlying user changes passwords, revokes access, or if the administrator removes rotates or deletes the OAuth Client ID.

## Example Code

It's not as bad as it sounds. Please see the following minimal but complete examples.

### Python

```bash
python scripts/programmatic_access.py --client-secret REPLACE_ME \
    --client-id 851877082059-85tfqg9hlm8j9km5d9uripd0dvk72mvk.apps.googleusercontent.com \
    --pomerium-client-id 851877082059-bfgkpj09noog7as3gpc3t7r6n9sjbgs6.apps.googleusercontent.com
```

<<< @/scripts/programmatic_access.py

### Bash

<<< @/scripts/programmatic_access.sh

[authorization bearer token]: https://developers.google.com/gmail/markup/actions/verifying-bearer-tokens
[identity provider]: ../docs/identity-providers.md
[proof key for code exchange]: https://tools.ietf.org/html/rfc7636
