---
title: Programmatic access
description: >-
  This article describes how to configure pomerium to be used to enable
  machine-to-machine programmatic access.
---

# Programmatic access

This page describes how to obtain Pomerium access credentials programmatically via a web-based oauth2 style authorization flow. If you have ever used Google's `gcloud` commandline app, the mechanism is very similar.

## Components

### Login API

The API returns a cryptographically signed sign-in url that can be used to complete a user-driven login process with Pomerium and your identity provider. The login API endpoint takes a `pomerium_redirect_uri` query parameter as an argument which points to the location of the callback server to be called following a successful login.

For example:

```bash
$ curl "https://verify.example.com/.pomerium/api/v1/login?pomerium_redirect_uri=http://localhost:8000"

https://authenticate.example.com/.pomerium/sign_in?pomerium_redirect_uri=http%3A%2F%2Flocalhost%3Fpomerium_callback_uri%3Dhttps%253A%252F%verify.corp.example%252F.pomerium%252Fapi%252Fv1%252Flogin%253Fpomerium_redirect_uri%253Dhttp%253A%252F%252Flocalhost&sig=hsLuzJctmgsN4kbMeQL16fe_FahjDBEcX0_kPYfg8bs%3D&ts=1573262981
```

By default only `localhost` URLs are allowed as the `pomerium_redirect_uri`. This can be customized with the `programmatic_redirect_domain_whitelist` option.

### Callback handler

It is the script or application's responsibility to create a HTTP callback handler. Authenticated sessions are returned in the form of a [callback](https://developer.okta.com/docs/concepts/auth-overview/#what-kind-of-client-are-you-building) from pomerium to a HTTP server. This is the `pomerium_redirect_uri` value used to build login API's URL, and represents the URL of a (usually local) HTTP server responsible for receiving the resulting user session in the form of `pomerium_jwt` query parameters.

See the python script below for example of how to start a callback server, and store the session payload.

## Handling expiration and revocation

Your script or application should anticipate the possibility that your underlying  `refresh_token` may stop working. For example, a refresh token might stop working if the underlying user changes passwords, revokes access, or if the administrator removes rotates or deletes the OAuth Client ID.

## High level workflow

The application interacting with Pomerium must manage the following workflow. Consider the following example where a script or program desires delegated, programmatic access to the domain `verify.corp.domain.example`:

1. The script or application requests a new login url from the pomerium managed endpoint (e.g. `https://verify.corp.domain.example/.pomerium/api/v1/login`) and takes a `pomerium_redirect_uri` as an argument.
1. The script or application opens a browser or redirects the user to the returned login page.
1. The user completes the identity providers login flow.
1. The identity provider makes a callback to pomerium's authenticate service (e.g. `authenticate.corp.domain.example`) .
1. Pomerium's authenticate service creates a user session and redirect token, then redirects back to the managed endpoint (e.g. `verify.corp.domain.example`)
1. Pomerium's proxy service makes a callback request to the original `pomerium_redirect_uri` with the user session and as an argument.
1. The script or application is responsible for handling that http callback request, and securely handling the callback session (`pomerium_jwt`) queryparam.
1. The script or application can now make any requests as normal to the upstream application by setting the `Authorization: Pomerium ${pomerium_jwt}` header.

:::tip
Pomerium supports `Authorization: Bearer Pomerium-${pomerium_jwt}` in addition to `Authorization: Pomerium ${pomerium_jwt}` format.
:::

## Example Code

Please consider see the following minimal but complete python example.

```bash
python3 scripts/programmatic_access.py \
	--dst https://verify.example.com/headers
```

<<< @/scripts/programmatic_access.py

[authorization bearer token]: https://developers.google.com/gmail/markup/actions/verifying-bearer-tokens
[identity provider]: ../identity-providers/readme.md
[proof key for code exchange]: https://tools.ietf.org/html/rfc7636
