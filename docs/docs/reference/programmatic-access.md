---
title: Programmatic access
description: >-
  This article describes how to configure pomerium to be used to enable
  machine-to-machine programmatic access.
---

# Programmatic access

This page describes how to obtain Pomerium access credentials programmatically via a web-based oauth2 based authorization flow. If you have ever used Google's `gcloud` commandline app, the mechanism is very similar.

## Components

### Login API

The API returns a signed, sign-in url that can be used to complete a user-driven login process with Pomerium and your identity provider. The Login API endpoints takes a `redirect_uri` query param as an argument which points to the location of the callback server to be called following a successful login.

For example:

```bash
$ curl "https://httpbin.example.com/.pomerium/api/v1/login?redirect_uri=http://localhost:8000"

https://authenticate.example.com/.pomerium/signin?redirect_uri=http%3A%2F%2Flocalhost%3Fpomerium_callback_uri%3Dhttps%253A%252F%252Fhttpbin.corp.example%252F.pomerium%252Fapi%252Fv1%252Flogin%253Fredirect_uri%253Dhttp%253A%252F%252Flocalhost&sig=hsLuzJctmgsN4kbMeQL16fe_FahjDBEcX0_kPYfg8bs%3D&ts=1573262981
```

### Callback handler

It is the script or application's responsibility to create a HTTP callback handler. Authenticated sessions are returned in the form of a [callback](https://developer.okta.com/docs/concepts/auth-overview/#what-kind-of-client-are-you-building) from pomerium to a HTTP server. This is the `redirect_uri` value used to build Login API's URL, and represents the URL of a (usually local) http server responsible for receiving the resulting user session in the form of `pomerium_jwt` and `pomerium_refresh_token` query parameters.

See the python script below for example of how to start a callback server, and store the session payload.

### Refresh API

The Refresh API allows for a valid refresh token enabled session, using an `Authorization: Pomerium` bearer token, to refresh the current user session and return a new user session (`jwt`) and refresh token (`refresh_token`). If successfully, a new updated refresh token and identity session are returned as a json response.

```bash
$ curl \
	-H "Accept: application/json" \
	-H "Authorization: Pomerium $(cat cred-from-above-step.json | jq -r .refresh_token)" \
	https://authenticate.example.com/api/v1/refresh

{
  "jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token":"fXiWCF_z1NWKU3yZ...."
}

```

:::tip
Note that the Authorization refresh token is set to Authorization `Pomerium` _not_ `Bearer`.
:::

## Handling expiration and revocation

Your application should handle token expiration. If the session expires before work is done, the identity provider issued `refresh_token` can be used to create a new valid session.

Also, your script or application should anticipate the possibility that a granted `refresh_token` may stop working. For example, a refresh token might stop working if the underlying user changes passwords, revokes access, or if the administrator removes rotates or deletes the OAuth Client ID.

## High level workflow

The application interacting with Pomerium must manage the following workflow. Consider the following example where a script or program desires delegated, programmatic access to the domain `httpbin.corp.domain.example`:

1. The script or application requests a new login url from the pomerium managed endpoint (e.g. `https://httpbin.corp.domain.example/.pomerium/api/v1/login`) and takes a `redirect_uri` as an argument.
1. The script or application opens a browser or redirects the user to the returned login page.
1. The user completes the identity providers login flow.
1. The identity provider makes a callback to pomerium's authenticate service (e.g. `authenticate.corp.domain.example`) .
1. Pomerium's authenticate service creates a user session and redirect token, then redirects back to the managed endpoint (e.g. `httpbin.corp.domain.example`)
1. Pomerium's proxy service and makes a callback request to the original `redirect_uri` with the user session and refresh token as arguments.
1. The script or application is responsible for handling that http callback request, and securely handling the callback session (`pomerium_jwt`) and refresh token (`pomerium_refresh_token`) queryparams.
1. The script or application can now make any requests as normal, by setting the `Authorization: Pomerium ${pomerium_jwt}` header.
1. If the script or application encounters a `401` error or token expiration error, the script or application can make a request the authenticate service's refresh api endpoint (e.g. `https://authenticate.corp.domain.example/api/v1/refresh`) with the `Authorization: Pomerium ${pomerium_refresh_token}` header. Note that the refresh token is used, not the user session jwt. If successful, a new user session jwt and refresh token will be returned and requests can continue as before.

## Example Code

Please consider see the following minimal but complete python example.

```bash
python3 scripts/programmatic_access.py \
	--dst https://httpbin.example.com/headers \
	--refresh-endpoint https://authenticate.example.com/api/v1/refresh
```

<<< @/scripts/programmatic_access.py

[authorization bearer token]: https://developers.google.com/gmail/markup/actions/verifying-bearer-tokens
[identity provider]: ../identity-providers/readme.md
[proof key for code exchange]: https://tools.ietf.org/html/rfc7636
