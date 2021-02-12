---
title: Single Sign-out
description: >-
  This article describes Pomerium's support for Single Sign-out according to
  OpenID Connect Front-Channel Logout 1.0.
---

# Single Sign-out

Single Sign-out enables session termination on multiple software systems via a single logout endpoint.

## OIDC Front-Channel Logout

Pomerium supports Front-Channel Logout as described in [OpenID Connect Front-Channel Logout 1.0 - draft 04](https://openid.net/specs/openid-connect-frontchannel-1_0.html).

### Provider Support

To find out if your identity provider (IdP) supports Front-Channel Logout, have a look at the at your IdP's `/.well-known/openid-configuration` endpoint. On standard compliant providers it would contain:

```json
{
  "frontchannel_logout_session_supported": true
}
```

### Configuration

You need to register a `frontchannel_logout_uri` in your OAuth 2.0 Client settings. The url gets handled by the Authenticate Service under the path `/.pomerium/sign_out` (e.g `https://authenticate.localhost.pomerium.io/.pomerium/sign_out`).


### The endpoint

See Pomerium's `/.well-known/pomerium` endpoint for the sign-out page's uri. For example,

```json
{
  "authentication_callback_endpoint": "https://authenticate.localhost.pomerium.io/oauth2/callback",
  "jwks_uri": "https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json",
  "frontchannel_logout_uri": "https://authenticate.localhost.pomerium.io/.pomerium/sign_out"
}
```

Note, a CSRF token is required for the single sign out endpoint (despite supporting `GET` and `POST`) and can be retrieved from the
`X-CSRF-Token` response header on the well known endpoint above or using the `_pomerium_csrf` session set.

