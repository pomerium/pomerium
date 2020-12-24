---
title: Single Sign-out
description: >-
  This article describes Pomerium's support for Single Sign-out
---

# Single Sign-out

Single Sign-out enables the session termination on multiple software systems by logging out from a single logout gateway.


## OIDC Front-Channel Logout

Pomerium supports Front-Channel Logout as described in [OpenID Connect Front-Channel Logout 1.0 - draft 04](https://openid.net/specs/openid-connect-frontchannel-1_0.html).


### Provider Support

To find out if your idP supports Front-Channel Logout have a look at the at the
`/.well-known/openid-configuration`. On standard compliant providers it would contain:
```json
{
  "frontchannel_logout_session_supported": true
}
```


### Configuration

You need to register a `frontchannel_logout_uri` in your OAuth 2.0 Client settings.
The url gets handled by the Authenticate Service under the path `/.pomerium/frontchannel-logout` (e.g `https://authenticate.corp.example.com/.pomerium/frontchannel-logout`).
