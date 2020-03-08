---
title: Getting the user's identity
description: >-
  This article describes how to to get a user's identity with Pomerium.
---

# Getting the user's identity

This article describes how to retrieve a user's identity from a pomerium managed application.

## Headers

By default, pomerium passes the following [response headers] to it's downstream applications to identify the requesting users.

| Header                                 | description                                                    |
| :------------------------------------- | -------------------------------------------------------------- |
| `x-pomerium-authenticated-user-id`     | Subject is the user's id.                                      |
| `x-pomerium-authenticated-user-email`  | Email is the user's email.                                     |
| `x-pomerium-authenticated-user-groups` | Groups is the user's groups.                                   |
| `x-pomerium-jwt-assertion`             | **Recommended** Contains the user's details as a signed [JWT]. |

In an ideal environment, the cryptographic authenticity of the user's identifying headers should be enforced at the protocol level using mTLS.

### Recommended : Signed JWT header

For whatever reason, (e.g. an attacker bypasses pomerium's protocol encryption, or it is accidentally turned off), it is possible that the `x-pomerium-authenticated-user-{email,id,groups}` headers could be forged. Therefore, it is highly recommended to use and validate the [JWT] assertion header which adds an additional layer of authenticity.

Verify that the [JWT assertion header](./signed-headers.md) conforms to the following constraints:

|  [JWT]   | description                                                                                            |
| :------: | ------------------------------------------------------------------------------------------------------ |
|  `exp`   | Expiration time in seconds since the UNIX epoch. Allow 1 minute for skew.                              |
|  `iat`   | Issued-at time in seconds since the UNIX epoch. Allow 1 minute for skew.                               |
|  `aud`   | The client's final domain e.g. `httpbin.corp.example.com`.                                             |
|  `iss`   | Issuer must be `pomerium-proxy`.                                                                       |
|  `sub`   | Subject is the user's id. Can be used instead of the `x-pomerium-authenticated-user-id` header.        |
| `email`  | Email is the user's email. Can be used instead of the `x-pomerium-authenticated-user-email` header.    |
| `groups` | Groups is the user's groups. Can be used instead of the `x-pomerium-authenticated-user-groups` header. |

[jwt]: https://jwt.io
[response headers]: https://developer.mozilla.org/en-US/docs/Glossary/Response_header
