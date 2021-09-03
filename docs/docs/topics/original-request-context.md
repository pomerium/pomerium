---
title: Original User Context
description: This article describes how the original user context is passed secondary requests.
---

# Original User Context

::: tip
This article describes a use case available to [Pomerium Enterprise](/enterprise/about.md) customers.
:::

In enterprise environments where multiple services protected by Pomerium communicate with each other using a [service account](/enterprise/concepts.md#service-accounts), there are scenarios where the original user context must be preserved. This article describes how this is accomplished with the `X-Pomerium-Jwt-Assertion-For` header.

## Abstract

Let's look at two example routes, App and API:

```yaml
routes:
  - name: App
    from: https://app.localhost.pomerium.io
    to: https://appserver.local
    pass_identity_headers: true
    policy:
      - allow:
          or:
            - domain:
                is: companydomain.com
  - name: API
    from: https://api.localhost.pomerium.io
    to: https://apiserver.local
    pass_identity_headers: true
    policy:
      - allow:
          or:
            - user:
                is: api-access
```

- **App** is a user-facing application. Users connect to it through Pomerium.
- **API** is also accessed through it's Pomerium Route, but is only accessible by the **App**, using a [service account](/enterprise/concepts.md#service-accounts) to authenticate.
- The **API** service needs to know the user making the request to **App** in order to return the needed 

Both Routes include [`pass_identity_headers`](/reference.md#pass-identity-headers), which provides (at minimum) the `X-Pomerium-Jwt-Assertion` header to the downstream application.

- When a user connects to **App** to perform an action, `X-Pomerium-Jwt-Assertion` provides the service with the Json Web Token (**JWT**) for the user.
- When **App** sends a request to **API**, `X-Pomerium-Jwt-Assertion` is provided for the service account.
- Pomerium copies the original user context, the JWT from the user, to `X-Pomerium-Jwt-Assertion-For` and includes it in the request to **API**

Now the **API** can service can read `X-Pomerium-Jwt-Assertion-For` as needed to determine the proper response to send.
