---
title: User impersonation
description: >-
  This article describes how to configure Pomerium to allow an administrative
  user to impersonate another user or group.
---

# User Impersonation & Service Accounts

## What

User impersonation and service accounts enables administrative users to temporarily "sign in as" another user in pomerium. Users with impersonation permissions can impersonate all other users and groups. The impersonating user will be subject to the authorization and access policies of the impersonated user.

## Why

In certain circumstances, it's useful for an administrative user to impersonate another user. For example:

- To help a user troubleshoot an issue. If your downstream authorization policies are configured differently, it's possible that your UI will look different from theirs and you'll need to impersonate the other user to be able to see what they see.
- You want to make changes on behalf of another user (for example, the other user is away on vacation and you want to manage their orders or run a report).
- You're an administrator who's setting up authorization policies, and you want to preview what other users will be able to see depending on the permissions you grant them.

## How

There are two mechanisms for doing user impersonation or service account generation. The first, is using the web-interface using the special (`/.pomerium`) endpoint, and the second is by using an included command line interface tool.

### Using the web-interface

Pomerium contains an endpoint that allows administrators to impersonate a user, and/or their groups.

1. Add an administrator to your [configuration settings].
2. Navigate to user dashboard for any proxied route. (e.g. `https://{your-domain}/.pomerium`)
3. Add the `email` and `user groups` you want to impersonate.
4. That's it!

::: warning

**Note!** On session refresh, impersonation will be reset.

:::

Here's what it looks like.

<video width="100%" height="600" controls=""><source src="./img/pomerium-user-impersonation.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>

### Using the command line interface

Pomerium also includes a command line interface (cli) for generating arbitrary route-scoped service account sessions. Generated service accounts can be used to impersonate users, perform service-to-service communication, and facilitate end-to-end testing for applications managed by Pomerium. The cli is especially useful in situations where an administrator needs more control over the sessions she generates, or if skipping the authentication portion of pomerium's flow is required.

### How

```bash
pomerium-cli generates a pomerium service account from a shared key.

Usage: /bin/pomerium-cli [flags] [base64d shared secret setting]

For additional help see:

    https://www.pomerium.io
    https://jwt.io/

Flags:

  -aud value
        Audience (e.g. httpbin.int.pomerium.io,prometheus.int.pomerium.io)
  -email string
        Email
  -expiry duration
        Expiry (default 1h0m0s)
  -groups value
        Groups (e.g. admins@pomerium.io,users@pomerium.io)
  -impersonate_email string
        Impersonation Email (optional)
  -impersonate_groups value
        Impersonation Groups (optional)
  -iss string
        Issuing Server (e.g authenticate.int.pomerium.io)
  -sub string
        Subject (typically User's GUID)
  -user string
        User (typically User's GUID)
```

The easiest way to generate that service account would be to use pomerium's docker image and run the `pomerium-cli` tool. Consider the following example:

```bash
docker run -it --entrypoint "/bin/pomerium-cli" pomerium/pomerium:latest \
    -email bob@pomerium.io \
    -aud httpbin.int.pomerium.io \
    -sub bob \
    -user bob \
    -expiry 1h \
    -iss authenticate.int.pomerium.io
```

:::tip

The cli will then prompt you for your base64 encoded shared secret. As a reminder, your shared secret key is _extremely_ sensitive and is used to cryptographically sign sessions here and elsewhere.

:::

:::tip

You can also pass the shared secret by setting the `POMERIUM_SHARED_KEY` environment variable.

:::



You should now see something like:

```jwt
eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiaHR0cGJpbi5pbnQucG9tZXJpdW0uaW8iXSwiZW1haWwiOiJib2JAcG9tZXJpdW0uaW8iLCJleHAiOjE1ODY4NDI2NzksImlhdCI6MTU4NjgzOTA3OSwiaXNzIjoiYXV0aGVudGljYXRlLmludC5wb21lcml1bS5pbyIsIm5iZiI6MTU4NjgzOTA3OSwic3ViIjoiYm9iIiwidXNlciI6ImJvYiJ9.Z4LjZoap24YkWpX8QAhZzexSVKF4982Oma4GTHbdk4k
```

The above generated [JSON Web Token](https://jwt.io/) (JWT) value can now be used as your service account. This JWT session can be used as a [bearer token](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization), or as a session cookie.

As JSON, the payload looks like this (plus a signature).

```json
{
 "iss": "authenticate.int.pomerium.io",
 "sub": "bob",
 "aud": [
  "httpbin.int.pomerium.io"
 ],
 "exp": 1586842679,
 "nbf": 1586839079,
 "iat": 1586839079,
 "email": "bob@pomerium.io",
 "user": "bob"
}
```

For example, here's what the full flow could look like from a bash script:

```bash
jwt=$(docker run -it --entrypoint "/bin/pomerium-cli" pomerium/pomerium:latest \
    -email bob@pomerium.io \
    -aud httpbin.int.pomerium.io \
    -iss authenticate.int.pomerium.io \
    X/6+31jHCANkIbOajHMACNy+HmDreiXcDzRMRQepoVI=)

# note! you should probably use stdin to pass in your key for safety!

curl https://httpbin.imac.bdd.io/headers \
    -H "Accept: application/json" \
    -H "Authorization: Pomerium $jwt"
```

And you should see something like the following in response:

```json
{
  "headers": {
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Authorization": "Pomerium eyJhbGciOiJIUzI1NiJ9.REDACTED",
    "Cookie": "",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.64.1",
    "X-Forwarded-Host": "httpbin.imac.bdd.io",
    "X-Pomerium-Jwt-Assertion": "eyJhbGciOiAiRVMyNTYifQ.REDACTED"
  }
}
```

[configuration settings]: ../../reference/readme.md#administrators
