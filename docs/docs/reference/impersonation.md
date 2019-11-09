---
title: User impersonation
description: >-
  This article describes how to configure Pomerium to allow an administrative
  user to impersonate another user or group.
---

# User impersonation

## What

User impersonation allows administrative users to temporarily "sign in as" another user in pomerium. Users with impersonation permissions can impersonate all other users and groups. The impersonating user will be subject to the authorization and access policies of the impersonated user.

## Why

In certain circumstances, it's useful for an administrative user to impersonate another user. For example:

- To help a user troubleshoot an issue. If your downstream authorization policies are configured differently, it's possible that your UI will look different from theirs and you'll need to impersonate the other user to be able to see what they see.
- You want to make changes on behalf of another user (for example, the other user is away on vacation and you want to manage their orders or run a report).
- You're an administrator who's setting up authorization policies, and you want to preview what other users will be able to see depending on the permissions you grant them.

## How

1. Add an administrator to your [configuration settings].
2. Navigate to user dashboard for any proxied route. (e.g. `https://{your-domain}/.pomerium`)
3. Add the `email` and `user groups` you want to impersonate.
4. That's it!

::: warning

**Note!** On session refresh, impersonation will be reset.

:::

## Example

Here's what it looks like.

<video width="100%" height="600" controls=""><source src="./img/pomerium-user-impersonation.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>

[configuration settings]: ../../configuration/readme.md#administrators
