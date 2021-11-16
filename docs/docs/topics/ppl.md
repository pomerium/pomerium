---
title: Pomerium Policy Language
description: >-
  This article covers Pomerium Policy Language, used to define secure access policies for routes.
---

# Pomerium Policy Language

Pomerium Policy Language (**PPL**) is a yaml-based notation for creatng easy and flexible authorization policies. This document covers the usage of PPL and provides several example policies.

## At a Glance

Each PPL policy has at the top level a set of `allow` or `deny` actions, with a list of logitical operators, criteria, matchers, and values underdeath. For example:

```yaml
allow:
  and:
  - domain: 
      is: example.com
  - groups: 
      has: admin
deny:
  or:
  - user: 
      is: user1@example.com
  - user: 
      is: user2@example.com
```

This policy will allow a user with an email address at `example.com` who **is also** a member of the `admin` group. It will deny `user1` and `user2`, regardless of their domain and group membership.

### Rules

A PPL document is either an object or an array of objects. The object represents a rule where the action is the key and the value is an object containing the logical operators.

### Actions

Only two actions are supported: `allow` and `deny`. `deny` takes precedence over `allow`. More precisely: a user will have access to a route if **at least one** `allow` rule matches and **no** `deny` rules match. 

### Logical Operators

A logical operator combines multiple criteria together for the evaluation of a rule. There are 4 logical operators: `and`, `or`, `not` and `nor`.

### Criteria

Criteria in PPL are represented as an object where the key is the name and optional sub-path of the criterion, and the value changes depending on which criterion is used. A sub-path is indicated with a `/` in the name:

```yaml
allow:
  and:
  - claim/family_name: Smith
```

PPL supports many different criteria. In the open source the following criteria are available:

| Criterion Name               | Data Format                   | Description                                                                                                                                                                                              |
| ---------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accept`                     | Anything. Typically true.     | Always returns true, thus always allowing access. Equivalent to the `allow_public_unauthenticated_access` option.                                                                                        |
| `authenticated_user`         | Anything. Typically true.     | Always returns true for logged-in users. Equivalent to the `allow_any_authenticated_user` option.                                                                                                        |
| `claim`                      | Anything. Typically a string. | Returns true if a token claim matches (exactly) the supplied value. The claim to check is determined via the sub-path. (`claim/family_name: Smith` matches if the user's `family_name` claim is `Smith`) |
| `cors_preflight`             | Anything. Typically true.     | Returns true if the incoming request uses the `OPTIONS` method and has both the `Access-Control-Request-Method` and `Origin` headers. Used to allow CORS pre-flight requests.                            |
| `device`                     |                               | Used as part of WebAuthn which is not currently released.                                                                                                                                                |
| `domain`                     | String Matcher                | Returns true if the logged-in user's email address domain (the part after `@`) matches the given value.                                                                                                  |
| `email`                      | String Matcher                | Returns true if the logged-in user's email address matches the given value.                                                                                                                              |
| `groups`                     | List Matcher                  | Returns true if the logged-in user is a member of the given group.                                                                                                                                       |
| `invalid_client_certificate` | Anything. Typically true.     | Returns true if the incoming request has an invalid client certificate. A default `deny` rule using this criterion is added to all Pomerium policies and implements our mTLS client certificate options. |
| `pomerium_routes`            | Anything. Typically true.     | Returns true if the incoming request is for the special `.pomerium` routes. A default `allow` rule using this criterion is added to all Pomerium policies.                                               |
| `reject`                     | Anything. Typically true.     | Always returns false. The opposite of `accept`.                                                                                                                                                          |
| `user`                       | String Matcher                | Returns true if the logged-in user's id matches the given value.                                                                                                                                         |

The enterprise product supports all the open source criteria, but also supports these additional criteria:

| Criterion Name | Data Format         | Description                                                                            |
| -------------- | ------------------- | -------------------------------------------------------------------------------------- |
| `date`         | Date Matcher        | Returns true if the time of the request matches the constraints.                       |
| `day_of_week`  | Day of Week Matcher | Returns true if the day of the request matches the constraints.                        |
| `time_of_day`  | Time of Day Matcher | Returns true if the time of the request (for the current day) matches the constraints. |