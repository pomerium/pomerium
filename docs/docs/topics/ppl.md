---
title: Pomerium Policy Language
description: >-
  This article covers Pomerium Policy Language, used to define secure access policies for routes.
---

# Pomerium Policy Language

Pomerium Policy Language (**PPL**) is a [yaml]-based notation for creating easy and flexible authorization policies. This document covers the usage of PPL and provides several example policies.

## At a Glance

Each PPL policy has at the top level a set of `allow` or `deny` actions, with a list of logical operators, criteria, matchers, and values underneath. For example:

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

This policy will allow a user with an email address at `example.com` who **is also** a member of the `admin` group. It will deny `user1` **or** `user2`, regardless of their domain and group membership.

## Rules

A PPL document is either an object or an array of objects. The object represents a rule where the action is the key and the value is an object containing the logical operators.

## Actions

Only two actions are supported: `allow` and `deny`. `deny` takes precedence over `allow`. More precisely: a user will have access to a route if **at least one** `allow` rule matches and **no** `deny` rules match.

## Logical Operators

A logical operator combines multiple criteria together for the evaluation of a rule. There are 4 logical operators: `and`, `or`, `not` and `nor`.

::: details More on Logical Operators
Given the following example with `OPERATOR` replaced:

```yaml
allow:
  OPERATOR:
    - domain:
        is: example.com
    - groups:
        has: admin
```

If `and` is used, the user will have access if their email address ends in `example.com` **and** they are a member of the admin group. **(A ∧ B)**

If `or` is used, the user will have access if their email address ends in `example.com` **or** they are a member of the admin group. **(A ∨ B)**

If `not` is used, the user will have access if their email address does not end in `example.com` **and** they are not a member of the `admin` group. **(¬A ∧ ¬B)**

If `nor` is used, the user will have access if their email address does not end in `example.com` **or** they are not a member of the admin group. **(¬A ∨ ¬B)**
:::

## Criteria

Criteria in PPL are represented as an object where the key is the name and optional sub-path of the criterion, and the value changes depending on which criterion is used. A sub-path is indicated with a `/` in the name:

```yaml
allow:
  and:
    - claim/family_name: Smith
```

PPL supports many different criteria:

| Criterion Name               | Data Format                   | Description                                                                                                                                                                                                                  |
| ---------------------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accept`                     | Anything. Typically `true`.   | Always returns true, thus always allowing access. Equivalent to the [`allow_public_unauthenticated_access`] option.                                                                                                          |
| `authenticated_user`         | Anything. Typically `true`.   | Always returns true for logged-in users. Equivalent to the [`allow_any_authenticated_user`] option.                                                                                                                          |
| `claim`                      | Anything. Typically a string. | Returns true if a token claim matches the supplied value **exactly**. The claim to check is determined via the sub-path. <br/> For example, `claim/family_name: Smith` matches if the user's `family_name` claim is `Smith`. |
| `cors_preflight`             | Anything. Typically `true`.   | Returns true if the incoming request uses the `OPTIONS` method and has both the `Access-Control-Request-Method` and `Origin` headers. Used to allow [CORS pre-flight requests].                                              |
| `device`                     | [Device matcher]              | Returns true if the incoming request includes a valid device ID or type.                                                                                                                                                     |
| `domain`                     | [String Matcher]              | Returns true if the logged-in user's email address domain (the part after `@`) matches the given value.                                                                                                                      |
| `email`                      | [String Matcher]              | Returns true if the logged-in user's email address matches the given value.                                                                                                                                                  |
| `groups`                     | [List Matcher]                | Returns true if the logged-in user is a member of the given group.                                                                                                                                                           |
| `http_method`                | [String Matcher]              | Returns true if the HTTP method matches the given value.                                                                                                                                                                     |
| `http_path`                  | [String Matcher]              | Returns true if the HTTP path matches the given value.                                                                                                                                                                       |
| `invalid_client_certificate` | Anything. Typically `true`.   | Returns true if the incoming request has an invalid client certificate. A default `deny` rule using this criterion is added to all Pomerium policies when an mTLS [client certificate authority] is set.                     |
| `reject`                     | Anything. Typically `true`.   | Always returns false. The opposite of `accept`.                                                                                                                                                                              |
| `user`                       | [String Matcher]              | Returns true if the logged-in user's id matches the given value.                                                                                                                                                             |

[Pomerium Enterprise] supports all the open source criteria, but also supports these additional criteria:

| Criterion Name | Data Format           | Description                                                                            |
| -------------- | --------------------- | -------------------------------------------------------------------------------------- |
| `date`         | [Date Matcher]        | Returns true if the time of the request matches the constraints.                       |
| `day_of_week`  | [Day of Week Matcher] | Returns true if the day of the request matches the constraints.                        |
| `time_of_day`  | [Time of Day Matcher] | Returns true if the time of the request (for the current day) matches the constraints. |

## Matchers

## Day of Week Matcher

The day of week matcher is a **string**. The string can either be `*`, a comma-separated list of days, or a dash-separated list of days.

- `*` matches all days.
- `,` matches either day (e.g. `mon,wed,fri`).
- `-` matches a range of days. (e.g. `mon-fri`). Days can be specified as English full day names, or as 3 character abbreviations. For example:

  ```yaml
  allow:
    and:
      - day_of_week: tue-fri
  ```

## Date Matcher

The date matcher is an object with operators as keys. It supports the following operators: `after` and `before`. The values are [ISO-8601](https://en.wikipedia.org/wiki/ISO_8601) date strings. `after` means that the time of the request must be after the supplied date and `before` means that the time of the request must be before the supplied date. For example:

```yaml
allow:
  and:
    - date:
        after: 2020-01-02T16:20:00
        before: 2150-01-02T16:20:00
```

## Device Matcher

A device matcher is an object with operators as keys. It supports the following operators:

- `is` - an exact match of the device ID.
- `approved` - true if the device has been approved. This is an enterprise-only feature.
- `type` - Specifies the type of device to match on. The available types are `enclave_only` and `any`.
  - `enclave_only` will only match [platform authenticators](/docs/topics/device-identity.md#secure-enclaves). These include TPM modules and hardware-backed keystores built into mobile devices.
  - `any` will also match [hardware security keys](/docs/topics/device-identity.md#hardware-security-keys).

For example, a policy to allow any user with a registered device:

```yaml
- allow:
    or:
      - device:
          type: any
```

Compare to a policy that only allows a set of specific devices:

```yaml
- allow:
    or:
      - device:
          is: "5Vn3...C1RS"
    or:
      - device:
          is: "GAtL...doqu"
```

::: tip
Users can [find their device IDs](/guides/enroll-device.md#find-device-id) at the `/.pomerium` endpoint from any route.
:::

### List Matcher

A list matcher is an object with operators as keys. It supports the following operators: `has`. For example:

```yaml
allow:
  and:
    - groups:
        has: "admin"
```

### String Matcher

A string matcher is an object with operators as keys. It supports the following operators: `contains`, `ends_with`, `is` and `starts_with`. For example:

```yaml
allow:
  and:
    - email:
        starts_with: "admin@"
```

## Time of Day Matcher

The time of day matcher is an object with operators as keys. It supports the following operators: `timezone`, `after`, and `before`.

`timezone` is required and specifies the timezone to use when interpreting the supplied times. It is recommended to use city names (like `America/Phoenix`) instead of standard timezone abbreviations because standard timezones change throughout the year (i.e. EST becomes EDT and back again).

`after` means the time of the request must be after the supplied time and `before` means that the time of the request must be before the supplied time. For example:

```yaml
allow:
  and:
    - time_of_day:
        timezone: UTC
        after: 2:20:00
        before: 4:30PM
```

[`allow_public_unauthenticated_access`]: /reference/readme.md#public-access
[`allow_any_authenticated_user`]: /reference/readme.md#allow-any-authenticated-user
[CORS pre-flight requests]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests
[client certificate authority]: /reference/readme.md#client-certificate-authority
[Pomerium Enterprise]: /enterprise/about.md
[yaml]: https://en.wikipedia.org/wiki/YAML
[String Matcher]: #string-matcher
[Date Matcher]: #date-matcher
[Day of Week Matcher]: #day-of-week-matcher
[Time of Day Matcher]: #time-of-day-matcher
[List Matcher]: #list-matcher
[Device matcher]: #device-matcher
