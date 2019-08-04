---
title: Upgrading
description: >-
  This page contains the list of deprecations and important or breaking changes
  for Pomerium. Please read it carefully.
---

# Upgrade Guide

## Since 0.1.0

Pomerium `v0.2.0` has no known breaking changes compared to `v0.1.0`.

## Since 0.0.5

This page contains the list of deprecations and important or breaking changes for pomerium `v0.1.0` compared to `v0.0.5`. Please read it carefully.

### Semantic versioning changes

Starting with `v0.1.0` we've changed our [releases](https://semver.org/) are versioned (`MAJOR.MINOR.PATCH+GITHASH`). Planned, monthly releases will now bump `MINOR` and any security or stability releases required prior will bump `PATCH`.

Please note however that we are still pre `1.0.0` so breaking changes can and will happen at any release though we will do our best to document them.

### Breaking: Policy must be valid URLs

Previously, it was allowable to define a policy without a schema (e.g. `http`/`https`). Starting with version `v0.1.0` all `to` and `from` [policy] URLS must contain valid schema and host-names. For example:

```yaml
policy:
  - from: httpbin.corp.domain.example
    to: http://httpbin
    allowed_domains:
      - pomerium.io
  - from: external-httpbin.corp.domain.example
    to: https://httpbin.org
    allow_public_unauthenticated_access: true
```

Should now be:

```yaml
policy:
  - from: https://httpbin.corp.domain.example
    to: http://httpbin
    allowed_domains:
      - pomerium.io
  - from: https://external-httpbin.corp.domain.example
    to: https://httpbin.org
    allow_public_unauthenticated_access: true
```

## Since 0.0.4

This page contains the list of deprecations and important or breaking changes for pomerium `v0.0.5` compared to `v0.0.4`. Please read it carefully.

### Breaking: POLICY_FILE removed

Usage of the POLICY_FILE envvar is no longer supported. Support for file based policy configuration has been shifted into the new unified config file.

### Important: Configuration file support added

- Pomerium now supports an optional -config flag. This flag specifies a file from which to read all configuration options. It supports yaml, json, toml and properties formats.
- All options which can be specified via MY_SETTING style envvars can now be specified within your configuration file as key/value. The key is generally the same as the envvar name, but lower cased. See Reference Documentation for exact names.
- Options precedence is `environmental variables` > `configuration file` > `defaults`
- The options file supports a policy key, which contains policy in the same format as `POLICY_FILE`. To convert an existing policy.yaml into a config.yaml, just move your policy under a policy key.

  Old:

  ```yaml
  - from: httpbin.corp.beyondperimeter.com
    to: http://httpbin
    allowed_domains:
      - pomerium.io
    cors_allow_preflight: true
    timeout: 30s
  ```

  New:

  ```yaml
  policy:
    - from: httpbin.corp.beyondperimeter.com
      to: http://httpbin
      allowed_domains:
        - pomerium.io
      cors_allow_preflight: true
      timeout: 30s
  ```

### Authenticate Internal Service Address

The configuration variable [Authenticate Internal Service URL] must now be a valid [URL](https://golang.org/pkg/net/url/#URL) type and contain both a hostname and valid `https` schema.

[policy]: ./reference/reference.md#policy
[authenticate internal service url]: ./reference/reference.md#authenticate-service-url
