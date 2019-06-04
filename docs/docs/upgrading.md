---
title: Upgrading
description: >-
  This page contains the list of deprecations and important or breaking changes
  for Pomerium. Please read it carefully.
---

# Overview

## Since 0.0.4

This page contains the list of deprecations and important or breaking changes for pomerium `v0.0.4` compared to `v0.0.5`. Please read it carefully.

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

The configuration variable [Authenticate Internal Service URL](https://www.pomerium.io/reference/#authenticate-internal-service-url) must now be a valid [URL](https://golang.org/pkg/net/url/#URL) type and contain both a hostname and valid `https` schema.
