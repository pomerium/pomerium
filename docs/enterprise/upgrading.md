---
title: Upgrading
sidebarDepth: 0
description: >-
  This page contains the list of deprecations and important or breaking changes
  for Pomerium Enterprise. Please read it carefully.
---

#  Upgrading Pomerium Enterprise

When new version of Pomerium Enterprise are released, check back to this page before you upgrade.

## 0.15.0

### Before You Upgrade

- `signing-key` is now a required option to improve request security from Pomerium Core. The value should match the one set in Pomerium Core. See the [signing key] reference page for more information on generating a key.
- `audience` is now a required option to improve request security from Pomerium Core. The value should match the Enterprise Console's external URL hostname, as defined in the [`from`](/reference/readme.md#routes) field in the Routes entry (not including the protocol).

[signing key]: /reference/readme.md/#signing-key




