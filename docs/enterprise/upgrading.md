---
title: Upgrading
sidebarDepth: 0
description: >-
  This page contains the list of deprecations and important or breaking changes
  for Pomerium Enterprise. Please read it carefully.
---

#  Upgrading Pomerium Enterprise

When new version of Pomerium Enterprise are released, check back to this page before you upgrade.

## 0.16.0

## Before You Upgrade

- Configuring `signing-key` has been replaced by setting `authenticate-service-url`.  The [signing key] will be automatically retrieved by Pomerium Enterprise Console.  `signing-key` will continue to work, however `authenticate-service-url` is required for device enrollment.

## 0.15.0

### Before You Upgrade

- `signing-key` is now a required option to improve request security from Pomerium Core. The value should match the one set in Pomerium Core. See the [signing key] reference page for more information on generating a key.
- `audience` is now a required option to improve request security from Pomerium Core. The value should match the Enterprise Console's external URL hostname, as defined in the [`from`](/reference/readme.md#routes) field in the Routes entry (not including the protocol).

[signing key]: /reference/readme.md#signing-key

### Helm Installations

- As of v0.15.0, All Helm charts have been consolidated to a single repository. Remove the `pomerium-enterprise` repo and upgrade from `pomerium`:

   ```bash
   helm repo remove pomerium-enterprise
   helm upgrade --install pomerium-console pomerium/pomerium-console --values=./pomerium-console-values.yaml
   ```

- As noted above, `signing-key` must be shared between Pomerium and Enterprise. See the [Update Pomerium](/enterprise/install/helm.md#update-pomerium) section of [Install Pomerium Enterprise in Helm](/enterprise/install/helm.md) for more information.
