---
title: Changelog
sidebarDepth: 0
---

# Changelog

## 0.17.0

### New
- Pomerium Enterprise now requires a valid license to start.

### Updated

- Route and Policy screens have been redesigned for better UX.

## 0.16.0

### New

- Devices: It is now possible to manage, enroll, approve, and write authorization policy for device identity.
- Signing keys can now be dynamically pulled from the Authenticate service's JWKS endpoint.
- Added the ability to write PPL policy for HTTP method and path contexts.

### Updated

- Policies can now incorporate device identity and approval status.
- Routes certificate UI now shows the matching TLS certificate used.
- Routes now has Kubernetes service account token field
- Metric addresses are now shown in the runtime info dashboard.
- Envoy was upgraded to 1.20.1.
- The code editor now supports dark mode.
- Various UI style improvements and fixes.

### Fixed

- `--tls-insecure-skip-verify` was not applied to databroker connections.
- Fixed a bug in the host rewrite code (thank you @rankinc for reporting).
- Fixed a bug in the way timeout fields were being displayed.
- Fixed a bug in the way route header fields were being ordered.

### Fixed

## 0.15.2

### Fixed

- A regression in the `Deployments` page loading has been corrected.

## 0.15.1

### Fixed

- Tracing settings now persist correctly.

### Updated

- Support configuring multiple audiences for the console.
- Improved configuration validation.
- Various UI style improvements.

## 0.15.0

### New

- [Telemetry] - View real time metrics and status from Pomerium components inside the Enterprise Console.
- More expressive policy syntax: Pomerium's new extended [policy language] allows more complex policies to be configured, along with non-identity based conditions for access.
- Support for [Google Cloud Serverless] configuration on routes.
- Support for [SPDY] configuration on routes.
- More consistent filtering and sorting across [resource listing pages][runtime].

### Updated

- Certificate Management - Certificates with overlapping SAN names are no longer permitted.
- [Policies] - New editing screen supports Wizard based, Text based or Rego based policy.
- Policies - Only global administrators may manage Rego based policies.
- Policies - Support time based criteria.
- [Service Accounts] - Simplified UI.
- Service Accounts - Support token expiration time.
- Service Accounts - Namespace support.
- Impersonation - Impersonation is now done on an individual session basis.
- Various other bug fixes and improvements.

[`signing key`]: /reference/readme.md#signing-key
[google cloud serverless]: /reference/readme.md#enable-google-cloud-serverless-authentication
[policies]: /enterprise/reference/manage.md#policies-2
[policy language]: /enterprise/reference/manage.md#pomerium-policy-language
[runtime]: /enterprise/reference/reports.md#runtime
[service accounts]: /enterprise/concepts.md#service-accounts
[spdy]: /reference/readme.md#spdy
[telemetry]: /enterprise/reference/reports.md#traffic
