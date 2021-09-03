---
title: Changelog
sidebarDepth: 0
---

#  Changelog

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

- [Telemetry]: View real time metrics and status from Pomerium components inside the Enterprise Console.
- More expressive policy syntax: Pomerium's new extended [policy language] allows more complex policies to be configured, along with non-identity based conditions for access.
- Support for [Google Cloud Serverless] configuration on routes.
- Support for [SPDY] configuration on routes.
- More consistent filtering and sorting across [resource listing pages][runtime].

### Updated

- Certificate Management: Certificates with overlapping SAN names are no longer permitted.
- [Policies]: New editing screen supports Wizard based, Text based or Rego based policy.
- Policies: Only global administrators may manage Rego based policies.
- Policies: Support time based criteria.
- [Service Accounts]: Simplified UI.
- Service Accounts: Support token expiration time.
- Service Accounts: Namespace support.
- Impersonation: Impersonation is now done on an individual session basis.
- Various other bug fixes and improvements.

[`signing key`]: /reference/readme.md/#signing-key
[Telemetry]: /enterprise/reference/reports.md#traffic
[policy language]: /enterprise/reference/manage.md#pomerium-policy-language
[Google Cloud Serverless]: /reference/readme.md#enable-google-cloud-serverless-authentication
[SPDY]: /reference/readme.md#spdy
[runtime]: /enterprise/reference/reports.md#runtime
[Policies]: /enterprise/reference/manage.md#policies-2
[Service Accounts]: /enterprise/concepts.md#service-accounts