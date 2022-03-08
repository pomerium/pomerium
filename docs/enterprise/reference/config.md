---
title: Environment Variables
lang: en-US
meta:
    - name: keywords
      content: configuration, options, settings, pomerium, enterprise, reference
---

# Pomerium Console Environment Variables

The keys listed below can be applied in Pomerium Console's `config.yaml` file, or applied as environment variables (in uppercase, replacing `-` with `_`).

| Name    | Description | Default Value |
|:--------|:-------------|---------------|
| administrators | A list of user ids, names or emails to make administrators. Useful for bootstrapping. | none |
| audience | A list of audiences for verifying the signing key. | `[]` |
| authenticate-service-url | URL for the Authenticate Service. Required for Device Registration. | none |
| bind-addr | The address the Pomerium Console will listen on. | `:8701` |
| customer-id | The customer ID | none |
| database-encryption-key | The base64-encoded encryption key for encrypting sensitive data in the database. | none |
| database-url | The database Pomerium Enterprise Console will use. | `postgresql://pomerium:pomerium@localhost:5432/dashboard?sslmode=disable` |
| databroker-service-url | The databroker service URL. | `http://localhost:5443` |
| debug-config-dump | Dumps the Databroker configuration. This is a debug option to be used only when specified by Pomerium Support. | `false` |
| disable-remote-diagnostics | Disable remote diagnostics. | `true` |
| disable-validation | Disable config validation. | `false` |
| grpc-addr | The address to listen for gRPC on. | `:8702` |
| help | help for serve | `false` |
| license-key | Required: Provide the license key issued by your account team. | none |
| override-certificate-name | Overrides the certificate name used for the databroker connection. | none |
| prometheus-data-dir | The path to Prometheus data | none |
| prometheus-listen-addr | When set, embedded Prometheus listens at this address. Set as `host:port` | `127.0.0.1:9090` |
| prometheus-scrape-interval | The Prometheus scrape frequency | `10s` |
| prometheus-url | The URL to access the Prometheus metrics server. | none |
| shared-secret | The base64-encoded secret for signing JWTs, shared with OSS Pomerium. | none |
| signing-key | base64-encoded signing key (public or private) for verifying JWTs. This option is deprecated in favor of `authenticate-service-url`. | none |
| tls-ca | base64-encoded string of tls-ca | none |
| tls-ca-file | file storing tls-ca | none |
| tls-cert | base64-encoded string of tls-cert | none |
| tls-cert-file | file storing tls-cert | none |
| tls-insecure-skip-verify | Disable remote hosts TLS certificate chain and hostname checks. | `false` |
| tls-key | base64-encoded string of tls-key | none |
| tls-key-file | file storing tls-key | none |
| use-static-assets | When false, forward static requests to `localhost:3000`. | `true` |