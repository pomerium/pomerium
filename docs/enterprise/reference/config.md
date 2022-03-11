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
| <a class="entRef-anchor" id="administrators">#</a><a href=#administrators>administrators</a> | A list of user ids, names or emails to make administrators. Useful for bootstrapping. | none |
| <a class="entRef-anchor" id="audience">#</a><a href=#audience>audience</a> | A list of audiences for verifying the signing key. | `[]` |
| <a class="entRef-anchor" id="authenticate-service-url">#</a><a href=#authenticate-service-url>authenticate-service-url</a> | URL for the Authenticate Service. Required for Device Registration. | none |
| <a class="entRef-anchor" id="bind-addr">#</a><a href=#bind-addr>bind-addr</a> | The address the Pomerium Console will listen on. | `:8701` |
| <a class="entRef-anchor" id="customer-id">#</a><a href=#customer-id>customer-id</a> | The customer ID | none |
| <a class="entRef-anchor" id="database-encryption-key">#</a><a href=#database-encryption-key>database-encryption-key</a> | The base64-encoded encryption key for encrypting sensitive data in the database. | none |
| <a class="entRef-anchor" id="database-url">#</a><a href=#database-url>database-url</a> | The database Pomerium Enterprise Console will use. | `postgresql://pomerium:pomerium@localhost:5432/dashboard?sslmode=disable` |
| <a class="entRef-anchor" id="databroker-service-url">#</a><a href=#databroker-service-url>databroker-service-url</a> | The databroker service URL. | `http://localhost:5443` |
| <a class="entRef-anchor" id="debug-config-dump">#</a><a href=#debug-config-dump>debug-config-dump</a> | Dumps the Databroker configuration. This is a debug option to be used only when specified by Pomerium Support. | `false` |
| <a class="entRef-anchor" id="disable-remote-diagnostics">#</a><a href=#disable-remote-diagnostics>disable-remote-diagnostics</a> | Disable remote diagnostics. | `true` |
| <a class="entRef-anchor" id="disable-validation">#</a><a href=#disable-validation>disable-validation</a> | Disable config validation. | `false` |
| <a class="entRef-anchor" id="grpc-addr">#</a><a href=#grpc-addr>grpc-addr</a> | The address to listen for gRPC on. | `:8702` |
| <a class="entRef-anchor" id="help">#</a><a href=#help>help</a> | help for serve | `false` |
| <a class="entRef-anchor" id="license-key">#</a><a href=#license-key>license-key</a> | Required: Provide the license key issued by your account team. | none |
| <a class="entRef-anchor" id="override-certificate-name">#</a><a href=#override-certificate-name>override-certificate-name</a> | Overrides the certificate name used for the databroker connection. | none |
| <a class="entRef-anchor" id="prometheus-data-dir">#</a><a href=#prometheus-data-dir>prometheus-data-dir</a> | The path to Prometheus data | none |
| <a class="entRef-anchor" id="prometheus-listen-addr">#</a><a href=#prometheus-listen-addr>prometheus-listen-addr</a> | When set, embedded Prometheus listens at this address. Set as `host:port` | `127.0.0.1:9090` |
| <a class="entRef-anchor" id="prometheus-scrape-interval">#</a><a href=#prometheus-scrape-interval>prometheus-scrape-interval</a> | The Prometheus scrape frequency | `10s` |
| <a class="entRef-anchor" id="prometheus-url">#</a><a href=#prometheus-url>prometheus-url</a> | The URL to access the Prometheus metrics server. | none |
| <a class="entRef-anchor" id="shared-secret">#</a><a href=#shared-secret>shared-secret</a> | The base64-encoded secret for signing JWTs, shared with OSS Pomerium. | none |
| <a class="entRef-anchor" id="signing-key">#</a><a href=#signing-key>signing-key</a> | base64-encoded signing key (public or private) for verifying JWTs. This option is deprecated in favor of `authenticate-service-url`. | none |
| <a class="entRef-anchor" id="tls-ca">#</a><a href=#tls-ca>tls-ca</a> | base64-encoded string of tls-ca | none |
| <a class="entRef-anchor" id="tls-ca-file">#</a><a href=#tls-ca-file>tls-ca-file</a> | file storing tls-ca | none |
| <a class="entRef-anchor" id="tls-cert">#</a><a href=#tls-cert>tls-cert</a> | base64-encoded string of tls-cert | none |
| <a class="entRef-anchor" id="tls-cert-file">#</a><a href=#tls-cert-file>tls-cert-file</a> | file storing tls-cert | none |
| <a class="entRef-anchor" id="tls-insecure-skip-verify">#</a><a href=#tls-insecure-skip-verify>tls-insecure-skip-verify</a> | Disable remote hosts TLS certificate chain and hostname checks. | `false` |
| <a class="entRef-anchor" id="tls-key">#</a><a href=#tls-key>tls-key</a> | base64-encoded string of tls-key | none |
| <a class="entRef-anchor" id="tls-key-file">#</a><a href=#tls-key-file>tls-key-file</a> | file storing tls-key | none |
| <a class="entRef-anchor" id="use-static-assets">#</a><a href=#use-static-assets>use-static-assets</a> | When false, forward static requests to `localhost:3000`. | `true` |