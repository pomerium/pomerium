---
title: Upgrading
description: >-
  This page contains the list of deprecations and important or breaking changes
  for Pomerium. Please read it carefully.
---

# Since 0.12.0

## Breaking

### User impersonation removed

With the v0.13.0 release, user impersonation has been removed.

### Administrators option removed

The `administrators` configuration option has been removed.

# Since 0.11.0

## New

### TCP Proxying

Pomerium can now be used for non-HTTP services.  See [documentation](/docs/topics/tcp-support.md) for more details.

### Datadog Tracing

Datadog has been added as a natively supported [tracing backend](/reference/#datadog)

# Since 0.10.0

## Breaking

### User impersonation disabled by default

With the v0.11.0 release, the ability to do user user impersonation is **disabled by default**. To enable user impersonation, set `enable_user_impersonation` to true in the configuration options.

### `cache_service_url` has been renamed to `databroker_service_url`

The `cache_service_url` parameter has been deprecated since v0.10.0 and is now removed. Please replace it with `databroker_service_url` in your yaml configuration, or `DATABROKER_SERVICE_URL` as an environment variable.

## New

### Docker Multi-Arch Images

With the v0.11.0 release, Pomerium docker images are multi-arch for `arm64` and `amd64`.  Individual images for each architecture will continue to be published.

# Since 0.9.0

## Breaking

### Service accounts required for groups and directory data

With the v0.10.0 release, Pomerium now queries group information asynchronously using a service account. While a service account was already required for a few identity providers like Google's GSuite, an [Identity Provider Service Account] is now required for all other providers as well. The format of this field varies and is specified in each identity provider's documentation.

:::warning

If no [Identity Provider Service Account] is supplied, policies using groups (e.g. `allowed_groups` will not work).

:::

### Cache service builds stateful context

With the v0.10 release, Pomerium now asynchronously fetches associated authorization context (e.g. identity provider directory context, groups, user-data, session data, etc) in the `cache` service. In previous versions, Pomerium used session cookies to associated identity state which authorization policy was evaluated against. While using session tokens had the advantage of making Pomerium a relatively stateless application, that approach has many shortcomings which is more extensively covered in the [data storage docs](./topics/data-storage.md).

There are two [storage backend types] available: `memory` or `redis`. You can see the existing [storage backend configuration settings in the docs][cache service docs].

#### Memory Storage Backend

For `memory` storage, restarting the cache service will result in all users having to re-login. Code for the in-memory database used by the cache service can be found here: [internal/databroker/memory](https://github.com/pomerium/pomerium/tree/master/internal/databroker/memory).

:::warning

Running more than one instance of the `memory` type cache service is not supported.

:::

#### Redis Storage Backend

In production deployments, we recommend using the `redis` storage backend. Unlike the `memory` backend, `redis` can be used for persistent data.

#### Implementing your own storage backend

Please see the following interfaces for reference to implement your storage backend interface.

- [databroker gRPC interface](https://github.com/pomerium/pomerium/blob/master/pkg/grpc/databroker/databroker.proto)
- [storage backend interface](https://github.com/pomerium/pomerium/blob/master/pkg/storage/storage.go)

### Identity headers

With this release, pomerium will not insert identity headers (X-Pomerium-Jwt-Asserttion/X-Pomerium-Claim-*) by default. To get pre 0.9.0 behavior, you can set `pass_identity_headers` to true on a per-policy basis.

# Since 0.8.0

## Breaking

### Default log level

With this release, default log level has been changed to INFO.

### HTTP 1.0

HTTP 1.0 (not to be confused with HTTP 1.1) is not supported anymore. If you relied on it make sure to upgrade to HTTP 1.1 or higher.

Example for HAProxy health check, in pre `0.9.0`:

```sh
shell script option httpchk GET /ping
```

In `0.9.0`:

```sh
option httpchk GET /ping HTTP/1.1\r\nHost:pomerium
```

### preserve_host_header option

With this release, Pomerium uses an embedded envoy proxy instead hand-written one. Thus, we defer the preserve host header functionality to [envoys auto_host_rewrite](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-field-config-route-v3-routeaction-auto-host-rewrite), which does not affect if the policy routes to a static IP.

To preserve 0.8.x behavior, you can use the `set_request_headers` option to explicitly set the Host header.

### Unsupported platforms

- With this release we now use an embedded [envoy](https://www.envoyproxy.io/) binary as our proxy server. Due to this change we now only build and support Linux and MacOS binaries with the AMD64 architecture. We plan on supporting more platforms and architectures in future releases.

### Observability

- The `service` label on metrics and tracing no longer reflects the `Services` configuration option directly. `pomerium` will be used for all-in-one mode, and `pomerium-[service]` will be used for distributed services

#### Tracing

- Jaeger tracing support is no longer end-to-end in the proxy service. We recommend updating to the Zipkin provider for proper tracing support. Jaeger will continue to work but will not have coverage in the data plane.
- Option `tracing_debug` is no longer supported. Use `tracing_sampling_rate` instead. [Details](https://www.pomerium.io/configuration/#shared-tracing-settings).

#### Metrics

With this release we now use an embedded [envoy](https://www.envoyproxy.io/) binary as our proxy server.

- Due to this change, data plane metric names and labels have changed to adopt envoy's internal data model. [Details](https://www.pomerium.io/configuration/#envoy-proxy-metrics)

# Since 0.7.0

## Breaking

### Using paths in from URLs

Although it's unlikely anyone ever used it, prior to 0.8.0 the policy configuration allowed you to specify a `from` field with a path component:

```yaml
policy:
  - from: "https://example.com/some/path"
```

The proxy and authorization server would simply ignore the path and route/authorize based on the host name.

With the introduction of `prefix`, `path` and `regex` fields to the policy route configuration, we decided not to support using a path in the `from` url, since the behavior was somewhat ambiguous and better handled by the explicit fields.

To avoid future confusion, the application will now declare any configuration which contains a `from` field with a path as invalid, with this error message:

```
config: policy source url (%s) contains a path, but it should be set using the path field instead
```

If you see this error you can fix it by simply removing the path from the `from` field and moving it to a `prefix` field.

In other words, this configuration:

```yaml
policy:
  - from: "http://example.com/some/path"
```

Should be written like this:

```yaml
policy:
  - from: "http://example.com"
    prefix: "/some/path"
```

# Since 0.6.0

## Breaking

### Getting user's identity

:::warning

This changed was partially reverted in v0.7.2\. Session details like `user`, `email`, and `groups` can still be explicitly extracted by setting the [jwt_claims_header](../reference/readme.md#jwt-claim-headers) configuration option.

:::

User detail headers ( `x-pomerium-authenticated-user-id` / `x-pomerium-authenticated-user-email` / `x-pomerium-authenticated-user-groups`) have been removed in favor of using the more secure, more data rich attestation jwt header (`x-pomerium-jwt-assertion`).

If you still rely on individual claim headers, please see the `jwt_claims_headers` option [here](https://www.pomerium.io/configuration/#jwt-claim-headers).

### Non-standard port users

Non-standard port users (e.g. those not using `443`/`80` where the port _would_ be part of the client's request) will have to clear their user's session before upgrading. Starting with version v0.7.0, audience (`aud`) and issuer (`iss`) claims will be port specific.

# Since 0.5.0

## Breaking

### New cache service

A back-end cache service was added to support session refreshing from [single-page-apps](https://en.wikipedia.org/wiki/Single-page_application).

- For all-in-one deployments, _no changes are required_. The cache will be embedded in the binary. By default, autocache an in-memory LRU cache will be used to temporarily store user session data. If you wish to persist session data, it's also possible to use bolt or redis.
- For split-service deployments, you will need to deploy an additional service called cache. By default, pomerium will use autocache as a distributed, automatically managed cache. It is also possible to use redis as backend in this mode.

For a concrete example of the required changes, consider the following changes for those running split service mode,:

```diff
...
  pomerium-authenticate:
    environment:
      - SERVICES=authenticate
+      - CACHE_SERVICE_URL=http://pomerium-cache:443
...
+  pomerium-cache:
+    image: pomerium/pomerium
+    environment:
+      - SERVICES=cache
+    volumes:
+      - ../config/config.example.yaml:/pomerium/config.yaml:ro
+    expose:
+      - 443
```

Please see the updated examples, and [cache service docs] as a reference and for the available cache stores. For more details as to why this was necessary, please see [PR438](https://github.com/pomerium/pomerium/pull/438) and [PR457](https://github.com/pomerium/pomerium/pull/457).

# Since 0.4.0

## Breaking

### Subdomain requirement dropped

- Pomerium services and managed routes are no longer required to be on the same domain-tree root. Access can be delegated to any route, on any domain (that you have access to, of course).

### Azure AD

- Azure Active Directory now uses the globally unique and immutable`ID` instead of `group name` to attest a user's [group membership](https://docs.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0&tabs=http). Please update your policies to use group `ID` instead of group name.

### Okta

- Okta no longer uses tokens to retrieve group membership. [Group membership](https://developer.okta.com/docs/reference/api/groups/) is now fetched using Okta's API.
- Okta's group membership is now determined by the globally unique and immutable ID field. Please update your policies to use group `ID` instead of group name.
- Okta now requires an additional set of credentials to be used to query for group membership set as a [service account](https://www.pomerium.io/docs/reference/reference.html#identity-provider-service-account).

### OneLogin

- OneLogin [group membership](https://developers.onelogin.com/openid-connect/api/user-info) is now determined by the globally unique and immutable ID field. Please update your policies to use group `ID` instead of group name.

### Force Refresh Removed

Force refresh has been removed from the dashboard. Logging out and back in again should have the equivalent desired effect.

### Programmatic Access API changed

Previous programmatic authentication endpoints (`/api/v1/token`) has been removed and has been replaced by a per-route, oauth2 based auth flow. Please see updated [programmatic documentation](https://www.pomerium.io/docs/reference/programmatic-access.html) how to use the new programmatic access api.

### Forward-auth route change

Previously, routes were verified by taking the downstream applications hostname in the form of a path `(e.g. ${forwardauth}/.pomerium/verify/verify.some.example`) variable. The new method for verifying a route using forward authentication is to pass the entire requested url in the form of a query string `(e.g. ${forwardauth}/.pomerium/verify?url=https://verify.some.example)` where the routed domain is the value of the `uri` key.

Note that the verification URL is no longer nested under the `.pomerium` endpoint.

For example, in nginx this would look like:

```diff
-    nginx.ingress.kubernetes.io/auth-url: https://forwardauth.corp.example.com/.pomerium/verify/verify.corp.example.com?no_redirect=true
-    nginx.ingress.kubernetes.io/auth-signin: https://forwardauth.corp.example.com/.pomerium/verify/verify.corp.example.com
+    nginx.ingress.kubernetes.io/auth-url: https://forwardauth.corp.example.com/verify?uri=$scheme://$host$request_uri
+    nginx.ingress.kubernetes.io/auth-signin: https://forwardauth.corp.example.com?uri=$scheme://$host$request_uri
```

# Since 0.3.0

## Breaking

### Authorize Service URL no longer used in all-in-one mode

Pomerium no longer handles both gRPC and HTTPS traffic from the same network listener (port). As a result, all-in-one mode configurations will default to serving gRPC traffic over loopback on port `5443` and will serve HTTPS traffic as before on port `443`. In previous versions, it was recommended to configure authorize in this mode which will now break. The error will typically look something like:

```
rpc error: code = DeadlineExceeded desc = latest connection error: connection closed
```

To upgrade, simply remove the `AUTHORIZE_SERVICE_URL` setting.

### Removed Authenticate Internal URL

The authenticate service no longer uses gRPC to do back channel communication. As a result, `AUTHENTICATE_INTERNAL_URL`/`authenticate_internal_url` is no longer required.

### No default certificate location

In previous versions, if no explicit certificate pair (in base64 or file form) was set, Pomerium would make a last ditch effort to check for certificate files (`cert.key`/`privkey.pem`) in the root directory. With the introduction of insecure server configuration, we've removed that functionality. If there settings for certificates and insecure server mode are unset, pomerium will give a appropriate error instead of a failed to find/open certificate error.

### Authorize service health-check is non-http

The Authorize service will no longer respond to `HTTP`-based healthcheck queries when run as a distinct service (vs all-in-one). As an alternative, you can used on TCP based checks. For example, if using [Kubernetes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-a-tcp-liveness-probe):

```yaml
---
readinessProbe:
  tcpSocket:
    port: 443
  initialDelaySeconds: 5
  periodSeconds: 10
livenessProbe:
  tcpSocket:
    port: 443
  initialDelaySeconds: 15
  periodSeconds: 20
```

## Non-breaking changes

### All-in-one

If service mode (`SERVICES`/`services`) is set to `all`, gRPC communication with the authorize service will by default occur over localhost, on port `:5443`.

# Since 0.2.0

Pomerium `v0.3.0` has no known breaking changes compared to `v0.2.0`.

# Since 0.1.0

Pomerium `v0.2.0` has no known breaking changes compared to `v0.1.0`.

# Since 0.0.5

This page contains the list of deprecations and important or breaking changes for pomerium `v0.1.0` compared to `v0.0.5`. Please read it carefully.

## Semantic versioning changes

Starting with `v0.1.0` we've changed our [releases](https://semver.org/) are versioned (`MAJOR.MINOR.PATCH+GITHASH`). Planned, monthly releases will now bump `MINOR` and any security or stability releases required prior will bump `PATCH`.

Please note however that we are still pre `1.0.0` so breaking changes can and will happen at any release though we will do our best to document them.

## Breaking: Policy must be valid URLs

Previously, it was allowable to define a policy without a schema (e.g. `http`/`https`). Starting with version `v0.1.0` all `to` and `from` [policy] URLS must contain valid schema and host-names. For example:

```yaml
policy:
  - from: verify.corp.domain.example
    to: http://verify
    allowed_domains:
      - pomerium.io
  - from: external-verify.corp.domain.example
    to: https://verify.pomerium.com
    allow_public_unauthenticated_access: true
```

Should now be:

```yaml
policy:
  - from: https://verify.corp.domain.example
    to: http://verify
    allowed_domains:
      - pomerium.io
  - from: https://external-verify.corp.domain.example
    to: https://verify.pomerium.com
    allow_public_unauthenticated_access: true
```

# Since 0.0.4

This page contains the list of deprecations and important or breaking changes for pomerium `v0.0.5` compared to `v0.0.4`. Please read it carefully.

## Breaking: POLICY_FILE removed

Usage of the POLICY_FILE envvar is no longer supported. Support for file based policy configuration has been shifted into the new unified config file.

## Important: Configuration file support added

- Pomerium now supports an optional -config flag. This flag specifies a file from which to read all configuration options. It supports yaml, json, toml and properties formats.
- All options which can be specified via MY_SETTING style envvars can now be specified within your configuration file as key/value. The key is generally the same as the envvar name, but lower cased. See Reference Documentation for exact names.
- Options precedence is `environmental variables` > `configuration file` > `defaults`
- The options file supports a policy key, which contains policy in the same format as `POLICY_FILE`. To convert an existing policy.yaml into a config.yaml, just move your policy under a policy key.

  Old:

  ```yaml
  - from: verify.localhost.pomerium.io
    to: http://verify
    allowed_domains:
      - pomerium.io
    cors_allow_preflight: true
    timeout: 30s
  ```

  New:

  ```yaml
  policy:
    - from: verify.localhost.pomerium.io
      to: http://verify
      allowed_domains:
        - pomerium.io
      cors_allow_preflight: true
      timeout: 30s
  ```

## Authenticate Internal Service Address

The configuration variable [Authenticate Internal Service URL] must now be a valid [URL](https://golang.org/pkg/net/url/#URL) type and contain both a hostname and valid `https` schema.

[authenticate internal service url]: ../reference/readme.md#authenticate-service-url
[cache service docs]: ../reference/readme.md#cache-service
[identity provider service account]: ../reference/readme.md#identity-provider-service-account
[policy]: ../reference/readme.md#policy
[storage backend configuration here]: ../reference/readme.md#cache-service
[storage backend types]: ../reference/readme.md#data-broker-storage-type
