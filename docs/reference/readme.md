---
title: Settings
lang: en-US
sidebarDepth: 2
meta:
  - name: keywords
    content: configuration options settings pomerium
---

# Configuration Settings

Pomerium can be configured using a configuration file ([YAML]/[JSON]/[TOML]) or [environmental variables]. In general, environmental variable keys are identical to config file keys but are in uppercase. If you are coming from a kubernetes or docker background this should feel familiar. If not, check out the following primers.

- [Store config in the environment](https://12factor.net/config)
- [Kubernetes: Environment variables](https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/)
- [Kubernetes: Config Maps](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/)
- [Docker: Environment variables](https://docs.docker.com/compose/environment-variables/)

Using both [environmental variables] and config file keys is allowed and encouraged (for instance, secret keys are probably best set as environmental variables). However, if duplicate configuration keys are found, environment variables take precedence.

Pomerium will automatically reload the configuration file if it is changed. At this time, only policy is re-configured when this reload occurs, but additional options may be added in the future. It is suggested that your policy is stored in a configuration file so that you can take advantage of this feature.

## Shared Settings

These are configuration variables shared by all services, in all service modes.

### Address

- Environmental Variable: `ADDRESS`
- Config File Key: `address`
- Type: `string`
- Example: `:443`, `:8443`
- Default: `:443`
- Required

Address specifies the host and port to serve HTTP requests from. If empty, `:443` is used. Note, in all-in-one deployments, gRPC traffic will be served on loopback on port `:5443`.

### Administrators

- Environmental Variable: `ADMINISTRATORS`
- Config File Key: `administrators`
- Type: slice of `string`
- Example: `"admin@example.com,admin2@example.com"`

Administrative users are [super user](https://en.wikipedia.org/wiki/Superuser) that can sign in as another user or group. User impersonation allows administrators to temporarily impersonate a different user.

### Autocert

- Environmental Variable: `AUTOCERT`
- Config File Key: `autocert`
- Type: `bool`
- Optional

Turning on autocert allows Pomerium to automatically retrieve, manage, and renew public facing TLS certificates from [Let's Encrypt][letsencrypt] for each of your managed pomerium routes as well as for the authenticate service. This setting must be used in conjunction with [Autocert Directory](./#autocert-directory) as Autocert must have a place to persist, and share certificate data between services. Provides [OCSP stapling](https://en.wikipedia.org/wiki/OCSP_stapling).

This setting can be useful in a situation where you do not have Pomerium behind a TLS terminating ingress or proxy that is already handling your public certificates on your behalf.

:::warning

By using autocert, you agree to the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf). There are [_strict_ usage limits](https://letsencrypt.org/docs/rate-limits/) per domain you should be aware of. Consider testing with `autocert_use_staging` first.

:::

:::warning

Autocert requires that ports `80`/`443` be accessible from the internet in order to complete a [TLS-ALPN-01 challenge](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01).

:::

### Autocert Must-Staple

- Environmental Variable: `AUTOCERT_MUST_STAPLE`
- Config File Key: `autocert_must_staple`
- Type: `bool`
- Optional

If true, cause autocert to request a certificate with `status_request` extension (commonly called `Must-Staple`). This allows the TLS client (the browser) to fail immediately if the TLS handshake doesn't include OCSP stapling information. Only used when [Autocert](./#autocert) is true.

NOTE: this only takes effect the next time Pomerium renews your certificates.

See also <https://tools.ietf.org/html/rfc7633> for more context.

### Autocert Directory

- Environmental Variable: either `AUTOCERT_DIR`
- Config File Key: `autocert_dir`
- Type: `string` pointing to the path of the directory
- Required if using [Autocert](./#autocert) setting
- Default:

  - `/data/autocert` in published Pomerium docker images
  - [$XDG_DATA_HOME](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
  - `$HOME/.local/share/pomerium`

Autocert directory is path in which autocert will store x509 certificate data.

### Autocert Use Staging

- Environmental Variable: `AUTOCERT_USE_STAGING`
- Config File Key: `autocert_use_staging`
- Type: `bool`
- Optional

Let's Encrypt has strict [usage limits](https://letsencrypt.org/docs/rate-limits/). Enabling this setting allows you to use Let's Encrypt's [staging environment](https://letsencrypt.org/docs/staging-environment/) which has much more lax usage limits.

### Certificates

- Config File Key: `certificates` (not yet settable using environmental variables)
- Config File Key: `certificate` / `certificate_key`
- Config File Key: `certificate_file` / `certificate_key_file`
- Environmental Variable: `CERTIFICATE` / `CERTIFICATE_KEY`
- Environmental Variable: `CERTIFICATE_FILE` / `CERTIFICATE_KEY_FILE`
- Type: array of relative file locations `string`
- Type: [base64 encoded] `string`
- Type: certificate relative file location `string`
- Required (if insecure not set)

Certificates are the x509 _public-key_ and _private-key_ used to establish secure HTTP and gRPC connections. Any combination of the above can be used together, and are additive. Use in conjunction with `Autocert` to get OCSP stapling.

For example, if specifying multiple certificates at once:

```yaml
certificates:
  - cert: "$HOME/.acme.sh/authenticate.example.com_ecc/fullchain.cer"
    key: "$HOME/.acme.sh/authenticate.example.com_ecc/authenticate.example.com.key"
  - cert: "$HOME/.acme.sh/httpbin.example.com_ecc/fullchain.cer"
    key: "$HOME/.acme.sh/httpbin.example.com_ecc/httpbin.example.com.key"
  - cert: "$HOME/.acme.sh/prometheus.example.com_ecc/fullchain.cer"
    key: "$HOME/.acme.sh/prometheus.example.com_ecc/prometheus.example.com.key"
```

### Client Certificate Authority

- Environment Variable: `CLIENT_CA` / `CLIENT_CA_FILE`
- Config File Key: `client_ca` / `client_ca_file`
- Type: [base64 encoded] `string` or relative file location
- Optional

The Client Certificate Authority is the x509 _public-key_ used to validate [mTLS](https://en.wikipedia.org/wiki/Mutual_authentication) client certificates. If not set, no client certificate will be required.

### Cookie options

These settings control the Pomerium session cookies sent to users's browsers.

#### Cookie name

- Environmental Variable: `COOKIE_NAME`
- Config File Key: `cookie_name`
- Type: `string`
- Default: `_pomerium`

The name of the session cookie sent to clients.

#### Cookie secret

- Environmental Variable: `COOKIE_SECRET`
- Config File Key: `cookie_secret`
- Type: [base64 encoded] `string`
- Required for proxy service 

Secret used to encrypt and sign session cookies. You can generate a random key with `head -c32 /dev/urandom | base64`.

#### Cookie domain

- Environmental Variable: `COOKIE_DOMAIN`
- Config File Key: `cookie_domain`
- Type: `string`
- Example: `corp.beyondperimeter.com`
- Optional

The scope of session cookies issued by Pomerium. Session cookies will be shared by all subdomains of the domain specified here.

#### HTTPS only

- Environmental Variable: `COOKIE_SECURE`
- Config File Key: `cookie_secure`
- Type: `bool`
- Default: `true`

If true, instructs browsers to only send user session cookies over HTTPS.

:::warning

Setting this to false may result in session cookies being sent in cleartext.

:::

#### Javascript security

- Environmental Variable: `COOKIE_HTTP_ONLY`
- Config File Key: `cookie_http_only`
- Type: `bool`
- Default: `true`

If true, prevents javascript in browsers from reading user session cookies.

:::warning

Setting this to false enables hostile javascript to steal session cookies and impersonate users.

:::

#### Expiration

- Environmental Variable: `COOKIE_EXPIRE`
- Config File Key: `cookie_expire`
- Type: [Go Duration](https://golang.org/pkg/time/#Duration.String) `string`
- Default: `14h`

Sets the lifetime of session cookies. After this interval, users will be forced to go through the OAuth login flow again to get a new cookie.

### Debug

- Environmental Variable: `POMERIUM_DEBUG`
- Config File Key: `pomerium_debug`
- Type: `bool`
- Default: `false`

::: danger

Enabling the debug flag will result in sensitive information being logged!!!

:::

By default, JSON encoded logs are produced. Debug enables colored, human-readable logs to be streamed to [standard out](https://en.wikipedia.org/wiki/Standard_streams#Standard_output_(stdout)>>>). In production, it's recommended to be set to `false`.

For example, if `true`

```
10:37AM INF cmd/pomerium version=v0.0.1-dirty+ede4124
10:37AM INF proxy: new route from=httpbin.corp.beyondperimeter.com to=https://httpbin.org
10:37AM INF proxy: new route from=ssl.corp.beyondperimeter.com to=http://neverssl.com
10:37AM INF proxy/authenticator: grpc connection OverrideCertificateName= addr=auth.corp.beyondperimeter.com:443
```

If `false`

```
{"level":"info","version":"v0.0.1-dirty+ede4124","time":"2019-02-18T10:41:03-08:00","message":"cmd/pomerium"}
{"level":"info","from":"httpbin.corp.beyondperimeter.com","to":"https://httpbin.org","time":"2019-02-18T10:41:03-08:00","message":"proxy: new route"}
{"level":"info","from":"ssl.corp.beyondperimeter.com","to":"http://neverssl.com","time":"2019-02-18T10:41:03-08:00","message":"proxy: new route"}
{"level":"info","OverrideCertificateName":"","addr":"auth.corp.beyondperimeter.com:443","time":"2019-02-18T10:41:03-08:00","message":"proxy/authenticator: grpc connection"}
```

### Forward Auth

- Environmental Variable: `FORWARD_AUTH_URL`
- Config File Key: `forward_auth_url`
- Type: `URL` (must contain a scheme and hostname)
- Example: `https://forwardauth.corp.example.com`
- Resulting Verification URL: `https://forwardauth.corp.example.com/?uri={URL-TO-VERIFY}`
- Optional

Forward authentication creates an endpoint that can be used with third-party proxies that do not have rich access control capabilities ([nginx](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html), [nginx-ingress](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/), [ambassador](https://www.getambassador.io/reference/services/auth-service/), [traefik](https://docs.traefik.io/middlewares/forwardauth/)). Forward authentication allow you to delegate authentication and authorization for each request to Pomerium.

#### Request flow

![pomerium forward auth request flow](./img/auth-flow-diagram.svg)

#### Examples

##### NGINX Ingress

Some reverse-proxies, such as nginx split access control flow into two parts: verification and sign-in redirection. Notice the additional path `/verify` used for `auth-url` indicating to Pomerium that it should return a `401` instead of redirecting and starting the sign-in process.

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: httpbin
  annotations:
    kubernetes.io/ingress.class: "nginx"
    certmanager.k8s.io/issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/auth-url: https://forwardauth.corp.example.com/verify?uri=$scheme://$host$request_uri
    nginx.ingress.kubernetes.io/auth-signin: "https://forwardauth.corp.example.com/?uri=$scheme://$host$request_uri"
spec:
  tls:
    - hosts:
        - httpbin.corp.example.com
      secretName: quickstart-example-tls
  rules:
    - host: httpbin.corp.example.com
      http:
        paths:
          - path: /
            backend:
              serviceName: httpbin
              servicePort: 80
```

#### Traefik docker-compose

If the `forward_auth_url` is also handled by Traefik, you will need to configure Traefik to trust the `X-Forwarded-*` headers as described in [the documentation](https://docs.traefik.io/v2.2/routing/entrypoints/#forwarded-headers).

```yml
version: "3"

services:
  traefik:
    # The official v2.2 Traefik docker image
    image: traefik:v2.2
    # Enables the web UI and tells Traefik to listen to docker
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.web.forwardedheaders.insecure=true"
    ports:
      # The HTTP port
      - "80:80"
      # The Web UI (enabled by --api.insecure=true)
      - "8080:8080"
    volumes:
      # So that Traefik can listen to the Docker events
      - /var/run/docker.sock:/var/run/docker.sock
  httpbin:
    # A container that exposes an API to show its IP address
    image: kennethreitz/httpbin:latest
    labels:
      - "traefik.http.routers.httpbin.rule=Host(`httpbin.corp.example.com`)"
      # Create a middleware named `foo-add-prefix`
      - "traefik.http.middlewares.test-auth.forwardauth.authResponseHeaders=X-Pomerium-Authenticated-User-Email,x-pomerium-authenticated-user-id,x-pomerium-authenticated-user-groups,x-pomerium-jwt-assertion"
      - "traefik.http.middlewares.test-auth.forwardauth.address=http://forwardauth.corp.example.com/?uri=https://httpbin.corp.example.com"
      - "traefik.http.routers.httpbin.middlewares=test-auth@docker"
```

### Global Timeouts

- Environmental Variables: `TIMEOUT_READ` `TIMEOUT_WRITE` `TIMEOUT_IDLE`
- Config File Key: `timeout_read` `timeout_write` `timeout_idle`
- Type: [Go Duration](https://golang.org/pkg/time/#Duration.String) `string`
- Example: `TIMEOUT_READ=30s`
- Defaults: `TIMEOUT_READ=30s` `TIMEOUT_WRITE=0` `TIMEOUT_IDLE=5m`

Timeouts set the global server timeouts. For route-specific timeouts, see [policy](./#policy).

![cloudflare blog on timeouts](https://blog.cloudflare.com/content/images/2016/06/Timeouts-001.png)

> For a deep dive on timeout values see [these](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/) [two](https://blog.cloudflare.com/exposing-go-on-the-internet/) excellent blog posts.

### GRPC Options

These settings control upstream connections to the Authorize service.

#### GRPC Address

- Environmental Variable: `GRPC_ADDRESS`
- Config File Key: `grpc_address`
- Type: `string`
- Example: `:443`, `:8443`
- Default: `:443` or `:5443` if in all-in-one mode

Address specifies the host and port to serve GRPC requests from. Defaults to `:443` (or `:5443` in all in one mode).

#### GRPC Insecure

- Environmental Variable: `GRPC_INSECURE`
- Config File Key: `grpc_insecure`
- Type: `bool`
- Default: `:443` (or `:5443` if in all-in-one mode)

If set, GRPC Insecure disables transport security for communication between the proxy and authorize components. If running in all-in-one mode, defaults to true as communication will run over localhost's own socket.

#### GRPC Client Timeout

Maximum time before canceling an upstream RPC request. During transient failures, the proxy will retry upstreams for this duration, if possible. You should leave this high enough to handle backend service restart and rediscovery so that client requests do not fail.

- Environmental Variable: `GRPC_CLIENT_TIMEOUT`
- Config File Key: `grpc_client_timeout`
- Type: [Go Duration](https://golang.org/pkg/time/#Duration.String) `string`
- Default: `10s`

#### GRPC Client DNS RoundRobin

Enable grpc DNS based round robin load balancing. This method uses DNS to resolve endpoints and does client side load balancing of _all_ addresses returned by the DNS record. Do not disable unless you have a specific use case.

- Environmental Variable: `GRPC_CLIENT_DNS_ROUNDROBIN`
- Config File Key: `grpc_client_dns_roundrobin`
- Type: `bool`
- Default: `true`

#### GRPC Server Max Connection Age

Set max connection age for GRPC servers. After this interval, servers ask clients to reconnect and perform any rediscovery for new/updated endpoints from DNS.

See <https://godoc.org/google.golang.org/grpc/keepalive#ServerParameters> for details

- Environmental Variable: `GRPC_SERVER_MAX_CONNECTION_AGE`
- Config File Key: `grpc_server_max_connection_age`
- Type: [Go Duration](https://golang.org/pkg/time/#Duration.String) `string`
- Default: `5m`

#### GRPC Server Max Connection Age Grace

Additive period with `grpc_server_max_connection_age`, after which servers will force connections to close.

See <https://godoc.org/google.golang.org/grpc/keepalive#ServerParameters> for details

- Environmental Variable: `GRPC_SERVER_MAX_CONNECTION_AGE_GRACE`
- Config File Key: `grpc_server_max_connection_age_grace`
- Type: [Go Duration](https://golang.org/pkg/time/#Duration.String) `string`
- Default: `5m`

### HTTP Redirect Address

- Environmental Variable: `HTTP_REDIRECT_ADDR`
- Config File Key: `http_redirect_addr`
- Type: `string`
- Example: `:80`, `:8080`
- Optional

If set, the HTTP Redirect Address specifies the host and port to redirect http to https traffic on. If unset, no redirect server is started.

### Insecure Server

- Environmental Variable: `INSECURE_SERVER`
- Config File Key: `insecure_server`
- Type: `bool`
- Required if certificates unset

Turning on insecure server mode will result in pomerium starting, and operating without any protocol encryption in transit.

This setting can be useful in a situation where you have Pomerium behind a TLS terminating ingress or proxy. However, even in that case, it is highly recommended to use TLS to protect the confidentiality and integrity of service communication even behind the ingress using self-signed certificates or an internal CA. Please see our helm-chart for an example of just that.

:::warning

Pomerium should _never_ be exposed to the internet without TLS encryption.

:::

### Log Level

- Environmental Variable: `LOG_LEVEL`
- Config File Key: `log_level`
- Type: `string`
- Options: `debug` `info` `warn` `error`
- Default: `debug`

Log level sets the global logging level for pomerium. Only logs of the desired level and above will be logged.

### Metrics Address

- Environmental Variable: `METRICS_ADDRESS`
- Config File Key: `metrics_address`
- Type: `string`
- Example: `:9090`, `127.0.0.1:9090`
- Default: `disabled`
- Optional

Expose a prometheus format HTTP endpoint on the specified port. Disabled by default.

:::warning

**Use with caution:** the endpoint can expose frontend and backend server names or addresses. Do not externally expose the metrics if this is sensitive information.

:::

#### Pomerium Metrics Tracked

| Name                                          | Type      | Description                                                             |
| --------------------------------------------- | --------- | ----------------------------------------------------------------------- |
| grpc_client_request_duration_ms               | Histogram | GRPC client request duration by service                                 |
| grpc_client_request_size_bytes                | Histogram | GRPC client request size by service                                     |
| grpc_client_requests_total                    | Counter   | Total GRPC client requests made by service                              |
| grpc_client_response_size_bytes               | Histogram | GRPC client response size by service                                    |
| grpc_server_request_duration_ms               | Histogram | GRPC server request duration by service                                 |
| grpc_server_request_size_bytes                | Histogram | GRPC server request size by service                                     |
| grpc_server_requests_total                    | Counter   | Total GRPC server requests made by service                              |
| grpc_server_response_size_bytes               | Histogram | GRPC server response size by service                                    |
| http_client_request_duration_ms               | Histogram | HTTP client request duration by service                                 |
| http_client_request_size_bytes                | Histogram | HTTP client request size by service                                     |
| http_client_requests_total                    | Counter   | Total HTTP client requests made by service                              |
| http_client_response_size_bytes               | Histogram | HTTP client response size by service                                    |
| http_server_request_duration_ms               | Histogram | HTTP server request duration by service                                 |
| http_server_request_size_bytes                | Histogram | HTTP server request size by service                                     |
| http_server_requests_total                    | Counter   | Total HTTP server requests handled by service                           |
| http_server_response_size_bytes               | Histogram | HTTP server response size by service                                    |
| pomerium_build_info                           | Gauge     | Pomerium build metadata by git revision, service, version and goversion |
| pomerium_config_checksum_int64                | Gauge     | Currently loaded configuration checksum by service                      |
| pomerium_config_last_reload_success           | Gauge     | Whether the last configuration reload succeeded by service              |
| pomerium_config_last_reload_success_timestamp | Gauge     | The timestamp of the last successful configuration reload by service    |
| redis_conns                                   | Gauge     | Number of total connections in the pool                                 |
| redis_idle_conns                              | Gauge     | Total number of times free connection was found in the pool             |
| redis_wait_count_total                        | Counter   | Total number of connections waited for                                  |
| redis_wait_duration_ms_total                  | Counter   | Total time spent waiting for connections                                |
| storage_operation_duration_ms                 | Histogram | Storage operation duration by operation, result, backend and service    |

#### Envoy Proxy Metrics

As of `v0.9`, Pomerium uses [envoy Proxy]([https://](https://www.envoyproxy.io/) for the data plane. As such, proxy related metrics are sourced from envoy, and use envoy's internal [stats data model](https://www.envoyproxy.io/docs/envoy/latest/operations/stats_overview). Please see Envoy's documentation for information about specific metrics.

All metrics coming from envoy will be labeled with `service="pomerium"` or `service="pomerium-proxy"`, depending if you're running all-in-one or distributed service mode.

### Proxy Log Level

- Environmental Variable: `PROXY_LOG_LEVEL`
- Config File Key: `proxy_log_level`
- Type: `string`
- Options: `debug` `info` `warn` `error`
- Default: value of `log_level` or `debug` if both are unset

Log level sets the logging level for the pomerium proxy service. Only logs of the desired level and above will be logged.

### Service Mode

- Environmental Variable: `SERVICES`
- Config File Key: `services`
- Type: `string`
- Default: `all`
- Options: `all` `authenticate` `authorize` `cache` or `proxy`

Service mode sets the pomerium service(s) to run. If testing, you may want to set to `all` and run pomerium in "all-in-one mode." In production, you'll likely want to spin up several instances of each service mode for high availability.

### Shared Secret

- Environmental Variable: `SHARED_SECRET`
- Config File Key: `shared_secret`
- Type: [base64 encoded] `string`
- Required

Shared Secret is the base64 encoded 256-bit key used to mutually authenticate requests between services. It's critical that secret keys are random, and stored safely. Use a key management system or `/dev/urandom/` to generate a key. For example:

```
head -c32 /dev/urandom | base64
```

### Tracing

Tracing tracks the progression of a single user request as it is handled by Pomerium.

Each unit work is called a Span in a trace. Spans include metadata about the work, including the time spent in the step (latency), status, time events, attributes, links. You can use tracing to debug errors and latency issues in your applications, including in downstream connections.

#### Shared Tracing Settings

| Config Key          | Description                                                                          | Required |
| :------------------ | :----------------------------------------------------------------------------------- | -------- |
| tracing_provider    | The name of the tracing provider. (e.g. jaeger, zipkin)                              | ✅        |
| tracing_sample_rate | Percentage of requests to sample in decimal notation. Default is `0.0001`, or `.01%` | ❌        |

#### Jaeger (partial)

**Warning** At this time, Jaeger protocol does not capture spans inside the proxy service. Please use Zipkin protocol with Jaeger for full support.

[Jaeger](https://www.jaegertracing.io/) is a distributed tracing system released as open source by Uber Technologies. It is used for monitoring and troubleshooting microservices-based distributed systems, including:

- Distributed context propagation
- Distributed transaction monitoring
- Root cause analysis
- Service dependency analysis
- Performance / latency optimization

| Config Key                        | Description                                 | Required |
| :-------------------------------- | :------------------------------------------ | -------- |
| tracing_jaeger_collector_endpoint | Url to the Jaeger HTTP Thrift collector.    | ✅        |
| tracing_jaeger_agent_endpoint     | Send spans to jaeger-agent at this address. | ✅        |

#### Zipkin

Zipkin is an open source distributed tracing system and protocol.

Many tracing backends support zipkin either directly or through intermediary agents, including Jaeger. For full tracing support, we recommend using the Zipkin tracing protocol.

| Config Key              | Description                      | Required |
| :---------------------- | :------------------------------- | -------- |
| tracing_zipkin_endpoint | Url to the Zipkin HTTP endpoint. | ✅        |

#### Example

![jaeger example trace](./img/jaeger.png) pomerium_config_last_reload_success_timestamp | Gauge | The timestamp of the last successful configuration reload by service pomerium_build_info | Gauge | Pomerium build metadata by git revision, service, version and goversion

## Authenticate Service

### Authenticate Callback Path

- Environmental Variable: `AUTHENTICATE_CALLBACK_PATH`
- Config File Key: `authenticate_callback_path`
- Type: `string`
- Default: `/oauth2/callback`
- Optional

The authenticate callback path is the path/url from the authenticate service that will receive the response from your identity provider. The value must exactly match one of the authorized redirect URIs for the OAuth 2.0 client.

This value is referred to as the `redirect_url` in the [OpenIDConnect][oidc rfc] and OAuth2 specs.

See also:

- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749#section-3.1.2)
- [OIDC Spec][oidc rfc]
- [Google - Setting Redirect URI](https://developers.google.com/identity/protocols/OpenIDConnect#setredirecturi)

### Authenticate Service URL

- Environmental Variable: `AUTHENTICATE_SERVICE_URL`
- Config File Key: `authenticate_service_url`
- Type: `URL`
- Required
- Example: `https://authenticate.corp.example.com`

Authenticate Service URL is the externally accessible URL for the authenticate service.

### Identity Provider Client ID

- Environmental Variable: `IDP_CLIENT_ID`
- Config File Key: `idp_client_id`
- Type: `string`
- Required

Client ID is the OAuth 2.0 Client Identifier retrieved from your identity provider. See your identity provider's documentation, and our [identity provider] docs for details.

### Identity Provider Client Secret

- Environmental Variable: `IDP_CLIENT_SECRET`
- Config File Key: `idp_client_secret`
- Type: `string`
- Required

Client Secret is the OAuth 2.0 Secret Identifier retrieved from your identity provider. See your identity provider's documentation, and our [identity provider] docs for details.

### Identity Provider Name

- Environmental Variable: `IDP_PROVIDER`
- Config File Key: `idp_provider`
- Type: `string`
- Required
- Options: `azure` `google` `okta` `onelogin` or `oidc`

Provider is the short-hand name of a built-in OpenID Connect (oidc) identity provider to be used for authentication. To use a generic provider,set to `oidc`.

See [identity provider] for details.

### Identity Provider Scopes

- Environmental Variable: `IDP_SCOPES`
- Config File Key: `idp_scopes`
- Type: `[]string` comma separated list of oauth scopes.
- Default: `oidc`,`profile`, `email`, `offline_access` (typically)
- Optional for built-in identity providers.

Identity provider scopes correspond to access privilege scopes as defined in Section 3.3 of OAuth 2.0 RFC6749\. The scopes associated with Access Tokens determine what resources will be available when they are used to access OAuth 2.0 protected endpoints. If you are using a built-in provider, you probably don't want to set customized scopes.

### Identity Provider Service Account

- Environmental Variable: `IDP_SERVICE_ACCOUNT`
- Config File Key: `idp_service_account`
- Type: `string`
- Required for group based policies

Identity Provider Service Account is field used to configure any additional user account or access-token that may be required for querying additional user information during authentication.

**All group membership from an IdP is queried via service account.**

### Identity Provider URL

- Environmental Variable: `IDP_PROVIDER_URL`
- Config File Key: `idp_provider_url`
- Type: `string`
- Required, depending on provider

Provider URL is the base path to an identity provider's [OpenID connect discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html). For example, google's URL would be `https://accounts.google.com` for [their discover document](https://accounts.google.com/.well-known/openid-configuration).

### Identity Provider Request Params

- Environmental Variable: `IDP_REQUEST_PARAMS`
- Config File Key: `idp_request_params`
- Type: map of `strings` key value pairs
- Optional

Request parameters to be added as part of a signin request using OAuth2 code flow.

For more information see:

- [OIDC Request Parameters](https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters)
- [IANA OAuth Parameters](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml)
- [Microsoft Azure Request params](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code)
- [Google Authentication URI parameters](https://developers.google.com/identity/protocols/oauth2/openid-connect)

### Identity Provider Refresh Directory Settings

- Environmental Variables: `IDP_REFRESH_DIRECTORY_INTERVAL` `IDP_REFRESH_DIRECTORY_TIMEOUT`
- Config File Key: `idp_refresh_directory_interval` `idp_refresh_directory_timeout`
- Type: [Go Duration](https://golang.org/pkg/time/#Duration.String) `string`
- Example: `IDP_REFRESH_DIRECTORY_INTERVAL=30m`
- Defaults: `IDP_REFRESH_DIRECTORY_INTERVAL=10m` `IDP_REFRESH_DIRECTORY_TIMEOUT=1m`

Refresh directory interval is the time that pomerium will sync your IDP diretory, while refresh directory timeout is the
maximum time allow each run. Use it at your ownn risk, if you set a too low value, you may reach IDP API rate limit.

## Proxy Service

### Authenticate Service URL

- Environmental Variable: `AUTHENTICATE_SERVICE_URL`
- Config File Key: `authenticate_service_url`
- Type: `URL`
- Required
- Example: `https://authenticate.corp.example.com`

Authenticate Service URL is the externally accessible URL for the authenticate service.

### Authorize Service URL

- Environmental Variable: `AUTHORIZE_SERVICE_URL`
- Config File Key: `authorize_service_url`
- Type: `URL`
- Required; inferred in all-in-one mode to be localhost.
- Example: `https://pomerium-authorize-service.default.svc.cluster.local` or `https://localhost:5443`

Authorize Service URL is the location of the internally accessible authorize service. NOTE: Unlike authenticate, authorize has no publicly accessible http handlers so this setting is purely for gRPC communication.

If your load balancer does not support gRPC pass-through you'll need to set this value to an internally routable location (`https://pomerium-authorize-service.default.svc.cluster.local`) instead of an externally routable one (`https://authorize.corp.example.com`).

### Certificate Authority

- Environmental Variable: `CERTIFICATE_AUTHORITY` or `CERTIFICATE_AUTHORITY_FILE`
- Config File Key: `certificate_authority` or `certificate_authority_file`
- Type: [base64 encoded] `string` or relative file location
- Optional

Certificate Authority is set when behind-the-ingress service communication uses self-signed certificates. Be sure to include the intermediary certificate.

### Default Upstream Timeout

- Environmental Variable: `DEFAULT_UPSTREAM_TIMEOUT`
- Config File Key: `default_upstream_timeout`
- Type: [Duration](https://golang.org/pkg/time/#Duration) `string`
- Example: `10m`, `1h45m`
- Default: `30s`

Default Upstream Timeout is the default timeout applied to a proxied route when no `timeout` key is specified by the policy.

### Headers

- Environmental Variable: `HEADERS`
- Config File Key: `headers`
- Type: map of `strings` key value pairs
- Examples:

  - Comma Separated: `X-Content-Type-Options:nosniff,X-Frame-Options:SAMEORIGIN`
  - JSON: `'{"X-Test": "X-Value"}'`
  - YAML:

    ```yaml
    headers:
      X-Test: X-Value
    ```

- To disable: `disable:true`

- Default :

  ```javascript
  X-Content-Type-Options : nosniff,
  X-Frame-Options:SAMEORIGIN,
  X-XSS-Protection:1; mode=block,
  Strict-Transport-Security:max-age=31536000; includeSubDomains; preload,
  ```

Headers specifies a mapping of [HTTP Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) to be added to proxied requests. _Nota bene_ Downstream application headers will be overwritten by Pomerium's headers on conflict.

By default, conservative [secure HTTP headers](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project) are set.

![pomerium security headers](./img/security-headers.png)

### JWT Claim Headers

- Environmental Variable: `JWT_CLAIMS_HEADERS`
- Config File Key: `jwt_claims_headers`
- Type: slice of `string`
- Example: `email`,`groups`, `user`
- Optional

The JWT Claim Headers setting allows you to pass specific user session data down to downstream applications as HTTP request headers. Note, unlike the header `x-pomerium-jwt-assertion` these values are not signed by the authorization service.

Any claim in the pomerium session JWT can be placed into a corresponding header for downstream consumption. This claim information is sourced from your Identity Provider (IdP) and Pomerium's own session metadata. The header will have the following format:

`X-Pomerium-Claim-{Name}` where `{Name}` is the name of the claim requested.

Use this option if you previously relied on `x-pomerium-authenticated-user-{email|user-id|groups}` for downstream authN/Z.

### Override Certificate Name

- Environmental Variable: `OVERRIDE_CERTIFICATE_NAME`
- Config File Key: `override_certificate_name`
- Type: `int`
- Optional
- Example: `*.corp.example.com` if wild card or `authenticate.corp.example.com`/`authorize.corp.example.com`

Secure service communication can fail if the external certificate does not match the internally routed service hostname/[SNI](https://en.wikipedia.org/wiki/Server_Name_Indication). This setting allows you to override that value.

### Refresh Cooldown

- Environmental Variable: `REFRESH_COOLDOWN`
- Config File Key: `refresh_cooldown`
- Type: [Duration](https://golang.org/pkg/time/#Duration) `string`
- Example: `10m`, `1h45m`
- Default: `5m`

Refresh cooldown is the minimum amount of time between allowed manually refreshed sessions.

## Cache Service

The cache service is used for storing user session data.

### Data Broker Service URL

- Environmental Variable: `DATABROKER_SERVICE_URL`
- Config File Key: `databroker_service_url`
- Type: `URL`
- Example: `https://cache.corp.example.com`
- Default: in all-in-one mode, `http://localhost:5443`

The data broker service URL points to a data broker which is responsible for storing sessions, users and user groups. The `cache` service implements a basic in-memory databroker, so the legacy option `cache_service_url` will be used if this option is not configured.

To create your own data broker, implement the following gRPC interface:

- [pkg/grpc/databroker/databroker.proto](https://github.com/pomerium/pomerium/blob/master/pkg/grpc/databroker/databroker.proto)

For an example implementation, the in-memory database used by the cache service can be found here:

- [pkg/databroker/memory](https://github.com/pomerium/pomerium/tree/master/pkg/databroker/memory)

### Data Broker Storage Type

- Environmental Variable: `DATABROKER_STORAGE_TYPE`
- Config File Key: `databroker_storage_type`
- Type: `string`
- Optional
- Example: `redis`
- Default: `memory`

The backend storage that databroker server will use, available types: `memory`, `redis`.

### Data Broker Storage Connection String

- Environmental Variable: `DATABROKER_STORAGE_CONNECTION_STRING`
- Config File Key: `databroker_storage_connection_string`
- Type: `string`
- **Required** when storage type is `redis`
- Example: `"redis://localhost:6379/0"`

The connection string that server will use to connect to storage backend.

## Policy

- Environmental Variable: `POLICY`
- Config File Key: `policy`
- Type: [base64 encoded] `string` or inline policy structure in config file
- **Required** However, pomerium will safely start without a policy configured, but will be unable to authorize or proxy traffic until the configuration is updated to contain a policy.

Policy contains route specific settings, and access control details. If you are configuring via POLICY environment variable, just the contents of the policy needs to be passed. If you are configuring via file, the policy should be present under the policy key. For example,

<<< @/examples/config/policy.example.yaml

Policy routes are checked in the order they appear in the policy, so more specific routes should appear before less specific routes. For example:

```yaml
policies:
  - from: http://from.example.com
    to: http://to.example.com
    prefix: /admin
    allowed_groups: ["superuser"]
  - from: http://from.example.com
    to: http://to.example.com
    allow_public_unauthenticated_access: true
```

In this example an incoming request with a path prefix of `/admin` would be handled by the first route (which is restricted to superusers). All other requests for `from.example.com` would be handled by the second route (which is open to the public).

A list of policy configuration variables follows.

### Allowed Domains

- `yaml`/`json` setting: `allowed_domains`
- Type: collection of `strings`
- Required
- Example: `pomerium.io` , `gmail.com`

Allowed domains is a collection of whitelisted domains to authorize for a given route.

### Allowed Groups

- `yaml`/`json` setting: `allowed_groups`
- Type: collection of `strings`
- Required
- Example: `admins` , `support@company.com`

Allowed groups is a collection of whitelisted groups to authorize for a given route.

### Allowed Users

- `yaml`/`json` setting: `allowed_users`
- Type: collection of `strings`
- Required
- Example: `alice@pomerium.io` , `bob@contractor.co`

Allowed users is a collection of whitelisted users to authorize for a given route.

### CORS Preflight

- `yaml`/`json` setting: `cors_allow_preflight`
- Type: `bool`
- Optional
- Default: `false`

Allow unauthenticated HTTP OPTIONS requests as [per the CORS spec](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests).


### Enable Google Cloud Serverless Authentication

- Environmental Variable: `ENABLE_GOOGLE_CLOUD_SERVERLESS_AUTHENTICATION`
- Config File Key: `enable_google_cloud_serverless_authentication`
- Type: `bool`
- Default: `false`

Enable sending a signed [Authorization Header](https://cloud.google.com/run/docs/authenticating/service-to-service) to upstream GCP services.

Requires setting [Google Cloud Serverless Authentication Service Account](./#google-cloud-serverless-authentication-service-account) or running Pomerium in an environment with a GCP service account present in default locations.

### From

- `yaml`/`json` setting: `from`
- Type: `URL` (must contain a scheme and hostname, must not contain a path)
- Required
- Example: `https://httpbin.corp.example.com`

`From` is externally accessible source of the proxied request.

### Path

- `yaml`/`json` setting: `path`
- Type: `string`
- Optional
- Example: `/admin/some/exact/path`

If set, the route will only match incoming requests with a path that is an exact match for the specified path.

### Prefix

- `yaml`/`json` setting: `prefix`
- Type: `string`
- Optional
- Example: `/admin`

If set, the route will only match incoming requests with a path that begins with the specified prefix.

### Public Access

- `yaml`/`json` setting: `allow_public_unauthenticated_access`
- Type: `bool`
- Optional
- Default: `false`

**Use with caution:** Allow all requests for a given route, bypassing authentication and authorization. Suitable for publicly exposed web services.

If this setting is enabled, no whitelists (e.g. Allowed Users) should be provided in this route.

### Regex

- `yaml`/`json` setting: `regex`
- Type: `string` (containing a regular expression)
- Optional
- Example: `^/(admin|superuser)/.*$`

If set, the route will only match incoming requests with a path that matches the specified regular expression. The supported syntax is the same as the Go [regexp package](https://golang.org/pkg/regexp/) which is based on [re2](https://github.com/google/re2/wiki/Syntax).

### Route Timeout

- `yaml`/`json` setting: `timeout`
- Type: [Go Duration](https://golang.org/pkg/time/#Duration.String) `string`
- Optional
- Default: `30s`

Policy timeout establishes the per-route timeout value. Cannot exceed global timeout values.

### Preserve Host Header

- `yaml`/`json` setting: `preserve_host_header`
- Type: `bool`
- Optional
- Default: `false`

When enabled, this option will pass the host header from the incoming request to the proxied host, instead of the destination hostname.

See [ProxyPreserveHost](http://httpd.apache.org/docs/2.0/mod/mod_proxy.html#proxypreservehost).

### Set Request Headers

- Config File Key: `set_request_headers`
- Type: map of `strings` key value pairs
- Optional

Set Request Headers allows you to set static values for given request headers. This can be useful if you want to pass along additional information to downstream applications as headers, or set authentication header to the request. For example:

```yaml
- from: https://httpbin.corp.example.com
  to: https://httpbin.org
  allowed_users:
    - bdd@pomerium.io
  set_request_headers:
    # works auto-magically!
    # https://httpbin.corp.example.com/basic-auth/root/hunter42
    Authorization: Basic cm9vdDpodW50ZXI0Mg==
    X-Your-favorite-authenticating-Proxy: "Pomerium"
```

### Remove Request Headers

- Config File Key: `removet_request_headers`
- Type: array of `strings`
- Optional

Remove Request Headers allows you to remove given request headers. This can be useful if you want to prevent privacy information from being passed to downstream applications. For example:

```yaml
- from: https://httpbin.corp.example.com
  to: https://httpbin.org
  allowed_users:
    - bdd@pomerium.io
  remove_request_headers:
    - X-Email
    - X-Username
```

### To

- `yaml`/`json` setting: `to`
- Type: `URL` (must contain a scheme and hostname)
- Required
- Example: `http://httpbin` , `https://192.1.20.12:8080`, `http://neverssl.com`, `https://httpbin.org/anything/`

`To` is the destination of a proxied request. It can be an internal resource, or an external resource.

Be careful with trailing slash.

With rule:
 
```yaml
- from: https://httpbin.corp.example.com
  to: https://httpbin.org/anything
```

Requests to `https://httpbin.corp.example.com` will be forwarded to `https://httpbin.org/anything`, while requests to
`https://httpbin.corp.example.com/foo` will be forwarded to `https://httpbin.org/anythingfoo`.To make the request forwarded to
`https://httbin.org/anything/foo`, you can use double slashes in your request `https://httbin.corp.example.com//foo`.

While with rule:

```yaml
- from: https://httpbin.corp.example.com
  to: https://httpbin.org/anything/
```

All requests to `https://httpbin.corp.example.com/*` will be forwarded to `https://httpbin.org/anything/*`. That means accessing to
`https://httpbin.corp.example.com` will be forwarded to `https://httpbin.org/anything/`. That said, if your application does not handle
trailing slash, the request will end up with 404 not found.

### TLS Skip Verification

- Config File Key: `tls_skip_verify`
- Type: `bool`
- Default: `false`

TLS Skip Verification controls whether a client verifies the server's certificate chain and host name. If enabled, TLS accepts any certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing.

### TLS Server Name

- Config File Key: `tls_server_name`
- Type: `string`
- Optional

TLS Server Name overrides the hostname you specified in the `to` field. If set, this server name will be used to verify server side certificate. This is useful when the backend of your service is an HTTPS server with valid certificate, but you want to communicate via an internal hostname or IP address.

### TLS Custom Certificate Authority

- Config File Key: `tls_custom_ca` or `tls_custom_ca_file`
- Type: [base64 encoded] `string` or relative file location
- Optional

TLS Custom Certificate Authority defines the set of root certificate authorities that clients use when verifying server certificates.

Note: This setting will replace (not append) the system's trust store for a given route.

### TLS Client Certificate

- Config File Key: `tls_client_cert` and `tls_client_key` or `tls_client_cert_file` and `tls_client_key_file`
- Type: [base64 encoded] `string` or relative file location
- Optional

Pomerium supports client certificates which can be used to enforce [mutually authenticated and encrypted TLS connections](https://en.wikipedia.org/wiki/Mutual_authentication) (mTLS). For more details, see our [mTLS example repository](https://github.com/pomerium/examples/tree/master/mutual-tls) and the [certificate docs](../docs/reference/certificates.md).

### Websocket Connections

- Config File Key: `allow_websockets`
- Type: `bool`
- Default: `false`

If set, enables proxying of websocket connections.

**Use with caution:** By definition, websockets are long-lived connections, so [global timeouts](#global-timeouts) are not enforced. Allowing websocket connections to the proxy could result in abuse via [DOS attacks](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/).

### Pass Identity Headers

- `yaml`/`json` setting: `pass_identity_headers`
- Type: `bool`
- Optional
- Default: `false`

When enabled, this option will pass the identity headers to the downstream application. These headers include:

- X-Pomerium-Jwt-Assertion
- X-Pomerium-Claim-*

## Authorize Service

### Authenticate Service URL

- Environmental Variable: `AUTHENTICATE_SERVICE_URL`
- Config File Key: `authenticate_service_url`
- Type: `URL`
- Required
- Example: `https://authenticate.corp.example.com`

Authenticate Service URL is the externally accessible URL for the authenticate service.

### Google Cloud Serverless Authentication Service Account

- Environmental Variable: `GOOGLE_CLOUD_SERVERLESS_AUTHENTICATION_SERVICE_ACCOUNT`
- Config File Key: `google_cloud_serverless_authentication_service_account`
- Type: [base64 encoded] `string`
- Optional

Manually specify the service account credentials to support GCP's [Authorization Header](https://cloud.google.com/run/docs/authenticating/service-to-service) format.

If unspecified: 

- If [Identity Provider Name](#identity-provider-name) is set to `google`, will default to [Identity Provider Service Account](#identity-provider-service-account) 
- Otherwise, will default to ambient credentials in the default locations searched by the Google SDK.  This includes GCE metadata server tokens.

### Signing Key

- Environmental Variable: `SIGNING_KEY`
- Config File Key: `signing_key`
- Type: [base64 encoded] `string`
- Optional

Signing Key is the key used to sign a user's attestation JWT which can be consumed by upstream applications to pass along identifying user information like username, id, and groups.

If set, the signing key's public key will can retrieved by hitting Pomerium's `/.well-known/pomerium/jwks.json` endpoint which lives on the authenticate service. For example:

```bash
$ curl https://authenticate.int.example.com/.well-known/pomerium/jwks.json | jq
```

```json
{
  "keys": [
    {
      "use": "sig",
      "kty": "EC",
      "kid": "ccc5bc9d835ff3c8f7075ed4a7510159cf440fd7bf7b517b5caeb1fa419ee6a1",
      "crv": "P-256",
      "alg": "ES256",
      "x": "QCN7adG2AmIK3UdHJvVJkldsUc6XeBRz83Z4rXX8Va4",
      "y": "PI95b-ary66nrvA55TpaiWADq8b3O1CYIbvjqIHpXCY"
    }
  ]
}
```

If no certificate is specified, one will be generated and the base64'd public key will be added to the logs. Note, however, that this key be unique to each service, ephemeral, and will not be accessible via the authenticate service's `jwks_uri` endpoint.

[base64 encoded]: https://en.wikipedia.org/wiki/Base64
[environmental variables]: https://en.wikipedia.org/wiki/Environment_variable
[identity provider]: ../docs/identity-providers/
[json]: https://en.wikipedia.org/wiki/JSON
[letsencrypt]: https://letsencrypt.org/
[oidc rfc]: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[signed headers]: ./signed-headers.md
[toml]: https://en.wikipedia.org/wiki/TOML
[yaml]: https://en.wikipedia.org/wiki/YAML
