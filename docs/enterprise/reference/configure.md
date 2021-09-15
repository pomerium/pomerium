---
title: Configure
lang: en-US
sidebarDepth: 2
meta:
    - name: keywords
      content: configuration options settings Pomerium Enterprise
---

# Configure

## Settings


### Global


#### Debug

::: danger

Enabling the debug flag could result in sensitive information being logged!!!

:::

By default, JSON encoded logs are produced. Debug enables colored, human-readable logs to be streamed to [standard out](https://en.wikipedia.org/wiki/Standard_streams#Standard_output_(stdout)>>>). In production, it is recommended to be set to `false`.

For example, if `true`

```
10:37AM INF cmd/pomerium version=v0.0.1-dirty+ede4124
10:37AM INF proxy: new route from=verify.localhost.pomerium.io to=https://verify.pomerium.com
10:37AM INF proxy: new route from=ssl.localhost.pomerium.io to=http://neverssl.com
10:37AM INF proxy/authenticator: grpc connection OverrideCertificateName= addr=auth.localhost.pomerium.io:443
```

If `false`

```
{"level":"info","version":"v0.0.1-dirty+ede4124","time":"2019-02-18T10:41:03-08:00","message":"cmd/pomerium"}
{"level":"info","from":"verify.localhost.pomerium.io","to":"https://verify.pomerium.com","time":"2019-02-18T10:41:03-08:00","message":"proxy: new route"}
{"level":"info","from":"ssl.localhost.pomerium.io","to":"http://neverssl.com","time":"2019-02-18T10:41:03-08:00","message":"proxy: new route"}
{"level":"info","OverrideCertificateName":"","addr":"auth.localhost.pomerium.io:443","time":"2019-02-18T10:41:03-08:00","message":"proxy/authenticator: grpc connection"}
```

#### Forward Auth

Forward authentication creates an endpoint that can be used with third-party proxies that do not have rich access control capabilities ([nginx](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html), [nginx-ingress](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/), [ambassador](https://www.getambassador.io/reference/services/auth-service/), [traefik](https://docs.traefik.io/middlewares/forwardauth/)). Forward authentication allows you to delegate authentication and authorization for each request to Pomerium.

#### Request flow

![pomerium forward auth request flow](./img/auth-flow-diagram.svg)

#### Examples

##### NGINX Ingress

Some reverse-proxies, such as nginx split access control flow into two parts: verification and sign-in redirection. Notice the additional path `/verify` used for `auth-url` indicating to Pomerium that it should return a `401` instead of redirecting and starting the sign-in process.

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: verify
  annotations:
    kubernetes.io/ingress.class: "nginx"
    certmanager.k8s.io/issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/auth-url: https://forwardauth.corp.example.com/verify?uri=$scheme://$host$request_uri
    nginx.ingress.kubernetes.io/auth-signin: "https://forwardauth.corp.example.com/?uri=$scheme://$host$request_uri"
spec:
  tls:
    - hosts:
        - verify.corp.example.com
      secretName: quickstart-example-tls
  rules:
    - host: verify.corp.example.com
      http:
        paths:
          - path: /
            backend:
              serviceName: verify
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
  verify:
    # A container that exposes an API to show its IP address
    image: pomerium/verify:latest
    labels:
      - "traefik.http.routers.verify.rule=Host(`verify.corp.example.com`)"
      # Create a middleware named `foo-add-prefix`
      - "traefik.http.middlewares.test-auth.forwardauth.authResponseHeaders=X-Pomerium-Authenticated-User-Email,x-pomerium-authenticated-user-id,x-pomerium-authenticated-user-groups,x-pomerium-jwt-assertion"
      - "traefik.http.middlewares.test-auth.forwardauth.address=http://forwardauth.corp.example.com/?uri=https://verify.corp.example.com"
      - "traefik.http.routers.verify.middlewares=test-auth@docker"
```

#### HTTP Redirect Address

If set, the HTTP Redirect Address specifies the host and port to redirect http to https traffic on. If unset, no redirect server is started.

#### DNS Lookup Family

The DNS IP address resolution policy. If not specified, the value defaults to `AUTO`.

#### Log Level

Log level sets the global logging level for pomerium. Only logs of the desired level and above will be logged.

#### Proxy Log Level

Proxy log level sets the logging level for the pomerium proxy service access logs. Only logs of the desired level and above will be logged.

#### Enable User Impersonation


### Cookies


#### HTTPS Only

If true, instructs browsers to only send user session cookies over HTTPS.

:::warning

Setting this to false may result in session cookies being sent in cleartext.

:::

#### Javascript Security

If true, prevents javascript in browsers from reading user session cookies.

:::warning

Setting this to false enables hostile javascript to steal session cookies and impersonate users.

:::

#### Expires

Sets the lifetime of session cookies. After this interval, users must reauthenticate.

### Timeouts

Timeouts set the global server timeouts. Timeouts can also be set for individual routes.

### GRPC


#### GRPC Server Max Connection Age

Set max connection age for GRPC servers. After this interval, servers ask clients to reconnect and perform any rediscovery for new/updated endpoints from DNS.

See https://godoc.org/google.golang.org/grpc/keepalive#ServerParameters for details


#### GRPC Server Max Connection Age Grace

Additive period with grpc_server_max_connection_age, after which servers will force connections to close.

See https://godoc.org/google.golang.org/grpc/keepalive#ServerParameters (opens new window)for details


### Tracing

Tracing tracks the progression of a single user request as it is handled by Pomerium.

Each unit of work is called a Span in a trace. Spans include metadata about the work, including the time spent in the step (latency), status, time events, attributes, links. You can use tracing to debug errors and latency issues in your applications, including in downstream connections.


#### Tracing Sample Rate

Percentage of requests to sample. Default is .01%.

Unlike the decimal value notion used for the `tracing_sample_rate` [key](/reference/readme.md#shared-tracing-settings) in open-source Pomerium, this value is a percentage, e.g. a value of `1` equates to 1%


### Authenticate


### Proxy


#### Certificate Authority

Certificate Authority is set when behind-the-ingress service communication uses custom or self-signed certificates.

:::warning

Be sure to include the intermediary certificate.

:::

#### Default Upstream Timeout

Default Upstream Timeout is the default timeout applied to a proxied route when no `timeout` key is specified by the policy.

#### JWT Claim Headers

The JWT Claim Headers setting allows you to pass specific user session data down to upstream applications as HTTP request headers. Note, unlike the header `x-pomerium-jwt-assertion` these values are not signed by the authorization service.

Any claim in the pomerium session JWT can be placed into a corresponding header for upstream consumption. This claim information is sourced from your Identity Provider (IdP) and Pomerium's own session metadata. The header will have the following format:

`X-Pomerium-Claim-{Name}` where `{Name}` is the name of the claim requested.

This option also supports a nested object to customize the header name. For example:

```yaml
jwt_claims_headers:
  X-Email: email
```

Will add an `X-Email` header with a value of the `email` claim.

Use this option if you previously relied on `x-pomerium-authenticated-user-{email|user-id|groups}`.

#### X-Forward-For HTTP Header

Do not append proxy IP address to `x-forwarded-for` HTTP header. See [Envoy](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html?highlight=skip_xff_append#x-forwarded-for) docs for more detail.

#### Response Headers

Set Response Headers allows you to set static values for the given response headers. These headers will take precedence over the global `set_response_headers`.

## Service Accounts

See [Concepts: Service Accounts][service-accounts-concept].


## Namespaces

A [Namespace][namespace-concept] is a collection of users, groups, routes, and policies that allows system administrators to organize, manage, and delegate permissions across their infrastructure.

- Policies can be optional or enforced on a Namespace.
   - Enforced policies are also enforced on child Namespaces, and optional policies are available to them as well.
- Users or groups can be granted permission to edit access to routes within a Namespace, allowing them self-serve access to the routes critical to their work.

::: tip
When using an IdP without directory sync or when working with non-domain users, they will not show up in the look-ahead search. See [Non-Domain Users](/enterprise/concepts.html#non-domain-users) for more information.
:::


[route-concept]: /enterprise/concepts.md#routes
[route-reference]: /enterprise/reference/manage.md#routes
[namespace-concept]: /enterprise/concepts.md#namespaces
[namespace-reference]: /enterprise/reference/configure.md#namespaces
[service-accounts-concept]: /enterprise/concepts.md#service-accounts
[policy-reference]: /enterprise/reference/manage.md#policies-2
