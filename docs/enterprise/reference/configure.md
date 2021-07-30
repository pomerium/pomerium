---
title: Configure
lang: en-US
sidebarDepth: 2
meta:
    - name: keywords
      content: configuration options settings Pomerium enterprise console
---

# Configure

## Settings


### Global


#### Administrators

A list of users with full access to the Pomerium Enterprise Console

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

See <https://godoc.org/google.golang.org/grpc/keepalive#ServerParameters> for details

#### GRPC Server Max Connection Age Grace

Additive period with `grpc_server_max_connection_age`, after which servers will force connections to close.

See <https://godoc.org/google.golang.org/grpc/keepalive#ServerParameters> for details

### Tracing

Tracing tracks the progression of a single user request as it is handled by Pomerium.

Each unit work is called a Span in a trace. Spans include metadata about the work, including the time spent in the step (latency), status, time events, attributes, links. You can use tracing to debug errors and latency issues in your applications, including in downstream connections.

#### Shared Tracing Settings

Config Key          | Description                                                                          | Required
:------------------ | :----------------------------------------------------------------------------------- | --------
tracing_provider    | The name of the tracing provider. (e.g. jaeger, zipkin)                              | ✅
tracing_sample_rate | Percentage of requests to sample in decimal notation. Default is `0.0001`, or `.01%` | ❌

#### Datadog

Datadog is a real-time monitoring system that supports distributed tracing and monitoring.

Config Key              | Description                                                                  | Required
:---------------------- | :--------------------------------------------------------------------------- | --------
tracing_datadog_address | `host:port` address of the Datadog Trace Agent. Defaults to `localhost:8126` | ❌

#### Jaeger (partial)

**Warning** At this time, Jaeger protocol does not capture spans inside the proxy service. Please use Zipkin protocol with Jaeger for full support.

[Jaeger](https://www.jaegertracing.io/) is a distributed tracing system released as open source by Uber Technologies. It is used for monitoring and troubleshooting microservices-based distributed systems, including:

- Distributed context propagation
- Distributed transaction monitoring
- Root cause analysis
- Service dependency analysis
- Performance / latency optimization

Config Key                        | Description                                 | Required
:-------------------------------- | :------------------------------------------ | --------
tracing_jaeger_collector_endpoint | Url to the Jaeger HTTP Thrift collector.    | ✅
tracing_jaeger_agent_endpoint     | Send spans to jaeger-agent at this address. | ✅

#### Zipkin

Zipkin is an open source distributed tracing system and protocol.

Many tracing backends support zipkin either directly or through intermediary agents, including Jaeger. For full tracing support, we recommend using the Zipkin tracing protocol.

Config Key              | Description                      | Required
:---------------------- | :------------------------------- | --------
tracing_zipkin_endpoint | Url to the Zipkin HTTP endpoint. | ✅

#### Example

![jaeger example trace](./img/jaeger.png)

### Authenticate


### Authorize


### Proxy


## Service Accounts

See [Concepts: Service Accounts][service-accounts-concept].


## Namespaces

A [Namespace][namespace-concept] is a collection of users, groups, routes, and policies that allows system administrators to organize, manage, and delegate permissions across their infrastructure.

- Policies can be optional or enforced on a Namespace, and they can be nested to create inheritance.
- Users or groups can be granted permission to edit access to routes within a Namespace, allowing them self-serve access to the routes critical to their work.


[route-concept]: /enterprise/concepts.md#routes
[route-reference]: /enterprise/reference/manage.md#routes
[namespace-concept]: /enterprise/concepts.md#namespaces
[namespace-reference]: /enterprise/reference/configure.md#namespaces
[service-accounts-concept]: /enterprise/concepts.md#service-accounts
