---
title: Manage
lang: en-US
sidebarDepth: 2
meta:
    - name: keywords
      content: configuration options settings Pomerium enterprise console
---

# Manage

## Routes

A Route provides access to a service through Pomerium.


### General

The **General** tab defines the route path, both from the internet and to the internal service, and the policies attached. Note that policies enforced on a Namespace the Route resides in will also be applied.


#### Name

This value is only visible in the Console UI.

#### From

`From` is the externally accessible URL for the proxied request.

Specifying `tcp+https` for the scheme enables [TCP proxying](../docs/topics/tcp-support.md) support for the route. You may map more than one port through the same hostname by specifying a different `:port` in the URL.

#### To

`To` is the destination(s) of a proxied request. It can be an internal resource, or an external resource. Multiple upstream resources can be targeted by using a list instead of a single URL:

```yaml
- from: https://example.com
  to:
  - https://a.example.com
  - https://b.example.com
```

A load balancing weight may be associated with a particular upstream by appending `,[weight]` to the URL.  The exact behavior depends on your [`lb_policy`](#load-balancing-policy) setting.  See [Load Balancing](/docs/topics/load-balancing) for example [configurations](/docs/topics/load-balancing.html#load-balancing-weight).

Must be `tcp` if `from` is `tcp+https`.

:::warning

Be careful with trailing slash.

With rule:

```yaml
- from: https://verify.corp.example.com
  to: https://verify.pomerium.com/anything
```

Requests to `https://verify.corp.example.com` will be forwarded to `https://verify.pomerium.com/anything`, while requests to `https://verify.corp.example.com/foo` will be forwarded to `https://verify.pomerium.com/anythingfoo`.To make the request forwarded to `https://httbin.org/anything/foo`, you can use double slashes in your request `https://httbin.corp.example.com//foo`.

While the rule:

```yaml
- from: https://verify.corp.example.com
  to: https://verify.pomerium.com/anything/
```

All requests to `https://verify.corp.example.com/*` will be forwarded to `https://verify.pomerium.com/anything/*`. That means accessing to `https://verify.corp.example.com` will be forwarded to `https://verify.pomerium.com/anything/`. That said, if your application does not handle trailing slash, the request will end up with 404 not found.

Either `redirect` or `to` must be set.

:::

#### Redirect

`Redirect` is used to redirect incoming requests to a new URL. The `redirect` field is an object with several possible
options:

- `https_redirect` (boolean): the incoming scheme will be swapped with "https".
- `scheme_redirect` (string): the incoming scheme will be swapped with the given value.
- `host_redirect` (string): the incoming host will be swapped with the given value.
- `port_redirect` (integer): the incoming port will be swapped with the given value.
- `path_redirect` (string): the incoming path portion of the URL will be swapped with the given value.
- `prefix_rewrite` (string): the incoming matched prefix will be swapped with the given value.
- `response_code` (integer): the response code to use for the redirect. Defaults to 301.
- `strip_query` (boolean): indicates that during redirection, the query portion of the URL will be removed. Defaults to false.

Either `redirect` or `to` must be set.

#### Pass Identity Headers

When enabled, this option will pass identity headers to upstream applications. These headers include:

- X-Pomerium-Jwt-Assertion
- X-Pomerium-Claim-*

#### Policies

Add or remove Policies to be applied to the Route. Note that Policies enforced in the Route's Namespace will be applied automatically.

#### Enable Google Cloud Serverless Authentication

@Travis plz explain.


### Matchers


#### Path

If set, the route will only match incoming requests with a path that is an exact match for the specified path.

#### Prefix

If set, the route will only match incoming requests with a path that begins with the specified prefix.

#### Regex

If set, the route will only match incoming requests with a path that matches the specified regular expression. The supported syntax is the same as the Go [regexp package](https://golang.org/pkg/regexp/) which is based on [re2](https://github.com/google/re2/wiki/Syntax).

### Rewrite


#### Prefix Rewrite

If set, indicates that during forwarding, the matched prefix (or path) should be swapped with this value.
For example, given this policy:

```yaml
from: https://from.example.com
to: https://to.example.com
prefix: /admin
prefix_rewrite: /
```

A request to `https://from.example.com/admin` would be forwarded to `https://to.example.com/`.

#### Regex Rewrite Pattern

The pattern to match before rewriting, ex: `^/service/([^/]+)(/.*)$`.


#### Regex Rewrite Substitution

The substitution for your regex pattern, ex: `\\2/instance/\\1`.


### Timeouts


#### Allow Websockets

If set, enables proxying of websocket connections.

:::warning

**Use with caution:** websockets are long-lived connections, so [global timeouts](#global-timeouts) are not enforced (though the policy-specific `timeout` is enforced). Allowing websocket connections to the proxy could result in abuse via [DOS attacks](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/).

:::

#### Timeout

Policy timeout establishes the per-route timeout value. Cannot exceed global timeout values.

#### Idle Timeout

If you are proxying long-lived requests that employ streaming calls such as websockets or gRPC,
set this to either a maximum value there may be no data exchange over a connection (recommended),
or set it to unlimited (`0s`). If `idle_timeout` is specified, and `timeout` is not
explicitly set, then `timeout` would be unlimited (`0s`). You still may specify maximum lifetime
of the connection using `timeout` value (i.e. to 1 day).

### Headers


#### Host Headers

The `host` header can be preserved via the `preserve_host_header` setting or customized via 3 mutually exclusive options:

1. `preserve_host_header` when enabled, this option will pass the host header from the incoming request to the proxied host, instead of the destination hostname. It's an optional parameter of type `bool` that defaults to `false`.
    See [ProxyPreserveHost](http://httpd.apache.org/docs/2.0/mod/mod_proxy.html#proxypreservehost).
2. `host_rewrite` which will rewrite the host to a new literal value.
3. `host_rewrite_header` which will rewrite the host to match an incoming header value.
4. `host_path_regex_rewrite_pattern`, `host_path_regex_rewrite_substitution` which will rewrite the host according to a regex matching the path. For example with the following config:

    ```yaml
    host_path_regex_rewrite_pattern: "^/(.+)/.+$"
    host_path_regex_rewrite_substitution: \1
    ```

    Would rewrite the host header to `example.com` given the path `/example.com/some/path`.

The 2nd, 3rd and 4th options correspond to the envoy route action host related options, which can be found [here](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto.html#config-route-v3-routeaction).

#### Set Request Headers

Set Request Headers allows you to set static values for given request headers. This can be useful if you want to pass along additional information to downstream applications as headers, or set authentication header to the request. For example:

```yaml
- from: https://verify.corp.example.com
  to: https://verify.pomerium.com
  allowed_users:
    - bdd@pomerium.io
  set_request_headers:
    # works auto-magically!
    # https://verify.corp.example.com/basic-auth/root/hunter42
    Authorization: Basic cm9vdDpodW50ZXI0Mg==
    X-Your-favorite-authenticating-Proxy: "Pomerium"
```

#### Remove Request Headers

Remove Request Headers allows you to remove given request headers. This can be useful if you want to prevent privacy information from being passed to downstream applications. For example:

```yaml
- from: https://verify.corp.example.com
  to: https://verify.pomerium.com
  allowed_users:
    - bdd@pomerium.io
  remove_request_headers:
    - X-Email
    - X-Username
```

#### Rewrite Response Headers

Rewrite Response Headers allows you to modify response headers before they are returned to the client. The `header` field will match the HTTP header name, and `prefix` will be replaced with `value`. For example, if the downstream server returns a header:

```text
Location: http://localhost:8000/two/some/path/
```

And the policy has this config:

```yaml
rewrite_response_headers:
  - header: Location
    prefix: http://localhost:8000/two/
    value: http://frontend/one/
```

The browser would be redirected to: `http://frontend/one/some/path/`. This is similar to nginx's [`proxy_redirect` option](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_redirect), but can be used for any header.

### Load Balancer


#### Load Balancing Policy

In presence of multiple upstreams, defines load balancing strategy between them.

See [Envoy documentation](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-enum-config-cluster-v3-cluster-lbpolicy) for more details.

- [`ROUND_ROBIN`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#weighted-round-robin) (default)
- [`LEAST_REQUEST`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#weighted-least-request) and may be further configured using [`least_request_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-msg-config-cluster-v3-cluster-leastrequestlbconfig)
- [`RING_HASH`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#ring-hash) and may be further configured using [`ring_hash_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#config-cluster-v3-cluster-ringhashlbconfig) option
- [`RANDOM`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#random)
- [`MAGLEV`](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#maglev) and may be further configured using [`maglev_lb_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-msg-config-cluster-v3-cluster-maglevlbconfig) option

Some policy types support additional [configuration](#load-balancing-policy-config).

## Policies

A Policy defines what permissions a set of users or groups has. Policies are applied to Namespaces or Routes to associate the set of permissions with a service or set of service, completing the authentication model.

::: tip
This is a separate concept from [policies](../reference/#policy) in the non-enterprise model. In open-source Pomerium, the `policy` block defines both routes and access.
:::

Policies can be constructed three ways:

### Web UI

From the **BUILDER** tab, users can add allow or deny blocks to a policy, containing and/or/not/nor logic to allow or deny sets of users and groups.

![A policy being constructed in Pomerium Enterprise console allowing a single user access](../img/example-policy-single-user.png)

### Pomerium Policy Language

From the **EDITOR** tab users can write policies in Pomerium Policy Language (**PPL**), a YAML-based notation.

![A policy as viewed from the editor tab](../img/example-policy-editor.png)

PPL documents contain one or more rules. Each rule has a corresponding action and one or more logical operators.
Each logical operator contains criteria and each criterion has a name and corresponding data.

PPL documents are defined via YAML:

```yaml
- allow:
    or:
      - email:
          is: x@example.com
      - email:
          is: y@example.com
```

The available rule actions are:

- `allow`
- `deny`

The available logical operators are:

- `and`
- `or`
- `not`
- `nor`

The available criteria types are:

- `accept`
- `authenticated_user`
- `claim`
- `date`
- `day_of_week`
- `domain`
- `email`
- `groups`
- `reject`
- `time_of_day`
- `user`

Some criteria also support a subpath as part of the criterion name:

```yaml
- allow:
    or:
      - claim/family_name:
          is: Smith
```

### Rego

For those using [OPA](https://www.openpolicyagent.org/), the **REGO** tab will accept policies written in Rego.

::: tip
A policy can only support PPL or Rego. Once one is set, the other tab is disabled.
:::

### Overrides

- **Any Authenticated User**: This setting will allow access to a route with this policy attached to any user who can authenticate to your Identity Provider (**IdP**).
- **CORS Preflight**:
- **Public Access**: This setting allows complete, unrestricted access to an associated route. Use this setting with caution.


## Certificates

Certificates are the x509 _public-key_ and _private-key_ used to establish secure HTTP and gRPC connections. Any combination of the above can be used together, and are additive. You can also use any of these settings in conjunction with `Autocert` to get OCSP stapling.

For example, if specifying multiple certificates at once:

```yaml
certificates:
  - cert: "$HOME/.acme.sh/authenticate.example.com_ecc/fullchain.cer"
    key: "$HOME/.acme.sh/authenticate.example.com_ecc/authenticate.example.com.key"
  - cert: "$HOME/.acme.sh/verify.example.com_ecc/fullchain.cer"
    key: "$HOME/.acme.sh/verify.example.com_ecc/verify.example.com.key"
  - cert: "$HOME/.acme.sh/prometheus.example.com_ecc/fullchain.cer"
    key: "$HOME/.acme.sh/prometheus.example.com_ecc/prometheus.example.com.key"
```

