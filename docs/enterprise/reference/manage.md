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

Several fields in the New Route View behave the same as their counterpoints in open-source Pomerium. See [Configuation Settings](/reference/) for more information on the following fields:
  - [From](/reference/#from)
  - [To](/reference/#to)
  - [Redirect](/reference/#redirect)
  - [Pass Identity Headers](/reference/#pass-identity-headers)


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

### Timeouts

### Headers

### Load Balancer

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

