---
sidebar: auto
---

# Configuration Variables

Pomerium uses [environmental variables] to set configuration settings. If you are coming from a kubernetes or docker background this should feel familiar. If not, check out the following primers.

- [Store config in the environment](https://12factor.net/config)
- [Kubernetes: Environment variables](https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/)
- [Docker: Environment variables](https://docs.docker.com/compose/environment-variables/)

## Global settings

These are configuration variables shared by all services, in all service modes.

### Service Mode

- Environmental Variable: `SERVICES`
- Type: `string`
- Default: `all`
- Options: `all` `authenticate` `authorize` or `proxy`

Service mode sets the pomerium service(s) to run. If testing, you may want to set to `all` and run pomerium in "all-in-one mode." In production, you'll likely want to spin up several instances of each service mode for high availability.

### Address

- Environmental Variable: `ADDRESS`
- Type: `string`
- Default: `:https`

Address specifies the host and port to serve HTTPS and gRPC requests from. If empty, `:https`/`:443` is used.

### Shared Secret

- Environmental Variable: `SHARED_SECRET`
- Type: [base64 encoded] `string`
- Required

Shared Secret is the base64 encoded 256-bit key used to mutually authenticate requests between services. It's critical that secret keys are random, and store safely. Use a key management system or `/dev/urandom/` to generate a key. For example:

```
head -c32 /dev/urandom | base64
```

### Policy

- Environmental Variable: either `POLICY` or `POLICY_FILE`
- Type: [base64 encoded] `string` or relative file location
- Filetype: `json` or `yaml`
- Required

Policy contains the routes, and their access policies. For example,

<<< @/policy.example.yaml

### Debug

- Environmental Variable: `POMERIUM_DEBUG`
- Type: `bool`
- Default: `false`

By default, JSON encoded logs are produced. Debug enables colored, human-readable logs to be streamed to [standard out](https://en.wikipedia.org/wiki/Standard_streams#Standard_output_(stdout)). In production, it's recommended to be set to `false`.

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

### Log Level

- Environmental Variable: `LOG_LEVEL`
- Type: `string`
- Options: `debug` `info` `warn` `error`
- Default: `debug`

Log level sets the global logging level for pomerium. Only logs of the desired level and above will be logged.

### Certificate

- Environmental Variable: either `CERTIFICATE` or `CERTIFICATE_FILE`
- Type: [base64 encoded] `string` or relative file location
- Required

Certificate is the x509 _public-key_ used to establish secure HTTP and gRPC connections. If unset, pomerium will attempt to find and use `./cert.pem`.

### Certificate Key

- Environmental Variable: either `CERTIFICATE_KEY` or `CERTIFICATE_KEY_FILE`
- Type: [base64 encoded] `string`
- Required

Certificate key is the x509 _private-key_ used to establish secure HTTP and gRPC connections. If unset, pomerium will attempt to find and use `./privkey.pem`.

## Authenticate Service

### Authenticate Service URL

- Environmental Variable: `AUTHENTICATE_SERVICE_URL`
- Type: `URL`
- Required
- Example: `https://authenticate.corp.example.com`

Authenticate Service URL is the externally accessible URL for the authenticate service.

### Identity Provider Name

- Environmental Variable: `IDP_PROVIDER`
- Type: `string`
- Required
- Options: `azure` `google` `okta` `gitlab` `onelogin` or `oidc`

Provider is the short-hand name of a built-in OpenID Connect (oidc) identity provider to be used for authentication. To use a generic provider,set to `oidc`.

See [identity provider] for details.

### Identity Provider Client ID

- Environmental Variable: `IDP_CLIENT_ID`
- Type: `string`
- Required

Client ID is the OAuth 2.0 Client Identifier retrieved from your identity provider. See your identity provider's documentation, and our [identity provider] docs for details.

### Identity Provider Client Secret

- Environmental Variable: `IDP_CLIENT_SECRET`
- Type: `string`
- Required

Client Secret is the OAuth 2.0 Secret Identifier retrieved from your identity provider. See your identity provider's documentation, and our [identity provider] docs for details.

### Identity Provider URL

- Environmental Variable: `IDP_PROVIDER_URL`
- Type: `string`
- Required, depending on provider

Provider URL is the base path to an identity provider's [OpenID connect discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html). For example, google's URL would be `https://accounts.google.com` for [their discover document](https://accounts.google.com/.well-known/openid-configuration).

### Identity Provider Scopes

- Environmental Variable: `IDP_SCOPES`
- Type: `[]string` comma separated list of oauth scopes.
- Default: `oidc`,`profile`, `email`, `offline_access` (typically)
- Optional for built-in identity providers.

Identity provider scopes correspond to access privilege scopes as defined in Section 3.3 of OAuth 2.0 RFC6749\. The scopes associated with Access Tokens determine what resources will be available when they are used to access OAuth 2.0 protected endpoints. If you are using a built-in provider, you probably don't want to set customized scopes.

### Identity Provider Service Account

- Environmental Variable: `IDP_SERVICE_ACCOUNT`
- Type: `string`
- Required, depending on provider

Identity Provider Service Account is field used to configure any additional user account or access-token that may be required for querying additional user information during authentication. For a concrete example, Google an additional service account and to make a follow-up request to query a user's group membership. For more information, refer to the [identity provider] docs to see if your provider requires this setting.

## Proxy Service

### Signing Key

- Environmental Variable: `SIGNING_KEY`
- Type: [base64 encoded] `string`
- Optional

Signing key is the base64 encoded key used to sign outbound requests. For more information see the [signed headers](./signed-headers.md) docs.

### Authenticate Service URL

- Environmental Variable: `AUTHENTICATE_SERVICE_URL`
- Type: `URL`
- Required
- Example: `https://authenticate.corp.example.com`

Authenticate Service URL is the externally accessible URL for the authenticate service.

### Authenticate Internal Service URL

- Environmental Variable: `AUTHENTICATE_INTERNAL_URL`
- Type: `string`
- Optional
- Example: `pomerium-authenticate-service.pomerium.svc.cluster.local`

Authenticate Internal Service URL is the internally routed dns name of the authenticate service. This setting is typically used with load balancers that do not gRPC, thus allowing you to specify an internally accessible name. 

### Authorize Service URL

- Environmental Variable: `AUTHORIZE_SERVICE_URL`
- Type: `URL`
- Required
- Example: `https://access.corp.example.com` or `pomerium-authorize-service.pomerium.svc.cluster.local`

Authorize Service URL is the location of the internally accessible authorize service. NOTE: Unlike authenticate, authorize has no publicly accessible http handlers so this setting is purely for gRPC communication. 

If your load balancer does not support gRPC pass-through you'll need to set this value to an internally routable location (`pomerium-authorize-service.pomerium.svc.cluster.local`) instead of an externally routable one (`https://access.corp.example.com`).  

### Override Certificate Name

- Environmental Variable: `OVERRIDE_CERTIFICATE_NAME`
- Type: `int`
- Optional (but typically required if Authenticate Internal Service Address is set)
- Example: `*.corp.example.com` if wild card or `authenticate.corp.example.com`/`authorize.corp.example.com`

When Authenticate Internal Service Address is set, secure service communication can fail because the external certificate name will not match the internally routed service url. This setting allows you to override that check.

### Certificate Authority

- Environmental Variable: `CERTIFICATE_AUTHORITY` or `CERTIFICATE_AUTHORITY_FILE`
- Type: [base64 encoded] `string` or relative file location
- Optional

Certificate Authority is set when behind-the-ingress service communication uses self-signed certificates. Be sure to include the intermediary certificate.

[base64 encoded]: https://en.wikipedia.org/wiki/Base64
[environmental variables]: https://en.wikipedia.org/wiki/Environment_variable
[identity provider]: ./identity-providers.md
[letsencrypt]: https://letsencrypt.org/
[oidc rfc]: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
