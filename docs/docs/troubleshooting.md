---
title: Troubleshooting
description: >-
  Learn how to troubleshoot common configuration issues or work around any outstanding bugs.
sidebarDepth: 0
lang: en-US
meta:
  - name: keywords
    content: pomerium, troubleshooting, faq, frequently asked questions
---

# Troubleshooting

This article provides troubleshooting information for various tools and features in Pomerium.

[[toc]]

## Pomerium Core

### HTTP Strict Transport Security (HSTS)

By default, Pomerium sends the [`Strict-Transport-Security`](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) response header to the browser, which pins the certificate to our browser for one year. This is common best practice to help prevent man-in-the-middle attacks but can create issues while a new Pomerium configuration is in development.

When you visit an endpoint while Pomerium is using an untrusted certificate (like the self-signed bootstrap certificate or a Let's Encrypt staging certificate), that certificate may be pinned in your browser. Once Pomerium is switched to a trusted production certificate, the untrusted cert must reset in the browser.

While developing your Pomerium environment, consider adjusting the [`SET_RESPONSE_HEADERS`](/reference/readme.md#set-response-headers) key to remove `Strict-Transport-Security` or reduce the `max-age` value until your production certificates are in place.

See [this article](https://www.ssl2buy.com/wiki/how-to-clear-hsts-settings-on-chrome-firefox-and-ie-browsers) for more information on clearing HSTS for specific endpoints across common browsers.

### JWT Authentication

When securing the Pomerium Authenticate service with a certificate signed by Let's Encrypt, your upstream applications may reject the certificate when attempting to access the JWT signing key. Here's an example log line from [Grafana](/guides/grafana.md):

```log
logger=context error=Get "https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json": x509: certificate signed by unknown authority
```

This is often due to the recent expiration of the [DST Root CA X3](https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/) certificate. Many default keystores used by docker images and less-frequently updated distributions still carry this expired certificate. Even though Let's Encrypt certs are cross-signed with the [ISRG Root X1](https://letsencrypt.org/certificates/) CA certificate, some applications will still reject them.

To clarify; this does not mean that the upstream service is rejecting the JWT signing key. Rather, it doesn't trust the Let's Encrypt certificate used by the Authorize service for TLS, and so it will not read the JWKS file.

For upstream applications that can use a local signing key file, you can circumvent this issue using `curl` or `wget` to download the signing key locally (relative to the upstream service). Using Grafana again as an example:

1. Download the `jwks.json` file from the authenticate server:

    ::::: tabs
    :::: tab curl

    ```bash
    curl https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json > /etc/grafana/jwks.json
    ```
    ::::
    :::: tab wget

    ```bash
    wget -O /etc/grafana/jwks.json https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json
    ```
    ::::
    :::::

1. Edit the upstream service configuration to use the local key to verify tokens:

    ```ini
    [auth.jwt]
    enabled = true
    header_name = X-Pomerium-Jwt-Assertion
    email_claim = email
    jwk_set_file = /etc/grafana/jwks.json
    cache_ttl = 60m
    ```

### Kubernetes Ingress Controller

#### View Event History

Pomerium Ingress Controller will add **events** to the Ingress objects as it processes them.

```
kubectl describe ingress/my-ingress
```

```log
Events:
  Type    Reason   Age   From              Message
  ----    ------   ----  ----              -------
  Normal  Updated  18s   pomerium-ingress  updated pomerium configuration
```

If an error occurs, it may be reflected in the events:

```log
Events:
  Type     Reason       Age                 From              Message
  ----     ------       ----                ----              -------
  Normal   Updated      5m53s               pomerium-ingress  updated pomerium configuration
  Warning  UpdateError  3s                  pomerium-ingress  upsert routes: parsing ingress: annotations: applying policy annotations: parsing policy: invalid rules in policy: unsupported conditional "maybe", only and, or, not, nor and action are allowed
```

### Shared Secret Mismatch

Pomerium's independent services communicate securely using a [shared secret](/reference/readme.md#shared-secret). When services or the databroker have mismatched secrets, Pomerium will fail.

Pomerium Core will log a shared secret mismatch with:

```json
{
  "level": "error",
  "syncer_id": "authorize",
  "syncer_type": "",
  "error": "rpc error: code = Unauthenticated desc = invalid JWT: go-jose/go-jose: error in cryptographic primitive",
  "time": "2022-03-22T07:26:14-04:00",
  "message": "sync"
}
```

And Pomerium Enterprise will log the error with:

```json
{
  "level": "error",
  "ts": "2022-03-22T07:21:02-04:00",
  "caller": "dashboard/server.go:187",
  "msg": "syncer",
  "error": "failed to sync all devices: rpc error: code = Unauthenticated desc = invalid JWT: go-jose/go-jose: error in cryptographic primitive",
  "stacktrace": "github.com/pomerium/pomerium-console/svc/dashboard.(*Server).Run.func2\n\t/PATH/TO/POMERIUM/CONSOLE/SERVICE/svc/dashboard/server.go:187\ngolang.org/x/sync/errgroup.(*Group).Go.func1\n\t/Users/tgroth/workspace/go/pkg/mod/golang.org/x/sync@v0.0.0-20210220032951-036812b2e83c/errgroup/errgroup.go:57"
}
{
  "level": "info",
  "ts": "2022-03-22T07:21:02-04:00",
  "caller": "dashboard/server.go:202",
  "msg": "stopping dashboard servers"
}
```

Update the [shared secret](/reference/readme.md#shared-secret) across all Pomerium services to match the one set for the Databroker.

#### Redis Secret Mismatch

When using Redis, the [shared secret](/reference/readme.md#shared-secret) is used to encrypt data in Redis itself. If you change the configured shared secret, data from Redis can no longer be decrypted. This results in errant behavior, including redirect loops when a user session cannot be retrieved from the databroker.

```json
{
  "level": "error",
  "syncer_id": "authorize",
  "syncer_type": "",
  "error": "rpc error: code = Unknown desc = cryptutil: decryption failed (mismatched keys?): chacha20poly1305: message authentication failed",
  "time": "2022-03-22T07:18:12-04:00",
  "message": "error during initial sync"
}
{
  "level": "error",
  "syncer_id": "authorize",
  "syncer_type": "",
  "error": "rpc error: code = Unknown desc = cryptutil: decryption failed (mismatched keys?): chacha20poly1305: message authentication failed",
  "time": "2022-03-22T07:18:12-04:00",
  "message": "sync"
}
```

The resolution is to flush the Redis database with [`FLUSHDB`](https://redis.io/commands/flushdb) or [`FLUSHALL`](https://redis.io/commands/FLUSHALL).

An example of how to do this on Kubernetes with TLS enabled is to use kubectl to execute a command on the master pod, like so:
`kubectl exec -it pomerium-redis-master-0 -- redis-cli --tls --cert /opt/bitnami/redis/certs/tls.crt --key /opt/bitnami/redis/certs/tls.key --cacert /opt/bitnami/redis/certs/ca.crt FLUSHALL ASYNC`
If TLS is not enabled, you may omit the TLS options.

### RPC Errors

#### certificate signed by unknown authority

When authenticating and authorizing a user for the first time, you may see the following in your Pomerium logs:

```log
ERR http-error error="401 Unauthorized: ..... rpc error: code = DeadlineExceeded desc = latest connection error: connection error: desc = "transport: authentication handshake failed: x509: certificate signed by unknown authority...."
```

**Why**

This error means that the proxy is rejecting the Authorize service's supplied certificate (used to establish a secure connection) because it doesn't know or trust the certificate authority that signed it.

**Solution**

Ensure that the Proxy service knows about and trusts the certificate authority that signed the Authorize service's certificate.

- Add the certificate authority directly into Pomerium using the [certificate authority](/reference/readme.md#certificate-authority) config setting.
- Add the certificate authority to the system's underlying trust store.
- Replace your system / docker image certificate bundle.

    For Docker:

    ```docker
    COPY --from=builder /etc/ssl/certs/your-cert-bundle.crt /etc/ssl/certs/ca-certificates.crt
    ```
- Finally, ensure that you aren't being man-in-the-middle'd or that some eager router isn't injecting its own certificate along the way. Use openssl to verify that your Proxy service is getting the certificate you think its getting.

    ```bash
    openssl s_client -servername pomerium.io -connect pomerium.io:443 </dev/null \
    | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
    ```

#### rpc error: code = DeadlineExceeded

When authenticating and authorizing a user for the first time, you may get the following in your Pomerium logs.

```log
{"level":"error",..."error":"rpc error: code = DeadlineExceeded desc = context deadline exceeded","http-message":"rpc error: code = DeadlineExceeded desc = context deadline exceeded","http-code":500,"message":"http-error"}
```

**Why**

The Proxy service is not able to create a connection with the authorization service to validate a user.

**Solution**

Usually, this is the result of either a routing issue or a configuration error. Make sure that you are using the _internally_ routable URL for the Authorize service. Many cloud loud balancers _do not_ yet support gRPC transposing the ingress. So while your authenticate service url will probably look like `https://authenticate.corp.example.com`, your authorizer service url will likely be more like `https://pomerium-authorize-service.default.svc.cluster.local` or `https://localhost:5443`.

## Pomerium Enterprise

### Generate Recovery Token

!!!include(generate-recovery-token.md)!!!

## Miscellaneous

### Invalid Certificates from Command Line Tools

When using Let's Encrypt certificates, you must use the `fullchain.pem` file, not `cert.pem` in order to include intermediate certs. Browsers like Chrome will store intermediate certs for LE but other tools (like `curl`) don't, which is why your route might look fine in a web browser, but not when curl'd or used for TCP tunneling.
