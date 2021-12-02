---
title: Troubleshooting
description: >-
  Learn how to troubleshoot common configuration issues or work around any outstanding bugs.
sidebarDepth: 0
lang: en-US
meta:
  - name: keywords
    content: pomerium troubleshooting faq frequently asked questions
---

# Troubleshooting

This article provides troubleshooting information for various tools and features in Pomerium.

[[toc]]

## Pomerium Core

### JWT Authentication with Let's Encrypt

Wildcard certificates signed by LetsEncrypt may still be cross-signed by the [expired DST R3 root](https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/). While many browsers still trust these certificates (as long as they are also signed by a valid root), some upstream applications reject them, including Grafana as an example:

```log
logger=context error=Get "https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json": x509: certificate signed by unknown authority
```

For upstream applications that can use a local signing key file, you can circumvent this issue using `curl` or `wget` to download the signing key locally (relative to the upstream service):

::::: tabs
:::: tab curl

```bash
curl https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json > /etc/grafana/jwks.json
```
::::
:::: tab wget

```bash
wget -O /etc/upstream-service/jwks.json https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json
```
::::
:::::

Edit the upstream service configuration to use the local key to verify tokens.

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

#### HSTS

If your domain has [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) enabled and you visit an endpoint while Pomerium is using the self-signed bootstrap certificate or a LetsEncrypt staging certificate (before cert-manager has provisioned a production certificate), the untrusted certificate may be pinned in your browser and would need to be reset. See [this article](https://www.ssl2buy.com/wiki/how-to-clear-hsts-settings-on-chrome-firefox-and-ie-browsers) for more information.

### Redirect Loop with Redis Databroker

When using Redis, the [shared secret](/reference/readme.md#shared-secret) is used to encrypt data in Redis itself. if you change the configured shared secret, data from Redis can no longer be decrypted. This results in errant behavior, including redirect loops when a user session cannot be retrieved from the databroker.

The resolution is to flush the Redis database with [`FLUSHDB`](https://redis.io/commands/flushdb) or [`FLUSHALL`](https://redis.io/commands/FLUSHALL).

### RPC Errors

#### certificate signed by unknown authority

When authenticating and authorizing a user for the first time, you may see the following in your Pomerium logs:

```log
ERR http-error error="401 Unauthorized: ..... rpc error: code = DeadlineExceeded desc = latest connection error: connection error: desc = "transport: authentication handshake failed: x509: certificate signed by unknown authority...."
```

**Why**

This error means that the proxy is rejecting the authorize service's supplied certificate (used to establish a secure connection) because it doesn't know or trust the certificate authority that is associated with the supplied certificate. This can happen for a few reasons.

**Solution**

Ensure that the proxy service knows about and trusts the certificate authority that signed the authorize service's certificate.

- Add the certificate authority directly into Pomerium using the [certificate authority](/reference/readme.md#certificate-authority) config setting.
- Add the certificate authority to the system's underlying trust store.
- Replace your system / docker image certificate bundle.

    For Docker:

    ```docker
    COPY --from=builder /etc/ssl/certs/your-cert-bundle.crt /etc/ssl/certs/ca-certificates.crt
    ```
- Finally, ensure that you aren't being man-in-the-middle'd or that some eager router isn't injecting its own certificate along the way. Use openssl to verify that your proxy service is getting the certificate you think its getting.

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

The proxy service is not able to create a connection with the authorization service to validate a user.

**Solution**

Usually, this is the result of either a routing issue or a configuration error. Make sure that you are using the _internally_ routable URL for authorize service. Many cloud loud balancers _do not_ yet support gRPC transposing the ingress. So while your authenticate service url will probably look like `https://authenticate.corp.example.com`, your authorizer service url will likely be more like `https://pomerium-authorize-service.default.svc.cluster.local` or `https://localhost:5443`.

## Pomerium Enterprise

### Generate Recovery Token

!!!include(generate-recovery-token.md)!!!

## Miscellaneous

### Invalid Certificates from Command Line Tools

When using Let's Encrypt certificates, you must use the `fullchain.pem` file, not `cert.pem` in order to include intermediate certs. Browsers like Chrome store intermediate certs for LE but other tools (like `curl`) don't, which is why your route might look fine in a web browser, but not when curl'd or used for TCP tunneling.
