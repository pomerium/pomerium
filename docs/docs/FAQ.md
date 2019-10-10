---
title: Troubleshooting
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy troubleshooting faq issues
      -
---

# FAQ / Troubleshooting Guide

[[toc]]

## RPC Errors

### `certificate signed by unknown authority`

When authenticating and authorizing a user for the first time, you get the following in your Pomerium logs.

> ERR http-error error="401 Unauthorized: ..... rpc error: code = DeadlineExceeded desc = latest connection error: connection error: desc = "transport: authentication handshake failed: x509: certificate signed by unknown authority...."

**Why**

This error means that the proxy is rejecting the authorize service's supplied certificate (used to establish a secure connection) because it doesn't know or trust the certificate authority that is associated with the supplied certificate. This can happen for a few reasons.

**Solution**

Ensure that the proxy service knows about, and trusts the certificate authority that signed the authorize service's certificate.

- Add the certificate authority directly into pomerium using the certificate authority config setting.
- Add the certificate authority to the system's underlying trust store.
- Replace your system / docker image certificate bundle.

  > `COPY --from=builder /etc/ssl/certs/your-cert-bundle.crt /etc/ssl/certs/ca-certificates.crt`

- Finally, ensure that you aren't being man-in-the-middle'd or that some eager router isn't injecting it's own certificate along the way. Use openssl to verify that your proxy service is getting the certificate you think its getting.
  > `$openssl s_client -servername pomerium.io -connect pomerium.io:443 </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'`

### `rpc error: code = DeadlineExceeded`

When authenticating and authorizing a user for the first time, you get the following in your Pomerium logs.

> {"level":"error",..."error":"rpc error: code = DeadlineExceeded desc = context deadline exceeded","http-message":"rpc error: code = DeadlineExceeded desc = context deadline exceeded","http-code":500,"message":"http-error"}

**Why**

The proxy service is not able to create a connection with the authorization service to validate a user.

**Solution**

Usually, this is the result of either a routing issue or a configuration error. Make sure that you are using the _internally_ routable URL for authorize service. Many cloud loud balancers _not not_ yet support gRPC transposing the ingress. So while your authenticate service url will probably look like `https://authenticate.corp.example.com`, your authorizer service url will likely be more like `https://pomerium-authorize-service.default.svc.cluster.local` or `https://localhost:5443`
