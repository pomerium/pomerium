---
title: Client-Side mTLS
lang: en-US
meta:
  - name: keywords
    content: pomerium, identity access proxy, mtls, client certificate, mutual authentication
description: >-
  This guide covers how to use Pomerium to implement mutual authentication
  (mTLS) for end-users, using client certificates with a custom certificate authority.
---

# Client-Side mTLS With Pomerium

Secure communication on the web typically refers to using signed server certificates with the TLS protocol. TLS connections are both private and authenticated, preventing eavesdropping and impersonation of the server.

To authenticate clients (users), we typically use an identity provider (IDP). Clients must login before they can access a protected endpoint. However the TLS protocol also supports mutual authenticate (mTLS) via signed client certificates.

Pomerium supports requiring signed client certificates with the `client_ca`/`client_ca_file` configuration options. This guide covers how to configure Pomerium to implement mutual authentication using client certificates with a custom certificate authority.

## Before You Begin

- This guide assumes you already have a working Pomerium instance. See our [Quick-Start] doc for installation through Docker, and one of the [Identity Provider] docs to connect it to your IdP. You should also have a working route to test against.

- We will use the `mkcert` application to create the certificates. To install `mkcert` follow the instructions on [Github](https://github.com/FiloSottile/mkcert#installation).

    ::: warning
    The `mkcert` tool is designed for testing. It creates a locally-trusted root certificate for development purposes. We're using mkcert for this proof-of-concept example, but consider using a different certificate solution for production environments.
    :::

- For this guide the `localhost.pomerium.io` domain will be our root domain (all subdomains on `localhost.pomerium.io` point to `localhost`).

## Create Certificates

1. Create a trusted root certificate authority (**CA**):

    ```bash
    mkcert -install
    ```

1. Create a wildcard certificate for `*.localhost.pomerium.io`:

    ```bash
    mkcert '*.localhost.pomerium.io'
    ```

    ::: tip Note
    If you already have a certificate solution for route ingress, you can skip this step. Client certificates can be validated from a certificate authority independent of the route CA.
    :::

    This creates two files in the current working directory:

    - `_wildcard.localhost.pomerium.io.pem`
    - `_wildcard.localhost.pomerium.io-key.pem`

    We will use these files for the server TLS certificate.

1. Create a client TLS certificate:

    ```bash
    mkcert -client -pkcs12 'yourUsername@localhost.pomerium.io'
    ```

    This creates a new file in the current working directory:

    - `yourUsername@localhost.pomerium.io-client.p12`

## Configure Pomerium

Pomerium can be configured to require a client certificate for all routes signed by a single CA, or on a per-route basis with the CA set individually.

### Require mTLS for All Routes

Update the `config.yaml` file or environment variables with the following aditions. Replace `/YOUR/MKCERT/CAROOT` in this example with the value of `mkcert -CAROOT`:

::: tip
This configuration will require client certificates for _all_ routes. See [rquire mTLS per Route](#require-mtls-per-route) to enable mTLS on for specific routes.
:::

::::: tabs
:::: tab config.yaml

```yaml
# If you're using a separate certificate for server-side TLS, leave these keys unchanged.
certificate_file: "_wildcard.localhost.pomerium.io.pem"
certificate_key_file: "_wildcard.localhost.pomerium.io-key.pem"

# "$(mkcert -CAROOT)/rootCA.pem"
client_ca_file: "/YOUR/MKCERT/CAROOT/rootCA.pem"
```

Alternately, you can encode the client certificate authority as a base64-encoded string (`cat $(mkcert -CAROOT)/rootCA.pem | base64 -w 0`) and provide the value to `client_ca`.

::::
:::: tab Environment Variables
```bash
# If you're using a separate certificate for server-side TLS, leave these variables unchanged.
CERTIFICATE_FILE="_wildcard.localhost.pomerium.io.pem"
CERTIFICATE_KEY_FILE="_wildcard.localhost.pomerium.io-key.pem"

# "$(mkcert -CAROOT)/rootCA.pem"
CLIENT_CA_FILE="/YOUR/MKCERT/CAROOT/rootCA.pem"
```

Alternately, you can encode the client certificate authority as a base64-encoded string (`cat $(mkcert -CAROOT)/rootCA.pem | base64 -w 0`) and provide the value as `CLIENT_CA`.

::::
:::::

Start Pomerium.

### Require mTLS per Route

You can define a client certificate authority for an individual route. Use this option to only require mTLS for specific routes, or to require certificates singed by a different CA than the one required by default with `client_ca` or `client_ca_file`:

```yaml{3-4}
  - from: https://verify.localhost.pomerium.io
    to: https://verify.pomerium.com
    # "$(mkcert -CAROOT)/rootCA.pem"
    tls_downstream_client_ca_file: "/YOUR/MKCERT/CAROOT/rootCA.pem"
    pass_identity_headers: true
    policy:
      - allow:
          or:
            - domain:
                is: example.com
```

Alternately, you can encode the client certificate authority as a base64-encoded string (`cat $(mkcert -CAROOT)/rootCA.pem | base64 -w 0`) and provide the value to `tls_downstream_client_ca`.

## Install Client Certificate

Because your routes now require a client certificate to be accessed, we must install that client certificate in the browser. The following instructions are for Chrome, but client certificates are supported in all major browsers.

1. Go to `chrome://settings/certificates`:

    ![chrome settings](./img/mtls/01-chrome-settings-certificates.png)

1. Click on **Import** and browse to the directory where you created the certificates above. Choose `_wildcard.localhost.pomerium.io-client.p12`:

    ![import client certificate](./img/mtls/02-import-client-certificate.png)

1. You will be prompted for the certificate password. The default password is **`changeit`**:

    ![enter certificate password](./img/mtls/03-enter-certificate-password.png)

1. The **org-mkcert development certificate** should now be in your list of certificates:

    ![certificate list](./img/mtls/04-certificate-list.png)

## Using the Client Certificate

You can now visit **<https://verify.localhost.pomerium.io>** (or another route you've defined) and you should be prompted to choose a client certificate:

![choose client certificate](./img/mtls/05-select-client-certificate.png)

[Quick-Start]: /docs/install/readme.md
[Identity Provider]: /docs/identity-providers/readme.md
