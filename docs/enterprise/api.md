---
title: API
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc reverse-proxy enterprise console api python go
---

# Enterprise Console API

The Pantheon Enterprise Console supports programmatic interaction through an API. This page covers enabling and authenticating to the API.

## Before You Begin

This doc assumes:
 - You already have installed Pomerium and Pomerium Enterprise,
 - The enterprise console service is encrypted. Review the [tls-*] keys for more information. 

## Configure a New Route

We suggest configuring the route for API access in the open-source Pomerium, so that breaking changes made via the API can still be resolved from the API:

```yaml
  - from: https://console-api.pomerium.localhost.io
    to: https://pomerium-console-domain-name:8702
    pass_identity_headers: true
    allow_any_authenticated_user: true
    tls_custom_ca_file: /path/to/rootCA.pem # See https://www.pomerium.com/reference/#tls-custom-certificate-authority 
```

## Create a Service Account

1. In the enterprise Console under **Configure -> Service Accounts**, Click **+ Add Service Account**. You can choose an existing user for the service account to impersonate, or create a new user. Note that a new user will not be synced to your IdP.

1. The Enterprise Console will display the service account token. Be sure to store it securely not, as you cannot view it again after this point. 

## Install The Library

:::: tabs
::: tab Python
```bash
pip3 install git+ssh://git@github.com/pomerium/enterprise-client-python.git
```
:::
::: tab Go
```bash
go get github.com:pomerium/enterprise-client-go.git
```
:::
::::
## Test the API Connection

[tls-*]: /enterprise/reference/config.html#tls-ca