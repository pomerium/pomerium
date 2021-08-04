---
title: Local OIDC Provider
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc
description: >-
  This guide covers how to use Pomerium with a local OIDC provider using [qlik/simple-oidc-provider].
---

# Local OIDC Provider

You can use the same below configs for other supported [identity providers](/docs/identity-providers/readme.md).

## Configure
### Docker-compose

```yaml
version: "3"
services:
  pomerium:
    image: pomerium/pomerium:latest
    environment:
      # Generate new secret keys. e.g. `head -c32 /dev/urandom | base64`
      - COOKIE_SECRET=<reducted>
    volumes:
      # Mount your domain's certificates : https://www.pomerium.com/docs/reference/certificates
      - ./_wildcard.localhost.pomerium.io-key.pem:/pomerium/privkey.pem:ro
      - ./_wildcard.localhost.pomerium.io.pem:/pomerium/cert.pem:ro
      # Mount your config file : https://www.pomerium.com/docs/reference/

      - ./config.yaml:/pomerium/config.yaml
    ports:
      - 443:443
      - 5443:5443
      - 17946:7946
    depends_on:
      - identityprovider

  verify:
    image: pomerium/verify
    expose:
      - 80

  identityprovider:
    image: qlik/simple-oidc-provider
    environment:
      - CONFIG_FILE=/etc/identityprovider.json
      - USERS_FILE=/etc/identityprovider-users.json
    volumes:
      - ./identityprovider.json:/etc/identityprovider.json:ro
      - ./identityprovider-users.json:/etc/identityprovider-users.json:ro
    ports:
      - 9000:9000
```

You can generate certificates for `*.localhost.pomerium.io` using [this instruction](/docs/topics/certificates.md#certificates-2)

### Pomerium config

```yaml
# config.yaml
# See detailed configuration settings : https://www.pomerium.com/docs/reference/

authenticate_service_url: https://authenticate.localhost.pomerium.io

autocert: false

certificate_file: /pomerium/cert.pem
certificate_key_file: /pomerium/privkey.pem

idp_provider_url: http://identityprovider:9000
idp_provider: oidc
idp_client_id: foo
idp_client_secret: bar

# Generate 256 bit random keys  e.g. `head -c32 /dev/urandom | base64`
cookie_secret: <reducted>

# https://www.pomerium.io/configuration/#policy
policy:
  - from: https://verify.localhost.pomerium.io
    to: http://verify
    allowed_domains:
      - example.org
```

### identityprovider.json

```json
{
  "idp_name": "http://identityprovider:9000",
  "port": 9000,
  "client_config": [
    {
      "client_id": "foo",
      "client_secret": "bar",
      "redirect_uris": [
        "https://authenticate.localhost.pomerium.io/oauth2/callback"
      ]
    }
  ],
  "claim_mapping": {
    "openid": [ "sub" ],
    "email": [ "email", "email_verified" ],
    "profile": [ "name", "nickname" ]
  }
}
```

### identityprovider-users.json

```json
[
  {
    "id": "SIMPLE_OIDC_USER_ALICE",
    "email": "alice@example.org",
    "email_verified": true,
    "name": "Alice Smith",
    "nickname": "al",
    "password": "abc",
    "groups": ["Everyone", "Engineering"]
  },
  {
    "id": "SIMPLE_OIDC_USER_BOB",
    "email": "bob@example.org",
    "email_verified": true,
    "name": "Bob Smith",
    "nickname": "bobby",
    "password": "abc",
    "groups": ["Everyone", "Sales"]
  }
]
```

## Run

### Edit hosts file

Add following entry to `/etc/hosts`:

```
127.0.0.1 identityprovider
```

### Start services

```shell script
$ docker-compose up -d identityprovider
$ : wait identityprovider up
$ docker-compose up -d
```

Now accessing to `https://verify.localhost.pomerium.io` and you will be redireted to OIDC server for authentication.

[identity provider]: ../docs/identity-providers/readme.md
[qlik/simple-oidc-provider]: https://hub.docker.com/r/qlik/simple-oidc-provider/
