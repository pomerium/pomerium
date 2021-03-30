---
title: Overview
description: >-
  This article describes how to connect Pomerium to third-party identity
  providers / single-sign-on services. You will need to generate keys, copy
  these into your Pomerium settings, and enable the connection.
---

# Identity Provider Configuration

This article describes how to configure Pomerium to use a third-party identity service for single-sign-on.

There are a few configuration steps required for identity provider integration. Most providers support [OpenID Connect] which provides a standardized identity and authentication interface.

In this guide we'll cover how to do the following for each identity provider:

1. Set a **[Redirect URL](https://www.oauth.com/oauth2-servers/redirect-uris/)** pointing back to Pomerium. For example, `https://${authenticate_service_url}/oauth2/callback`.
2. Generate a **[Client ID]** and **[Client Secret]**.
3. Generate a **[Service Account]** for additional IdP Data.
4. Configure Pomerium to use the **[Client ID]** and **[Client Secret]** keys.
5. Configure Pomerium to synchronize directory data from your identity provider (e.g. groups membership), by setting a service account. 

:::warning

You must configure an IdP **[Service Account]** to write policy against group membership, or any other data that does not uniquely identify an end-user.

[client id]: ../../reference/readme.md#identity-provider-client-id
[client secret]: ../../reference/readme.md#identity-provider-client-secret
[environmental variables]: https://en.wikipedia.org/wiki/Environment_variable
[oauth2]: https://oauth.net/2/
[openid connect]: https://en.wikipedia.org/wiki/OpenID_Connect
[service account]: ../../reference/readme.md#identity-provider-service-account


### Pomerium-Dex-Freeipa Exercise

**This exercise depicts the authentication flow for the services which don't have authentication flow**

*Flow with the diagram*

![alt text](https://github.com/dharmendrakariya/pomerium-dex/blob/main/image.jpg?raw=true)


1. User makes an unauthenticated request to the service

2. Pomerium proxy receives the request and recognizes it as anonymous

3. It redirects the user to the auth provider for authentication

4. Upon successful login, Pomerium provides an auth cookie to the user. In the picture you can see the dex approval page before that.

5. Based on the cookie, Pomerium identifies the user and checks policy to determine whether to permit access. Authorization is based on identity factors like id, email,      group, role, or email domain.

6. When the cookie expires, the login flow gets triggered all over again.


*Here is our flow for accessing nextcloud service*

1. User access https://hello.YOURDOMAIN.dev

2. It will be redirected to the https://authenticate.YOURDOMAIN.dev (which is pomerium's authenticate service url)

3. Pomerium's authenticate service will redirect this to check at oidc provider( in our case DEX).

4. Dex(which is backed by FreeIpa in our case, freeipa's LDAP as backend) will check if the user is valid or not and after that flow gets redirected to pomerium back if user is valid.

5. User is finally redirected to the nextcloud service if all goes well.


Now to implement this flow we have configured static dex client ```pom``` with pomerium's authenticate service redirectURL

```Note: I am using dex helm chart and in backend freeipa as a ldap server```

```
connectors:
      - config:
          bindDN: uid=dex,cn=sysaccounts,cn=etc,dc=YOURDOMAIN,dc=dev
          bindPW: mN****tG****
          host: freeipa.YOURDOMAIN.dev:636
          insecureNoSSL: false
          insecureSkipVerify: true

          # (Group Search )
          groupSearch:
            baseDN: cn=groups,cn=accounts,dc=YOURDOMAIN,dc=dev
            filter: "(|(objectClass=posixGroup)(objectClass=group))"
            userAttr: DN # Use "DN" here not "uid"
            groupAttr: member
            nameAttr: cn

          # (User Search)
          userSearch:
            baseDN: cn=users,cn=accounts,dc=YOURDOMAIN,dc=dev
            emailAttr: mail
            filter: ""
            idAttr: uidNumber
            nameAttr: displayName
            preferredUsernameAttr: uid
            username: mail
          usernamePrompt: Email
        id: ldap
        name: FreeIPA/LDAP
        type: ldap
      issuer: http://dex.YOURDOMAIN.dev
      logger:
        level: debug
      oauth2:
        responseTypes:
        - code
        skipApprovalScreen: false

      staticClients:
      # (Here I am creating static client for pomerium)
      - id: pom
        name: pom
        redirectURIs:
        # (pomerium authenticate service url)
        - https://authenticate.YOURDOMAIN.dev/oauth2/callback
        secret: pomerium

```
Below is configuration which supposed to be done in Pomerium

```Note: I am using Pomerium helm chart```

```
config:
  # routes under this wildcard domain are handled by pomerium
  rootDomain: YOURDOMAIN.dev

  policy:
      # (give any name instead of hello, this will be the proxy url to access the particular service)
    - from: https://hello.YOURDOMAIN.dev
      # (give fqdn of the actual service which is being authenticated, here I am giving nextcloud service endpoint, which is running in nextcloud namespace)
      to: http://nextcloud.nextcloud.svc.cluster.local:8080

      # allowed_domains:
          #(in general give here your domain)
      #   - YOURDOMAIN.dev

      # (If you want to give access to particular group members, I have tested this by creating devops group and members in that group, in freeipa)
      allowed_groups:
        - devops

      # (If you want to give access to particular group members, I have tested this by creating devops group and members in that group, in freeipa)
      allowed_idp_claims:
        groups:
        - devops

  # (I didn't specify the root level CAs so)
  insecure: true

extraEnv:
  # (This will give you details if user is not able to authenticate, ideally this should be turned off)
  POMERIUM_DEBUG: true
  LOG_LEVEL: "error"
  IDP_SCOPES: "openid,profile,email,groups,offline_access"

authenticate:
  # (This we have set in dex's static client also remember! should be same)
  redirectUrl: "https://authenticate.YOURDOMAIN.dev/oauth2/callback"

  idp:
    provider: oidc
    clientID: pom
    clientSecret: pomerium
    # (your dex url)
    url: http://dex.YOURDOMAIN.dev
    scopes: "openid profile email groups offline_access"
    # (for group based access policy)
    serviceAccount: "pomerium-authenticate"

ingress:
  enabled: true
  authenticate:
    name: ""
  secretName: ""
  secret:
    name: ""
    cert: ""
    key: ""
  tls:
    hosts: []
  hosts: []
  annotations:
    kubernetes.io/ingress.class: nginx
    kubernetes.io/ingress.allow-http: "true"

resources:
  limits:
    cpu: 150m
    memory: 100Mi
  requests:
    cpu: 100m
    memory: 100Mi

```


