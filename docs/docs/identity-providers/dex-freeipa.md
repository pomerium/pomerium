---
title: FreeIPA with Dex
description: >-
  This article describes how to connect Pomerium to third-party identity
  providers / single-sign-on services. You will need to generate keys, copy
  these into your Pomerium settings, and enable the connection.
---


### Pomerium-Dex-Freeipa Exercise

**This exercise depicts the authentication flow for the services which don't have authentication flow**

*Flow with the diagram*

![alt text](https://github.com/dharmendrakariya/pomerium-dex/blob/main/image.jpg?raw=true)


1. User makes an unauthenticated request to the service

2. Pomerium proxy receives the request and recognizes it as anonymous

3. It redirects the user to the auth provider for authentication

4. Upon successful login, Pomerium provides an auth cookie to the user.

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

```yaml
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

```yaml
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


