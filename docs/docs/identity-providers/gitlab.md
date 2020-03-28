---
title: GitLab
lang: en-US
sidebarDepth: 0
meta:
  - name: keywords
    content: gitlab oidc openid-connect identity-provider
---

# GitLab

Log in to your GitLab account or create one [here](https://gitlab.com/users/sign_in)

Go to the user settings which can be found in the user profile to [create an application](https://gitlab.com/profile/applications) where you will get your app credentials

![create an application](./img/gitlab/gitlab-create-applications.png)

On the **Applications** page, add a new application by setting the following parameters:

Field        | Description
------------ | --------------------------------------------
Name         | The name of your web app
Redirect URI | `https://${authenticate_service_url}/oauth2/callback`
Scopes       | **Must** select **read_user** and **openid**

[Group ID](https://docs.gitlab.com/ee/api/groups.html#details-of-a-group) will be used to affirm group(s) a user belongs to.

Your `Client ID` and `Client Secret` will be displayed:

![Gitlab OAuth Client ID and Secret](./img/gitlab/gitlab-credentials.png)

Set `Client ID` and `Client Secret` in Pomerium's settings. Your environment variables should look something like this.

```bash
authenticate_service_url: https://authenticate.localhost.pomerium.io
idp_provider: "gitlab"
idp_client_id: "REDACTED"   // gitlab application ID
idp_client_secret: "REDACTED"   // gitlab application secret
```

When a user first uses pomerium to login, they will be presented with an authorization screen similar to the following depending on the scope parameters setup.

![gitlab access authorization screen](./img/gitlab/gitlab-verify-access.png)
