---
title: GitLab
lang: en-US
sidebarDepth: 0
meta:
  - name: keywords
    content: gitlab, oidc, openid connect, identity provider, idp
---

# GitLab

This document details how to use GitLab as an identity provider with Pomerium. It assumes you have already [installed Pomerium](/docs/install/readme.md)

::: warning
While we do our best to keep our documentation up to date, changes to third-party systems are outside our control. Refer to [GitLab as an OAuth 2.0 authentication service provider](https://docs.gitlab.com/ee/integration/oauth_provider.html) from GitLab's docs as needed, or [let us know](https://github.com/pomerium/pomerium/issues/new?assignees=&labels=&template=bug_report.md) if we need to re-visit this page.
:::

## Setting up GitLab OAuth2 for your Application

1. Log in to your GitLab account or create one [here](https://gitlab.com/users/sign_in). If you're using a self-hosted instance, log in to your custom GitLab domain.

1. From the User Settings area, select [**Applications**](https://gitlab.com/-/profile/applications). Create a new application:

   ![create an application](./img/gitlab/gitlab-create-applications.png)

1. Add a new application by setting the following parameters:

   Field        | Description
   ------------ | ---------------------------------------------------------------------------------
   Name         | The name of your web app
   Redirect URI | `https://${authenticate_service_url}/oauth2/callback`
   Scopes       | `openid`, `profile`, `email`

   Click **Save application**.

1. Your **Application ID** and **Secret** will be displayed:

   ![Gitlab OAuth Client ID and Secret](./img/gitlab/gitlab-credentials.png)

   Note the ID and Secret to apply in Pomerium's settings.

## Service Account

To use `allowed_groups` in a policy, an `idp_service_account` needs to be set in the Pomerium configuration. The service account for Gitlab uses a personal access token generated at: [gitlab.com/-/profile/personal_access_tokens](https://gitlab.com/-/profile/personal_access_tokens) with `read_api` access:

![Gitlab Personal Access Token](./img/gitlab/gitlab-personal-access-token.png)

The format of the `idp_service_account` for Gitlab is a base64-encoded JSON document:

```json
{
  "private_token": "..."
}
```

If you save this JSON document as a temporary file, you can encode it like this:

```bash
cat json.tmp | base64 -w 0
```

## Pomerium Configuration

Edit your Pomerium configuration to provide the Client ID, secret, service credentials, and domain (for self-hosted instances):

### GitLab.com

:::: tabs
::: tab config.yaml
```yaml
idp_provider: "gitlab"
idp_client_id: "REDACTED"   # gitlab application ID
idp_client_secret: "REDACTED"   # gitlab application secret
idp_service_account: "REDACTED"   # gitlab service account, base64-encoded json
```
:::
::: tab Environment Variables
```bash
IDP_PROVIDER="gitlab"
IDP_CLIENT_ID="REDACTED" # gitlab application ID
IDP_CLIENT_SECRET="REDACTED" # gitlab application secret
IDP_SERVICE_ACCOUNT="REDACTED" # gitlab service account, base64-encoded json
```
:::
::::

### Self-Hosted GitLab

Self-hosted CE/EE instances should be configured as a generic OpenID Connect provider:

:::: tabs
::: tab config.yaml
```yaml
idp_provider: oidc
idp_client_id: "REDACTED"
idp_client_secret: "REDACTED"
idp_scopes: openid,profile,email
idp_provider_url: https://gitlab.example.com # Base URL of GitLab instance
idp_service_account: "REDACTED"   # gitlab service account, base64-encoded json
```
:::
::: tab Environment Variables
```bash
IDP_PROVIDER="oidc"
IDP_CLIENT_ID="REDACTED"
IDP_CLIENT_SECRET="REDACTED"
IDP_SCOPES="openid,profile,email"
IDP_PROVIDER_URL="https://gitlab.example.com" # Base URL of GitLab instance
IDP_SERVICE_ACCOUNT="REDACTED"   # gitlab service account, base64-encoded json
```
:::
::::

---

When a user first uses Pomerium to login, they are presented with an authorization screen:

![gitlab access authorization screen](./img/gitlab/gitlab-verify-access.png)

Please be aware that [Group ID](https://docs.gitlab.com/ee/api/groups.html#details-of-a-group) will be used to affirm group(s) a user belongs to.