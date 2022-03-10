---
title: Auth0
lang: en-US
sidebarDepth: 0
meta:
  - name: keywords
    content: auth0, pomerium, identity provider, idp
---

# Auth0

This page documents configuring an [Auth0] Web Application and Machine to Machine Application for Pomerium to read user data. It assumes you have already [installed Pomerium](/docs/install/readme.md).

::: warning
While we do our best to keep our documentation up to date, changes to third-party systems are outside our control. Refer to [Applications in Auth0](https://auth0.com/docs/applications) from Auth0's docs as needed, or [let us know](https://github.com/pomerium/pomerium/issues/new?assignees=&labels=&template=bug_report.md) if we need to re-visit this page.
:::

[Log in to your Auth0 account](https://manage.auth0.com/) and head to your dashboard. Select **Applications → Applications** on the left menu. On the Applications page, click the **Create Application** button to create a new app.

![Auth0 Applications Dashboard](./img/auth0/dashboard.png)

## Create Regular Web Application

1. On the **Create New Application** page, name your application and select the **Regular Web Application** for your application. This is the application that your users will login to.

   ![Auth0 Create Application Select Platform](./img/auth0/create.png)

1. Under the **Settings** tab, note the **Domain**, **Client ID**, and **Client Secret** values. We'll provide these to Pomerium at the end of the process.

1. Provide the following information for your application settings:

   | Field                        | Description                                                               |
   | ---------------------------- | ------------------------------------------------------------------------- |
   | Name                         | The name of your application.                                             |
   | Application Login URI        | [Authenticate Service URL] (e.g. `https://${authenticate_service_url}`)   |
   | Allowed Callback URLs        | Redirect URL (e.g. `https://${authenticate_service_url}/oauth2/callback`).|

1. Under **Advanced Settings** → **OAuth**, confirm that **JSON Web Token (JWT) Signature Algorithm** is set to "RS256".

1. Click **Save Changes** at the bottom of the page when you're done.

## Service Account

Next, we'll create an application to handle machine-to-machine communication from Pomerium to Auth0 in order to retrieve and establish group membership.

::: tip

Auth0 refers to groups as roles.

:::

1. Repeat the process in step 1 above to create a new application, but this time select **Machine to Machine Application**. A different application is used for grabbing roles to keep things more secure.

   ![Auth Create Application Select Service Account Platform](./img/auth0/create-m2m.png)

   Click **Create**.

1. On the next page select **Auth0 Management API** from the dropdown. Under **Permissions** use the filter on the right to narrow things down to `role`, and choose the `read:roles` and `read:role_members` roles.

   ![Auth0 Management API Scopes](./img/auth0/m2m-scopes.png)

   Then click **Authorize**.

1. Just like the previous step, retrieve the **Client ID** and **Client Secret** from the **Settings** tab. To build the `idp_service_account` value for Pomerium's configuration, you must base64-encode a JSON document containing the **Client ID** and **Client Secret** of the application:

   ```json
   {
   "client_id": "...",
   "secret": "..."
   }
   ```

   If you save this JSON document as a temporary file, you can encode it like this:

   ```bash
   cat json.tmp | base64 -w 0
   ```

## Configure Pomerium

You can now configure Pomerium with the identity provider settings retrieved in the previous steps. Your `config.yaml` keys or [environmental variables] should look something like this.

:::: tabs
::: tab config.yaml
```yaml
idp_provider: "auth0"
idp_provider_url: "https://awesome-company.auth0.com"
idp_client_id: "REPLACE_ME" # from the web application
idp_client_secret: "REPLACE_ME" # from the web application
idp_service_acount: "REPLACE_ME" # built from the machine-to-machine application, base64-encoded
```
:::
::: tab Environment Variables
```bash
IDP_PROVIDER="auth0"
IDP_PROVIDER_URL="https://awesome-company.auth0.com"
IDP_CLIENT_ID="REPLACE_ME" # from the web application
IDP_CLIENT_SECRET="REPLACE_ME" # from the web application
IDP_SERVICE_ACCOUNT="REPLACE_ME" # built from the machine-to-machine application, base64-encoded
```
:::
::::

[Auth0]: https://auth0.com/
[authenticate service url]: /reference/readme.md#authenticate-service-url
[environmental variables]: https://en.wikipedia.org/wiki/Environment_variable
