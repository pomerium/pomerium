---
title: Google
lang: en-US
sidebarDepth: 0
meta:
  - name: keywords
    content: google gsuite gmail oidc openid-connect workspaces
---

# Google Workspace (formerly known as G Suite)

This guide covers the basics of setting up Pomerium to use GCP and Google Workspace / G Suite as your identity provider.

::: warning

Google changes their configuration screens frequently. Please refer to Google's documentation for authoritative instructions.

- [Setting up OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [Perform Google Workspace Domain-Wide Delegation of Authority](https://developers.google.com/admin-sdk/directory/v1/guides/delegation)

:::

## Setting up OAuth 2.0

You need [OAuth 2.0 credentials](https://developers.google.com/identity/protocols/oauth2/openid-connect), including a client ID and client secret, to authenticate users.

### Create OAuth 2.0

Log in to your Google account and go to the [APIs & services](https://console.developers.google.com/projectselector/apis/credentials).

1. Navigate to **Credentials** using the left-hand menu.
2. On the **Credentials** page, click **Create credentials** and choose **OAuth [Client ID]**.

![Create New Credentials](./img/google/google-credentials.png)

::: warning

If you don't currently have an OAuth consent page configured, Google will not allow you to create credentials until this is completed. Please follow Google's [instructions](https://developers.google.com/identity/protocols/oauth2/openid-connect#consentpageexperience) for doing so.

:::

### Set a redirect URI

The redirect URI that you set in the API Console tells Google where Pomerium's authentication callback URL is. On the **Create [Client ID]** page, select **Web application**.

To create, view, or edit the redirect URIs for a given OAuth 2.0 credential, do the following:

1. Go to the [Credentials](https://console.developers.google.com/apis/credentials) page.
2. In the OAuth 2.0 client IDs section of the page, click a credential.
3. View or edit the redirect URIs.

If there is no OAuth 2.0 client IDs section on the Credentials page, then your project has no OAuth credentials. To create one, click Create credentials.

Field        | Description
------------ | ------------------------------------------------------------------------
Name         | The name of your web app
Redirect URI | Redirect URL `https://${authenticate_service_url}/oauth2/callback` (e.g.`https://authenticate.localhost.pomerium.io/oauth2/callback`)

![Web App Credentials Configuration](./img/google/google-create-client-id-config.png)

## Setting up directory Sync

### Create a service account

In order to have Pomerium validate group membership, we'll also need to configure a [service account](https://console.cloud.google.com/iam-admin/serviceaccounts) with [G-suite domain-wide delegation](https://developers.google.com/admin-sdk/directory/v1/guides/delegation) enabled.

1. Open the [**Service accounts** page](https://console.developers.google.com/iam-admin/serviceaccounts). If prompted, select a project.
2. Click add **Create Service Account**, enter a name and description for the service account. You can use the default service account ID, or choose a different, unique one. When done click **Create**.
3. The **Service account permissions (optional)** section that follows is not required. Click **Continue**.
4. On the **Grant users access to this service account** screen, scroll down to the **Create key** section. Click add **Create key**.
5. In the side panel that appears, select the format for your key: **JSON**.
6. Click **Create**. Your new public/private key pair is generated and downloaded to your machine; it serves as the only copy of this key. For information on how to store it securely, see [Managing service account keys](https://cloud.google.com/iam/docs/understanding-service-accounts#managing_service_account_keys).
7. Click **Close** on the **Private key saved to your computer** dialog, then click **Done** to return to the table of your service accounts.

Next, we need to enable enable G Suite domain-wide delegation, follow these steps:

1. Locate the newly-created service account in the table. Under **Actions**, click **Edit**.
2. In the service account details, click expand_more **Show domain-wide delegation**, then ensure the **Enable G Suite Domain-wide Delegation** checkbox is checked.
3. If you haven't yet configured your app's OAuth consent screen, you must do so before you can enable domain-wide delegation. Follow the on-screen instructions to [configure the OAuth consent screen](https://support.google.com/cloud/answer/10311615?hl=en&ref_topic=3473162#), then repeat the above steps and re-check the checkbox.
4. Click **Save** to update the service account, and return to the table of service accounts. A new column, **Domain-wide delegation**, can be seen. Click **View Client ID**, to obtain and make a note of the client ID.

### Set the impersonating user


Then, you'll need to manually open an editor and add an `impersonate_user` field to the downloaded public/private key file. In this case, we'd be impersonating the admin account `user@pomerium.io`.

::: warning

[Google requires](https://stackoverflow.com/questions/48585700/is-it-possible-to-call-apis-from-service-account-without-acting-on-behalf-of-a-u/48601364#48601364) that service accounts act on behalf of another user. You MUST add the `impersonate_user` field to your json key file.

:::

```git
{
  "type": "service_account",
  "project_id": "pomerium-redacted",
  "private_key_id": "e07f7c93870c7e03f883560ecd8fd0f4d27b0081",
  "private_key": "-----BEGIN PRIVATE KEY-----\\n-----END PRIVATE KEY-----\n",
  "client_email": "redacted@pomerium-redacted.iam.gserviceaccount.com",
  "client_id": "101215990458000334387",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/redacted%40pomerium-redacted.iam.gserviceaccount.com",
+  "impersonate_user": "user@pomerium.com"
}
```

The base64 encoded contents of this public/private key pair json file will used for the value of the IdP [service account] configuration setting.

### Set directory permissions for Workspaces

Next, we need to give that service account permissionson the GSuite / Workspace side of the house.

1. From your Google Workspace domain's [Admin console](http://admin.google.com/), go to **Main menu** > **Security** > **API controls**.
2. In the **Domain wide delegation** pane, select **Manage Domain Wide Delegation**.
3. Click **Add new**.
4. In the **Client ID** field, enter the client ID obtained from the service account creation steps above.
5. In the **OAuth Scopes** field, enter a comma-delimited list of the scopes required for your application (for a list of possible scopes, see [Authorize requests](https://developers.google.com/admin-sdk/directory/v1/guides/authorizing)).
6. Enter the following list of scopes: `https://www.googleapis.com/auth/admin.directory.group.readonly` `https://www.googleapis.com/auth/admin.directory.user.readonly`
7. Click the **Authorize** button.

![Google create service account](./img/google/google-gsuite-add-scopes.png)

Your [environmental variables] should look something like this.

```bash
IDP_PROVIDER="google"
IDP_PROVIDER_URL="https://accounts.google.com"
IDP_CLIENT_ID="yyyy.apps.googleusercontent.com"
IDP_CLIENT_SECRET="xxxxxx"
IDP_SERVICE_ACCOUNT="zzzz" # output of `base64 -i service-account-key.json`
```

[client id]: ../../reference/readme.md#identity-provider-client-id
[client secret]: ../../reference/readme.md#identity-provider-client-secret
[environmental variables]: https://en.wikipedia.org/wiki/Environment_variable
[oauth2]: https://oauth.net/2/
[openid connect]: https://en.wikipedia.org/wiki/OpenID_Connect
[service account]: ../../reference/readme.md#identity-provider-service-account
