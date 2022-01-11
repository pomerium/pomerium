---
title: Cognito
lang: en-US
# sidebarDepth: 0
meta:
  - name: keywords
    content: amazon, aws, cognito, openid, oidc, identity provider, idp
---

# Cognito

This document describes the use of AWS Cognito as an identity provider with Pomerium. It assumes you have already [installed Pomerium](/docs/install/readme.md)

## Setting up AWS Cognito

### Create a User Pool

1. Log in to the [AWS Console](https://console.aws.amazon.com) account. Go to **Services** on the top menu, and search for **Cognito**:

   ![AWS Cognito Services](./img/cognito/cognito-service.png)

1. Once you have selected **Cognito**, you will be presented with the option of **Manage User Pools** or **Manage Identity Pools**. Pick **Manage User Pools**:

   ![AWS Cognito User or Identity Pools](./img/cognito/cognito-pools.png)

1. The next page shows any User Pools you have already created, or the option to **Create a User Pool**:

   ![AWS Cognito Creating User Pool](./img/cognito/cognito-create-pool.png)

1. Give the pool a name, then choose to either **Review defaults** or **Step through settings**. It is up to you whether you choose to Review the defaults (and make some customization) or set up every setting individually.

   ![AWS Cognito Naming User Pool](./img/cognito/cognito-user-pool-name.png)

1. Assuming you selected **Review defaults**, you will see the following:

   ![AWS Cognito Pool Settings](./img/cognito/cognito-pool-settings.png)

   You can enable Multi-Factor Authentication (MFA), change your Password requirements, Tag the pool, among many other settings.

   ::: tip
   If you need to make changes after creating your pool, be aware that some settings will recreate the pool rather than update the existing pool. This will also generate new **Client IDs** and **Client Secrets**. An example would be changing _How do you want your end users to sign in?_ in **Attributes** from **Username** to **Email address or phone number**.
   :::

### Create an App Client

1. Once the pool is created, create an **App Client** under **General settings**. This is where you configure the Pomerium application settings. Choose **Add an App Client**:

   ![AWS Cognito Create App Client](./img/cognito/cognito-app-client-create.png)

1. Once the client is created, retrieve the **Client ID**, and the **Client Secret** by clicking **Show Details**.

   ![AWS Cognito App Client Details](./img/cognito/cognito-app-client-details.png)

1. Go to **App client settings** (in the Side menu under **App Integration**)

   ![AWS Cognito Side Menu](./img/cognito/cognito-side-menu.png)

   In the settings for **Pomerium** app, put in the following details

   | **Field**                  | **Description**                                                                              |
   | -------------------------- | -------------------------------------------------------------------------------------------- |
   | Enabled Identity Providers | Choose **Cognito User Pool**, unless you have set up another **Identity Provider** (eg SAML) |
   | Callback URL(s)            | https://${authenticate_service_url}/oauth2/callback                                          |
   | Allowed OAuth Flows        | Authorization code grant                                                                     |
   | Allowed OAuth Scopes       | Email, OpenID, Profile                                                                       |

1. **IMPORTANT**: For OAuth2 to work correctly with AWS Cognito, you must configure a **Domain name**. This is under **App integration** in the side menu

   ![AWS Cognito Domain Name](./img/cognito/cognito-domain-name.png)

You can choose whether to use your own **Domain Name**, or use an AWS-provided one. The AWS-provided domain names are in the format `https://${DOMAIN-PREFIX}.auth.${AWS-REGION}.amazoncognito.com`

## Pomerium Configuration

Once you have configured AWS Cognito, configure Pomerium to connext to it:

:::: tabs
::: tab config.yaml
```yaml
idp_provider: "oidc"
idp_provider_url: "https://cognito-idp.${AWS-REGION}.amazonaws.com/${USER-POOL-ID}"
idp_client_id: "304a12ktcc5djt9d7enj6dsjkg"
idp_client_secret: "1re5ukkv3dab6up5aefv7rru65lu60oblf04t6cv8u9s0itjbci7"
idp_scopes: "openid,profile,email"
```
:::
::: tab Environment Variables
```bash
IDP_PROVIDER="oidc"
IDP_PROVIDER_URL="https://cognito-idp.${AWS-REGION}.amazonaws.com/${USER-POOL-ID}"
IDP_CLIENT_ID="304a12ktcc5djt9d7enj6dsjkg"
IDP_CLIENT_SECRET="1re5ukkv3dab6up5aefv7rru65lu60oblf04t6cv8u9s0itjbci7"
IDP_SCOPES="openid,profile,email"
```
:::
::: tab Kubernetes ConfigMap
```yaml
apiVersion: v1
data:
  config.yaml: |
    # Main configuration flags : https://www.pomerium.io/reference/
    authenticate_service_url: https://k8s-auth-prod.example.com # The URL you have set up for the Pomerium Authentication service
    authorize_service_url: https://pomerium-authorize-service.default.svc.cluster.local

    idp_provider: oidc
    idp_provider_url: https://cognito-idp.${AWS-REGION}.amazonaws.com/${USER_POOL_ID}
    idp_client_id: 304a12ktcc5djt9d7enj6dsjkg
    idp_client_secret: "1re5ukkv3dab6up5aefv7rru65lu60oblf04t6cv8u9s0itjbci7"
    idp_scopes: ["openid", "email", "profile"]
kind: ConfigMap
metadata:
  name: pomerium-config
```
:::
::::

To retrieve the **User Pool ID**, go to **General Settings** in the Cognito Side menu within your pool. The **Pool ID** is just above the **Pool ARN**.
