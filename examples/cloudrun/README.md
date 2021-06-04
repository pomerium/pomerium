# Pomerium on Cloud Run

Run this demo with gcloud command line configured for your project.  The commands assume
all resources (Cloud Run, Cloud DNS, and Secret Manager) are in a single project.

We recommend a dedicated project that is easy to clean up.

## Note
When deployed to [Cloud Run](https://cloud.google.com/run), your protected application must authenticate requests from Pomerium
by either inspecting the [X-Pomerium-Jwt-Assertion](https://www.pomerium.com/docs/reference/getting-users-identity.html),
or [GCP Serverless Authorization](https://cloud.google.com/run/docs/authenticating/service-to-service) header.

This demo includes a Cloud Run target configured to only accept requests from the Pomerium deployment.

## Includes

- Authentication and Authorization managed by pomerium
- Cloud Run target
## How

gcloud config set project [yourprojectid]
export OAUTH_CLIENT_ID=[client-id]
export OAUTH_CLIENT_SECRET=[client-secret]

- Update `config.yaml` for your e-mail address, if not using gmail/google.
- Replace secrets in `config.yaml`.
- Deploy config.yaml to Secret Manager
- Deploy the demo hello world app
- Deploy pomerium with policy
- Navigate to 

- Navigate to `https://verify.cloudrun.pomerium.io`
- Navigate to `https://hello-direct.cloudrun.pomerium.io`
- Navigate to `https://hello.cloudrun.pomerium.io`
