# Pomerium on Cloud Run

Run this demo with gcloud command line configured for your project.  The commands assume 
all resources (Cloud Run, Cloud DNS, and Secret Manager) are in a single project.  

We recommend a dedicated project that is easy to clean up.

## Note
When deployed to Cloud Run, your protected application must authenticate requests from Pomerium
by either inspecting the [X-Pomerium-Jwt-Assertion](https://www.pomerium.com/docs/reference/getting-users-identity.html),
or [GCP Serverless Authorization](https://cloud.google.com/run/docs/authenticating/service-to-service) header.

This demo includes a Cloud Run target configured to only accept requests from the Pomerium deployment.

## Includes

- Authentication and Authorization managed by pomerium
- Custom Cloud Run domains
- Cloud Run target
- HTTPBin target

## How

- Update `config.yaml` for your e-mail address, if not using gmail/google.
- Replace secrets in `config.yaml`.
- Replace `cloudrun.pomerium.io` with your own domain.
- Update your DNS
- Deploy config.yaml to Secret Manager
- Deploy the demo hello world app
- Deploy pomerium with policy
- Navigate to `https://httpbin.cloudrun.pomerium.io`
- Navigate to `https://hello-direct.cloudrun.pomerium.io`
- Navigate to `https://hello.cloudrun.pomerium.io`