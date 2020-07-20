#!/bin/bash

# Install gcloud beta
gcloud components install beta

# Capture current project number
PROJECT=$(gcloud projects describe $(gcloud config get-value project) --format='get(projectNumber)')

# Point a wildcard domain of *.cloudrun.pomerium.io to the cloudrun front end
gcloud dns record-sets import --zone pomerium-io zonefile --zone-file-format

# Deploy our protected application and associate a DNS name
gcloud run deploy hello --image=gcr.io/cloudrun/hello --region us-central1 --platform managed --no-allow-unauthenticated
gcloud run services add-iam-policy-binding hello --platform managed --region us-central1 \
    --member=serviceAccount:${PROJECT}-compute@developer.gserviceaccount.com \
    --role=roles/run.invoker
gcloud beta run domain-mappings --platform managed --region us-central1 create --service=hello --domain hello-direct.cloudrun.pomerium.io

# Rewrite policy file with unique 'hello' service URL
HELLO_URL=$(gcloud run services describe hello --platform managed --region us-central1 --format 'value(status.address.url)') envsubst <policy.template.yaml >policy.yaml

# Install our base configuration in a GCP secret
gcloud secrets create --data-file config.yaml pomerium-config --replication-policy automatic

# Grant the default compute account access to the secret
gcloud secrets add-iam-policy-binding pomerium-config \
    --member=serviceAccount:${PROJECT}-compute@developer.gserviceaccount.com \
    --role=roles/secretmanager.secretAccessor

# Deploy pomerium with policy and configuration references
gcloud run deploy pomerium --region us-central1 --platform managed --allow-unauthenticated --max-instances 1 \
    --image=gcr.io/pomerium-io/pomerium:v0.10.0-rc2-cloudrun \
    --set-env-vars VALS_FILES="/pomerium/config.yaml:ref+gcpsecrets://${PROJECT}/pomerium-config",POLICY=$(base64 policy.yaml)

# Set domain mappings for the protected routes and authenticate
gcloud beta run domain-mappings --platform managed --region us-central1 create --service=pomerium --domain hello.cloudrun.pomerium.io
gcloud beta run domain-mappings --platform managed --region us-central1 create --service=pomerium --domain authn.cloudrun.pomerium.io
gcloud beta run domain-mappings --platform managed --region us-central1 create --service=pomerium --domain httpbin.cloudrun.pomerium.io
