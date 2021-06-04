#!/bin/bash

# Install gcloud beta
gcloud components install beta

# Set your desired working project
gcloud config set run/platform managed

# Capture current project number and ID
PROJECTNUM=$(gcloud projects describe $(gcloud config get-value project) --format='get(projectNumber)')
PROJECTID=$(gcloud projects describe $(gcloud config get-value project) --format='get(projectId)')

# Deploy our protected application and associate a DNS name
gcloud run deploy hello --image=gcr.io/cloudrun/hello --region us-central1 --no-allow-unauthenticated

# Create an identity for the Pomerium proxy
gcloud iam service-accounts create pomerium

gcloud run services add-iam-policy-binding hello --region us-central1 \
    --member serviceAccount:pomerium@${PROJECTID}.iam.gserviceaccount.com \
    --role=roles/run.invoker




# Rewrite policy file with unique 'hello' service URL
HELLO_URL=$(gcloud run services describe hello --region us-central1 --format 'value(status.address.url)') \
COOKIE_SECRET=$(head -c32 /dev/urandom | base64) \
SHARED_SECRET=$(head -c32 /dev/urandom | base64) \
URL_HASH=$(gcloud run services describe hello --region us-central1 --format='get(status.address.url)' | rev | cut -d- -f2 | rev) \
envsubst <config.template.yaml >config.yaml

# Install our base configuration in a GCP secret
gcloud secrets create --data-file config.yaml pomerium-config --replication-policy automatic

# Grant the default compute account access to the secret
gcloud secrets add-iam-policy-binding pomerium-config \
    --member=serviceAccount:pomerium@${PROJECTID}.iam.gserviceaccount.com \
    --role=roles/secretmanager.secretAccessor

# Deploy pomerium with policy and configuration references
gcloud alpha run deploy pomerium --region us-central1 --allow-unauthenticated --min-instances 1 \
   --set-secrets="/pomerium/config.yaml=pomerium-config:latest" \
   --set-env-vars "ADDRESS=:8080" \
   --set-env-vars "GRPC_INSECURE=true" \
   --set-env-vars "INSECURE_SERVER=true" \
   --image=gcr.io/ptone-misc-sodo/pomerium:latest 
#    --image=gcr.io/pomerium-io/pomerium:latest 

echo ""
echo "Deploy completed, update OAuth client with this callback URL:"
echo "$(gcloud run services describe pomerium --region us-central1 --format='get(status.address.url)')/oauth2/callback"
