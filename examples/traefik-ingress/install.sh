#!/bin/bash

kubectl create namespace pomerium

# Create shared TLS secret
kubectl create secret tls wildcard-tls \
    --namespace pomerium \
    --cert=_wildcard.localhost.pomerium.io.pem \
    --key=_wildcard.localhost.pomerium.io-key.pem

# Install Traefik helm chart
helm upgrade --install --wait \
    --namespace pomerium \
    traefik traefik/traefik \
    --values values/traefik.yaml

# Install Pomerium helm chart
helm upgrade --install --wait \
    --namespace pomerium \
    pomerium pomerium/pomerium \
    --values values/pomerium.yaml

# Create middleware
kubectl apply -f crds/middleware.yaml

# Install hello app
helm upgrade --install --wait \
    --namespace pomerium \
    hello bitnami/nginx \
    --values values/hello.yaml
