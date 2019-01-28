#!/bin/bash
# NOTE! This will create real resources on Google's cloud. Make sure you clean up any unused
# resources to avoid being billed. For reference, this tutorial cost me <10 cents for a couple of hours.

# create a cluster
gcloud container clusters create pomerium
# get cluster credentials os we can use kubctl locally
gcloud container clusters get-credentials pomerium
# create `pomerium` namespace
kubectl create ns pomerium

# create our cryptographically random keys
kubectl create secret generic -n pomerium shared-secret --from-literal=shared-secret=$(head -c32 /dev/urandom | base64)
kubectl create secret generic -n pomerium cookie-secret --from-literal=cookie-secret=$(head -c32 /dev/urandom | base64)

# load TLS for pomerium services
kubectl create secret generic -n pomerium certificate --from-literal=certificate=$(base64 -i cert.pem)
kubectl create secret generic -n pomerium certificate-key --from-literal=certificate-key=$(base64 -i privkey.pem)

# load  TLS to ingress
kubectl create secret tls -n pomerium pomerium-tls --key privkey.pem --cert cert.pem

#                       !!! IMPORTANT !!!
#          YOU MUST CHANGE THE Identity Provider Client Secret
#                       !!! IMPORTANT !!!
# kubectl create secret generic -n pomerium idp-client-secret --from-literal=REPLACE_ME

# Create the proxy & authenticate deployment
kubectl create -f docs/docs/examples/kubernetes/authenticate.deploy.yml
kubectl create -f docs/docs/examples/kubernetes/proxy.deploy.yml
# Create the proxy & authenticate services
kubectl apply -f docs/docs/examples/kubernetes/proxy.service.yml
kubectl apply -f docs/docs/examples/kubernetes/authenticate.service.yml
# Create and apply the Ingress; this is GKE specific
kubectl apply -f docs/docs/examples/kubernetes/ingress.yml

# When done, clean up by deleting the cluster!
# gcloud container clusters delete pomerium
