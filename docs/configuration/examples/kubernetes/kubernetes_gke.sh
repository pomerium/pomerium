#!/bin/bash
# NOTE! This will create real resources on Google GCP. Make sure you clean up any unused
# resources to avoid being billed.
# For reference, this tutorial cost ~10 cents for a couple of hours.
# NOTE! You must change the identity provider client secret setting in your config file!

echo "=> creating cluster"
gcloud container clusters create pomerium --num-nodes 2

echo "=> get cluster credentials so we can use kubctl locally"
gcloud container clusters get-credentials pomerium

echo "=> create config from kubernetes-config.yaml which we will mount"
kubectl create configmap config --from-file="config.yaml"="kubernetes-config.yaml"

echo "=> create our random shared-secret and cookie-secret keys as envars"
kubectl create secret generic shared-secret --from-literal=shared-secret=$(head -c32 /dev/urandom | base64)
kubectl create secret generic cookie-secret --from-literal=cookie-secret=$(head -c32 /dev/urandom | base64)

echo "=> initiliaze secrets for TLS wild card for service use"
kubectl create secret generic certificate \
	--from-literal=certificate=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/fullchain.cer")
kubectl create secret generic certificate-key \
	--from-literal=certificate-key=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/*.corp.beyondperimeter.com.key")

echo "=> load TLS to ingress"
kubectl create secret tls pomerium-tls \
	--key "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/*.corp.beyondperimeter.com.key" \
	--cert "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/fullchain.cer"

echo "=> deploy pomerium proxy, authorize, and authenticate"
kubectl apply -f pomerium-proxy.yml
kubectl apply -f pomerium-authenticate.yml
kubectl apply -f pomerium-authorize.yml

echo "=> deploy our test app, httpbin"
kubectl apply -f httpbin.yml

echo "=> deploy the GKE specific ingress"
kubectl apply -f ingress.yml

# Alternatively, nginx-ingress can be used
# kubectl apply -f ingress.nginx.yml

# When done, clean up by deleting the cluster!
# gcloud container clusters delete pomerium
