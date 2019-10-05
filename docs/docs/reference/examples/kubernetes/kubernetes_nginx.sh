#!/bin/bash
echo "=> create config from kubernetes-config.yaml which we will mount"
kubectl create configmap config --from-file="config.yaml"="kubernetes-config.yaml"

echo "=> create our random shared-secret and cookie-secret keys as envars"
kubectl create secret generic shared-secret --from-literal=shared-secret=$(head -c32 /dev/urandom | base64)
kubectl create secret generic cookie-secret --from-literal=cookie-secret=$(head -c32 /dev/urandom | base64)

echo "=> deploy pomerium proxy, authorize, and authenticate"
kubectl apply -f pomerium-proxy.yml
kubectl apply -f pomerium-authenticate.yml
kubectl apply -f pomerium-authorize.yml

echo "=> deploy our test app, httpbin"
kubectl apply -f httpbin.yml

echo "=> deploy nginx-ingress"
kubectl apply -f ingress.yml
