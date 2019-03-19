#!/bin/bash
# PRE-REQ:
# 1) Install Helm : You should verify the content of this script before running.
# curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get | bash

echo "=> [GCE] creating cluster"
gcloud container clusters create pomerium

echo "=> [GCE] get cluster credentials so we can use kubctl locally"
gcloud container clusters get-credentials pomerium

echo "=> [GCE] ensure your user account has the cluster-admin role in your cluster"
kubectl create \
	clusterrolebinding \
	user-admin-binding \
	--clusterrole=cluster-admin \
	--user=$(gcloud config get-value account)

echo "=> Create a service account that Tiller, the server side of Helm, can use for deploying your charts."
kubectl create serviceaccount tiller --namespace kube-system

echo "=> Grant the Tiller service account the cluster-admin role in your cluster"
kubectl create clusterrolebinding tiller-admin-binding --clusterrole=cluster-admin --serviceaccount=kube-system:tiller

echo "=> initialize Helm to install Tiller in your cluster"
helm init --service-account=tiller
helm repo update

echo "=> install pomerium with helm substituting configuration values as required; be sure to change these"
helm install helm/. \
	--set config.sharedSecret=$(head -c32 /dev/urandom | base64) \
	--set config.cookieSecret=$(head -c32 /dev/urandom | base64) \
	--set config.cert=$(base64 -i cert.pem) \
	--set config.key=$(base64 -i privkey.pem) \
	--set config.policy=$(cat policy.example.yaml) \
	--set authentiate.idp.provider="google" \
	--set authentiate.proxyRootDomains="pomerium.io" \
	--set authentiate.redirectUrl="https://auth.corp.pomerium.io/oauth2/callback" \
	--set authentiate.idp.clientID="REPLACE_ME" \
	--set authentiate.idp.clientSecret="REPLACE_ME" \
	--set proxy.authenticateServiceUrl="https://auth.corp.pomerium.io" \
	--set proxy.authorizeServiceUrl="https://access.corp.pomerium.io"

# When done, clean up by deleting the cluster!
#
# helm del $(helm ls --all --short) --purge #!!! DELETES ALL YOUR HELM INSTANCES!
# gcloud container clusters delete pomerium
