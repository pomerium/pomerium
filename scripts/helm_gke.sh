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

echo "=> wait 2 minutes for tiller to get setup"
sleep 120

echo "=> install pomerium with helm substituting configuration values as required; be sure to change these"
helm install $HOME/helm-charts/stable/pomerium/ \
	--set service.type="NodePort" \
	--set config.rootDomain="corp.pomerium.io" \
	--set ingress.secret.name="pomerium-tls" \
	--set ingress.secret.cert=$(base64 -i "$HOME/.acme.sh/*.corp.pomerium.io_ecc/*.corp.pomerium.io.cer") \
	--set ingress.secret.key=$(base64 -i "$HOME/.acme.sh/*.corp.pomerium.io_ecc/*.corp.pomerium.io.key") \
	--set config.policy="$(cat policy.example.yaml | base64)" \
	--set authenticate.idp.provider="google" \
	--set authenticate.redirectUrl="https://authenticate.corp.pomerium.io/oauth2/callback" \
	--set authenticate.idp.clientID="851877082059-bfgkpj09noog7as3gpc3t7r6n9sjbgs6.apps.googleusercontent.com" \
	--set authenticate.idp.clientSecret="Vf5w-TUUR-yPIY9RVTo_TnGQ"

# When done, clean up by deleting the cluster!
#
# helm del $(helm ls --all --short) --purge #!!! DELETES ALL YOUR HELM INSTANCES!
# gcloud container clusters delete pomerium
