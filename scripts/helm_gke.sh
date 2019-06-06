#!/bin/bash
# PRE-REQ: Install Helm : You should verify the content of this script before running.
# curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get | bash
# NOTE! This will create real resources on Google's cloud. Make sure you clean up any unused
# resources to avoid being billed. For reference, this tutorial cost me <10 cents for a couple of hours.
# NOTE! You must change the identity provider client secret setting, and service account setting!
# NOTE! If you are using gsuite, you should also set `authenticate.idp.serviceAccount`, see docs !

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

echo "=> wait a minute for tiller to get setup"
sleep 60

echo "=> install pomerium with helm"
echo " replace configuration settings to meet your specific needs and identity provider settings"

echo "=> initiliaze a configmap setting from config.example.yaml"
kubectl create configmap config --from-file="config.yaml"="docs/docs/examples/config/config.example.yaml"
# git clone https://github.com/pomerium/pomerium-helm.git $HOME/pomerium-helm

helm install $HOME/pomerium-helm \
	--set service.type="NodePort" \
	--set config.rootDomain="corp.beyondperimeter.com" \
	--set config.existingConfig="config" \
	--set config.sharedSecret=$(head -c32 /dev/urandom | base64) \
	--set config.cookieSecret=$(head -c32 /dev/urandom | base64) \
	--set ingress.secret.name="pomerium-tls" \
	--set ingress.secret.cert=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/fullchain.cer") \
	--set ingress.secret.key=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/*.corp.beyondperimeter.com.key") \
	--set authenticate.idp.provider="google" \
	--set authenticate.idp.clientID="REPLACE_ME" \
	--set authenticate.idp.clientSecret="REPLACE_ME" \
	--set-string ingress.annotations."kubernetes\.io/ingress\.allow-http"=false \
	--set service.annotations."cloud\.google\.com/app-protocols"='\{"https":"HTTPS"\}'

# When done, clean up by deleting the cluster!
# helm del $(helm ls --all --short) --purge # deletes all your helm instances
# gcloud container clusters delete pomerium # deletes your cluster
