#!/bin/bash
# PRE-REQ: Install Helm : You should verify the content of this script before running.
# curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get | bash
# NOTE! This will create real resources on Google's cloud. Make sure you clean up any unused
# resources to avoid being billed. For reference, this tutorial cost me <10 cents for a couple of hours.
# NOTE! You must change the identity provider client secret setting, and service account setting!
# NOTE! If you are using gsuite, you should also set `authenticate.idp.serviceAccount`, see docs !

echo "=> [GCE] creating cluster"
gcloud container clusters create pomerium --region us-west2 --num-nodes 1

echo "=> [GCE] get cluster credentials so we can use kubctl locally"
gcloud container clusters get-credentials pomerium --region us-west2

echo "=> add pomerium's helm repo"
helm repo add pomerium https://helm.pomerium.io

echo "=> add bitnami's helm repo"
helm repo add bitnami https://charts.bitnami.com/bitnami

echo "=> install nginx as a sample hello world app"
helm upgrade --install nginx bitnami/nginx --set service.type=ClusterIP

echo "=> update helm"
helm repo update

echo "=> install pomerium with helm"
helm install \
	pomerium \
	pomerium/pomerium \
	--set service.type="NodePort" \
	--set config.sharedSecret=$(head -c32 /dev/urandom | base64) \
	--set config.cookieSecret=$(head -c32 /dev/urandom | base64) \
	--set ingress.secret.name="pomerium-tls" \
	--set ingress.secret.cert=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/fullchain.cer") \
	--set ingress.secret.key=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/*.corp.beyondperimeter.com.key") \
	--values docs/configuration/examples/kubernetes/values.yaml

# When done, clean up by deleting the cluster!
# helm del $(helm ls --all --short) --purge # deletes all your helm instances
# gcloud container clusters delete pomerium # deletes your cluster
