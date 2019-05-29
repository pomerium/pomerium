#!/bin/bash
# NOTE! This will create real resources on Google's cloud. Make sure you clean up any unused
# resources to avoid being billed. For reference, this tutorial cost me <10 cents for a couple of hours.
# NOTE! You must change the identity provider client secret setting, and service account setting!

echo "=> creating cluster"
gcloud container clusters create pomerium --num-nodes 1

echo "=> get cluster credentials os we can use kubctl locally"
gcloud container clusters get-credentials pomerium

echo "=> create pomerium namespace"
kubectl create ns pomerium

echo "=> create our cryptographically random keys forshared-secret andcookie-secret from urandom"
kubectl create secret generic -n pomerium shared-secret --from-literal=shared-secret=$(head -c32 /dev/urandom | base64)
kubectl create secret generic -n pomerium cookie-secret --from-literal=cookie-secret=$(head -c32 /dev/urandom | base64)

echo "=> initiliaze secrets for TLS wild card certificatescertificate andcertificate-key"
kubectl create secret generic -n pomerium certificate \
	--from-literal=certificate=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/fullchain.cer")
kubectl create secret generic -n pomerium certificate-key \
	--from-literal=certificate-key=$(base64 -i "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/*.corp.beyondperimeter.com.key")

echo "=> load TLS to ingress"
kubectl create secret tls -n pomerium pomerium-tls \
	--key "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/*.corp.beyondperimeter.com.key" \
	--cert "$HOME/.acme.sh/*.corp.beyondperimeter.com_ecc/fullchain.cer"

echo "=> initiliaze a configmap setting for POLICY from policy.example.yaml"
kubectl create configmap -n pomerium policy --from-literal=policy=$(cat docs/docs/examples/config/policy.example.yaml | base64)

echo "=> settingidp-client-secret, you changed this right? :)"
exit 1 # comment out or delete this line once you change the following two settings
kubectl create secret generic -n pomerium idp-client-secret --from-literal=idp-client-secret=REPLACE_ME
kubectl create secret generic -n pomerium idp-service-account --from-literal=idp-service-account=$(base64 -i gsuite.service.account.json)

echo "=> apply the proxy, authorize, and authenticate deployment configs"
kubectl apply -f docs/docs/examples/kubernetes/authorize.deploy.yml
kubectl apply -f docs/docs/examples/kubernetes/authenticate.deploy.yml
kubectl apply -f docs/docs/examples/kubernetes/proxy.deploy.yml

echo "=> apply the proxy, authorize, and authenticate service configs"
kubectl apply -f docs/docs/examples/kubernetes/proxy.service.yml
kubectl apply -f docs/docs/examples/kubernetes/authenticate.service.yml
kubectl apply -f docs/docs/examples/kubernetes/authorize.service.yml

echo "=> create and apply the Ingress; this is GKE specific"
kubectl apply -f docs/docs/examples/kubernetes/ingress.yml

# Alternatively, nginx-ingress can be used
# kubectl apply -f docs/docs/examples/kubernetes/ingress.nginx.yml

# When done, clean up by deleting the cluster!
# gcloud container clusters delete pomerium
