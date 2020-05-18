#!/bin/bash
# PRE-REQ:
# 1) Install Helm : You should verify the content of this script before running.
# curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get | bash
# 2) Install https://eksctl.io/
# For more information see: 
#  - https://eksworkshop.com/helm_root/helm_intro/install/

echo "=> [AWS] creating cluster"
eksctl create cluster --name=pomerium --nodes=1 --region=us-west-2

echo "=> [AWS] get cluster credentials so we can use kubctl locally"
eksctl utils write-kubeconfig --name=pomerium

echo "=> [AWS] configure Helm access with RBAC"
cat <<EOF >.helm-rbac.yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: tiller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: tiller
    namespace: kube-system
EOF

kubectl apply -f .helm-rbac.yaml
# cleanup
rm .helm-rbac.yaml

echo "=> initialize Helm to install Tiller in your cluster"
helm init --service-account=tiller
helm repo update

echo "=> install pomerium with helm substituting configuration values as required; be sure to change these"
helm install $HOME/charts/stable/pomerium/ \
	--name pomerium \
	--set config.sharedSecret=$(head -c32 /dev/urandom | base64) \
	--set config.cookieSecret=$(head -c32 /dev/urandom | base64) \
	--set config.cert=$(base64 -i cert.pem) \
	--set config.key=$(base64 -i privkey.pem) \
	--set config.policy="$(cat policy.example.yaml | base64)" \
	--set authenticate.idp.provider="google" \
	--set authenticate.proxyRootDomains="pomerium.io" \
	--set authenticate.redirectUrl="https://auth.corp.pomerium.io/oauth2/callback" \
	--set authenticate.idp.clientID="REPLACE_ME" \
	--set authenticate.idp.clientSecret="REPLACE_ME" \
	--set proxy.authenticateServiceUrl="https://auth.corp.pomerium.io" \
	--set proxy.authorizeServiceUrl="https://access.corp.pomerium.io"

# When done, clean up by deleting the cluster!
#
# helm del $(helm ls --all --short) --purge #!!! DELETES ALL YOUR HELM INSTANCES!