---
title: Kubernetes Dashboard
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy kubernetes helm k8s oauth dashboard
description: >-
  This guide covers how to add authentication and authorization to kubernetes dashboard using single-sing-on, pomerium, helm, and letsencrypt certificates.
---

# Securing Kubernetes Dashboard

The following guide covers how to secure [Kubernetes Dashboard] using Pomerium. Kubernetes Dashboard is a powerful, web-based UI for managing Kubernetes clusters. Pomerium can act as a **forward-auth provider** _and_ as an independent **identity-aware access proxy** improving and adding single-sign-on to Kubernetes Dashboard's default access control. This guide aims to demonstrate a concrete example of those two methods of access control.

![fresh kubernetes dashboard install](./img/k8s-fresh-dashboard.png)

This tutorial covers:

- Installing [Helm] a package manger for Kubernetes
- Deploying [NGINX Ingress Controller]
- Install and configure [Cert-Manager] to issue [LetsEncrypt] certificates
- Deploying Pomerium
- Deploying [Kubernetes Dashboard]
- Secure Kubernetes Dashboard access:
  - _directly_, using Pomerium's proxy component
  - _indirectly_, using Pomerium as a [forward-auth] provider

## Background

Though securing [kubernetes dashboard] as an example may seem contrived, the damages caused by an unsecured dashboard is a real threat vector. In late 2018, Telsa [determined](https://redlock.io/blog/cryptojacking-tesla) that the hackers who were running [crypto-mining malware](https://arstechnica.com/information-technology/2018/02/tesla-cloud-resources-are-hacked-to-run-cryptocurrency-mining-malware/) on their cloud accounts came in through an unsecured [Kubernetes Dashboard] instance.

![tesla hacked from kubernetes dashboard](./img/k8s-tesla-hacked.png)

## Helm

First, we will install [Helm]. Helm is a package manager similar to `apt-get` or `brew` but for Kubernetes and it's what we'll use to install Pomerium, nginx-ingress, cert-manager, and the dashboard.

### Install

There are two parts to Helm: the client, and the server. This guide will cover the most common installation path. Please refer to the [Helm install] instructions for more details, and other options.

#### Client

We'll install by installing the helm client on our client on our local machine.

OSX via [homebrew].

```bash
brew install kubernetes-helm
```

Linux via [snap].

```bash
sudo snap install helm --classic
```

A script for the [trusting](https://sysdig.com/blog/friends-dont-let-friends-curl-bash/) 😉.

```bash
curl -L https://git.io/get_helm.sh | bash
```

#### Server

Next, we'll deploy Helm's server component, [Tiller] to your currently selected `kubtctl` instance.

```bash
helm init
```

```bash
Creating $HOME/.helm
...
...
$HELM_HOME has been configured at $HOME/.helm.

Tiller (the Helm server-side component) has been installed into your Kubernetes Cluster.
```

Now that you have both the helm client installed on your machine, and Tiller installed on your Kubernetes cluster, you can use [Helm] to deploy the subsequent packages.

## NGINX Ingress

[NGINX ingress controller] is a [Kubernetes Ingress] based on [NGINX] the is a very popular, full-feature reverse-proxy. We will use NGINX in two configurations: as a fronting proxy, and as proxy that delegates every request's access-control decision to Pomerium using forward-auth.

Also, please note that while this guide uses [NGINX Ingress Controller], Pomerium can act as a forward auth-provider alongside other fronting ingresses like [Traefik](https://docs.traefik.io/middlewares/forwardauth/), [Ambassador](https://www.getambassador.io/reference/services/auth-service/), and [envoy](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html) in a similar fashion.

### Install

NGINX Ingress controller can be installed via [Helm] from the official charts repository. To install the chart with the release name `helm-nginx-ingress`:

```bash
helm install stable/nginx-ingress --name helm-nginx-ingress
```

```bash
NAME:   helm-nginx-ingress
....
NAMESPACE: default
STATUS: DEPLOYED
```

Confirm the ingress has been installed, and that an external `LoadBalancer` IP has been set.

```sh
$kubectl get svc
```

```
NAME                                 TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
helm-nginx-ingress-controller        LoadBalancer   10.99.182.128   localhost     80:31059/TCP,443:32402/TCP   15m
helm-nginx-ingress-default-backend   ClusterIP      10.108.251.51   <none>        80/TCP                       15m
kubernetes                           ClusterIP      10.96.0.1       <none>        443/TCP                      93m
```

We now have a kubernetes ingress resource that can be used to delegate access control decisions to or front-proxy for Pomerium.

## Certificates

[Cert-manager] is a Kubernetes plugin that helps automate issuance of TLS certificates. In our case, we will use cert-manager to retrieve certs to each of our configured routes.

### Install

Like in previous steps, we will use [Helm] to install [Cert-manager].

```sh
# Install the CustomResourceDefinition resources separately
$kubectl apply --validate=false -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.11/deploy/manifests/00-crds.yaml
# Create the namespace for cert-manager
$kubectl create namespace cert-manager
# Add the Jetstack Helm repository
helm repo add jetstack https://charts.jetstack.io
# Update your local Helm chart repository cache
helm repo update
# Install the cert-manager Helm chart
helm install \
  --name cert-manager \
  --namespace cert-manager \
  --version v0.11.0 \
  jetstack/cert-manager
```

And we'll confirm cert-manager is up and running.

```
$kubectl get pods --namespace cert-manager
```

```
NAME                                       READY   STATUS    RESTARTS   AGE
cert-manager-756d9f56d6-brv6z              1/1     Running   0          23s
cert-manager-cainjector-74bb68d67c-7jdw6   1/1     Running   0          23s
cert-manager-webhook-645b8bdb7-8kgc9       1/1     Running   0          23s
```

### Configure

Now that cert-manager is installed, we need to make one more configuration to be able to retrieve certificates. We need to add a [http-01 issuer](https://letsencrypt.org/docs/challenge-types/) for use with [LetsEncrypt].

```sh
$kubectl apply -f docs/recipes/yml/letsencrypt-prod.yaml
```

<<< @/docs/recipes/yml/letsencrypt-prod.yaml

And confirm your issuer is set up correctly.

```bash
$kubectl describe issuer
```

```bash
Name:         letsencrypt-prod
...
API Version:  cert-manager.io/v1alpha2
Kind:         Issuer
Metadata:
Spec:
  Acme:
    Private Key Secret Ref:
      Name:  letsencrypt-prod
    Server:  https://acme-v02.api.letsencrypt.org/directory
    Solvers:
      Http 01:
        Ingress:
          Class:  nginx
      Selector:
Status:
  Acme:
    Last Registered Email:  ....
    Uri:                    https://acme-v02.api.letsencrypt.org/acme/acct/69070883
  Conditions:
    Message:               The ACME account was registered with the ACME server
    Reason:                ACMEAccountRegistered
    Status:                True
    Type:                  Ready
```

If you see something like the above, cert-manager should be all set to help issue you new certificates when you create a new `https` protected ingress. Note, if you need wild-card certificates, you may also need a [DNS-01](https://docs.cert-manager.io/en/latest/tasks/issuers/setup-acme/dns01/) type issuer.

## Dashboard

[Kubernetes Dashboard] is a general purpose, web-based UI for Kubernetes clusters. It allows users to manage applications running in the cluster and troubleshoot them, as well as manage the cluster itself.

![kubernetes dashboard login page](./img/k8s-dashboard-login.png)

### Install

As with the previous steps, we can use [Helm] to install our instance of [Kubernetes Dashboard].

```sh
helm install stable/kubernetes-dashboard \
  --name helm-dashboard \
  --set ingress.enabled="false" \
  --set enableSkipLogin="true"
```

That's it. We've now configured kubernetes dashboard to use the default service account, if none-is provided. We've also explicitly told helm that we are going to deploy our own custom, nginx / Pomerium / cert-manager enabled ingress.

## Pomerium

Pomerium is an identity-aware access proxy that can used to serve as an identity-aware reverse proxy, or as a forward-auth provider.

### Configure

Before installing, we will configure Pomerium's configuration settings in `config.yaml`. Other than the typical configuration settings covered in the quick-start guides, we will add a few settings that will make working with Kubernetes Dashboard easier.

We can retrieve the token to add to our proxied policy's authorization header as follows.

```sh
$kubectl describe secret dashboard-kubernetes-dashboard-token
```

```Name:         dashboard-kubernetes-dashboard-token-bv9jq
Namespace:    default
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: dashboard-kubernetes-dashboard
              kubernetes.io/service-account.uid: 18ab35ee-eca1-11e9-8c75-025000000001

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1025 bytes
namespace:  7 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.......

```

The above token then needs to be assigned to our route configuration and policy.

```yaml
# config.yaml
forward_auth_url: https://fwdauth.domain.example

policy:
  # this route is directly proxied by pomerium & injects the authorization header
  - from: https://dashboard-proxied.domain.example
    to: https://helm-dashboard-kubernetes-dashboard
    allowed_users:
      - user@domain.example
    tls_skip_verify: true # dashboard uses self-signed certificates in its default configuration
    set_request_headers:
      Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.....

  # this route is indirectly checked for access using forward-auth
  - from: https://dashboard-fwdauth.domain.example
    to: https://helm-dashboard-kubernetes-dashboard
    allowed_users:
      - user@domain.example
```

We then add our configuration to Kubernetes as a [ConfigMap](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/).

```bash
# add our pomerium policy to kubernetes as a configmap
$kubectl create configmap config --from-file="config.yaml"="config.yaml"
```

### Install

Finally, we get to install Pomerium! 🎉 Once again, we will use Helm to deploy Pomerium.

```bash
helm install stable/pomerium \
  --name "helm-pomerium" \
	--set config.rootDomain="domain.example" \
  --set config.existingConfig="config" \
  --set authenticate.idp.provider="google" \
	--set authenticate.idp.clientID="YOUR_CLIENT_ID" \
	--set authenticate.idp.clientSecret="YOUR_SECRET"
```

## Putting it all together

Now we just need to tell external traffic how to route everything by deploying the following ingresses.

```sh
$kubectl apply -f docs/recipes/yml/pomerium.ingress.yaml
```

<<< @/docs/recipes/yml/pomerium.ingress.yaml

```sh
$kubectl apply -f docs/recipes/yml/dashboard-fwdauth.ingress.yaml
```

<<< @/docs/recipes/yml/dashboard-fwdauth.ingress.yaml

```sh
$kubectl apply -f docs/recipes/yml/dashboard-proxied.ingress.yaml
```

<<< @/docs/recipes/yml/dashboard-proxied.ingress.yaml

And finally, check that the ingresses are up and running.

```sh
 $kubectl get ingress
```

```sh
NAME                    HOSTS                                                ADDRESS   PORTS     AGE
dashboard-fwdauth       dashboard-fwdauth.domain.example                               80, 443   42h
dashboard-proxied       dashboard-proxied.domain.example                               80, 443   42h
helm-pomerium           *.domain.example,authenticate.domain.example                   80, 443   42h
```

You'll notice this is the step where we put everything together. We've got [nginx] handling the initial requests, [cert-manager] handling our public certificates, and Pomerium handling access control.

## Conclusion

Though the net result will be similar between using forward-auth and direct proxying, there are a few differences:

- By having Pomerium **directly proxy the requests**, you as an administrator have control control over the underlying request. In this example, we are able to inject an authenticating bearer token header to the downstream request which arguably makes for a better user experience.

  <video controls  muted="" playsinline="" width="100%" height="600" control=""><source src="./img/k8s-proxied-example.mp4" type="video/mp4">
  Your browser does not support the video tag.
  </video>

* Conversely, going the **forward-auth** route potentially means using the ingress / reverse proxy you are are already accustomed to or have already modified to support your particular deployment.

  <video controls  muted="" playsinline="" width="100%" height="600" control=""><source src="./img/k8s-fwd-auth-example.mp4" type="video/mp4">
  Your browser does not support the video tag.
  </video>

In the end, you should choose whichever option makes the most sense for your use-case and environment.

Whichever option you choose to go with, 🎉🍾🎊 **congratulations** 🎉🍾🎊! You now have a single-sign-on enabled [Kubernetes Dashboard] protected by Pomerium and automatically renewing [LetsEncrypt] certificates.

[bearer token]: https://kubernetes.io/docs/admin/authentication/
[cert-manager]: https://github.com/jetstack/cert-manager
[command line proxy]: https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#command-line-proxy
[creating sample users]: https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md
[dashboard ui]: https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#deploying-the-dashboard-ui
[dns01 challenge provider]: https://docs.cert-manager.io/en/latest/tasks/issuers/setup-acme/dns01/index.html
[forward-auth]: ../docs/reference/reference.html#forward-auth
[helm install]: https://helm.sh/docs/using_helm/#installing-the-helm-client
[helm]: https://helm.sh
[homebrew]: https://brew.sh
[kubernetes dashboard]: https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/
[kubernetes ingress]: https://kubernetes.io/docs/concepts/services-networking/ingress/
[kubernetes securing a cluster]: https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/
[letsencrypt]: https://letsencrypt.org
[nginx ingress controller]: https://github.com/kubernetes/ingress-nginx
[nginx]: https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/
[securing your helm installation]: https://helm.sh/docs/using_helm/#securing-your-helm-installation
[snap]: https://github.com/snapcrafters/helm
[tiller]: https://helm.sh/docs/install/#installing-tiller
[with pomerium]: ../docs/reference/reference.html#forward-auth
[your dashboard]: http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#/login
