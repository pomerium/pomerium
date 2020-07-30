## Istio

[istio]: https://github.com/istio/istio
[certmanager]: https://github.com/jetstack/cert-manager
[grafana]: https://github.com/grafana/grafana

- Istio provides mutual TLS via sidecars and to make Istio play well with Pomerium we need to disable TLS on the Pomerium side.
- We need to provide Istio with information on how to route requests via Pomerium to their destinations.
- The following example shows how to make Grafana's [auth proxy](https://grafana.com/docs/grafana/latest/auth/auth-proxy) work with Pomerium inside of an Istio mesh.

#### Gateway

We are using the standard istio-ingressgateway that comes configured with Istio and attach a Gateway to it that deals with a subset of our ingress traffic based on the Host header (in this case `*.yourcompany.com`). This is the Gateway to which we will later attach VirtualServices for more granular routing decisions. Along with the Gateway, because we care about TLS, we are using Certmanager to provision a self-signed certificate (see Certmanager [docs](https://cert-manager.io/docs) for setup instructions).

<<< @/examples/kubernetes/istio/gateway.yml

#### Virtual Services

Here we are configuring two Virtual Services. One to route from the Gateway to the Authenticate service and one to route from the Gateway to the Pomerium Proxy, which will route the request to Grafana according to the configured Pomerium policy.

<<< @/examples/kubernetes/istio/virtual-services.yml

#### Service Entry

If you are enforcing mutual TLS in your service mesh you will need to add a ServiceEntry for your identity provider so that Istio knows not to expect a mutual TLS connection with, for example `https://yourcompany.okta.com`.

<<< @/examples/kubernetes/istio/service-entry.yml

#### Pomerium Configuration

For this example we're using the Pomerium Helm chart with the following `values.yaml` file. Things to note here are the `insecure` flag, where we are disabling TLS in Pomerium in favor of the Istio-provided TLS via sidecars. Also note the `extaEnv` arguments where we are asking Pomerium to extract the email property from the JWT and pass it on to Grafana in a header called `X-Pomerium-Claim-Email`. We need to do this because Grafana does not know how to read the Pomerium JWT but its auth-proxy authentication method can be configured to read user information from headers. The policy document contains a single route that will send all requests with a host header of `https://grafana.yourcompany.com` to the Grafana instance running in the monitoring namespace. We disable ingress because we are using the Istio ingressgateway for ingress traffic and don't need the Pomerium helm chart to create ingress objects for us.

<<< @/examples/kubernetes/istio/pomerium-helm-values.yml

#### Grafana ini

On the Grafana side we are using the Grafana Helm chart and what follows is the relevant section of the `values.yml` file. The most important thing here is that we need to tell Grafana from which request header to grab the username. In this case that's `X-Pomerium-Claim-Email` because we will be using the user's email (provided by your identity provider) as their username in Grafana. For all the configuration options check out the Grafana documentation about its auth-proxy authentication method.

<<< @/examples/kubernetes/istio/grafana.ini.yml