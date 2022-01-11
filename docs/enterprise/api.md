---
title: API
lang: en-US
meta:
  - name: keywords
    content: pomerium, identity access proxy, oidc, reverse proxy, enterprise, console, api, python, go
---

# Enterprise Console API

The Pomerium Enterprise Console supports programmatic interaction through an API. This page covers enabling and authenticating to the API.

## Before You Begin

This doc assumes:
 - You already have installed Pomerium and Pomerium Enterprise,
 - The enterprise console service is encrypted. Review the [tls-*] keys for more information.

## Configure a New Route

1. We suggest configuring the route for API access in the open-source Pomerium. That way changes made through the API that might break access to the console GUI will not break access to the API route.

    ```yaml
    - from: https://console-api.pomerium.localhost.io
      to: https://pomerium-console-domain-name:8702
      pass_identity_headers: true
      allow_any_authenticated_user: true
      tls_custom_ca_file: /path/to/rootCA.pem # See https://www.pomerium.com/reference/#tls-custom-certificate-authority
    ```

1. You must also update the `audience` key to include the new route's `from` value:

	```yaml
	audience: "console.pomerium.localhost.io,console-api.pomerium.localhost.io"
	```

	If you're running Pomerium Enterprise as a system service, restart the daemon.


## Create a Service Account

1. In the enterprise Console under **Configure -> Service Accounts**, Click **+ Add Service Account**. You can choose an existing user for the service account to impersonate, or create a new user. Note that a new user will not be synced to your IdP.

1. The Enterprise Console will display the service account token. Be sure to store it securely now, as you cannot view it again after this point.

1. Grant the service account the appropriate [role](/enterprise/concepts.md#rbac-for-enterprise-console-users) on the Namespace(s) it will operate against.

::: tip
Service accounts created in any Namespace other than **Global** will include a reference to that Namespace ID. You must specify the entire user ID (i.e. `design-api@bff1bea6-a3d6-232d-812c-b4fd8e26d72e.pomerium`) when using the service account.
:::

## Install The Library

:::: tabs
::: tab Python
```bash
pip3 install git+ssh://git@github.com/pomerium/enterprise-client-python.git
```
:::
::: tab Go
```bash
go get github.com/pomerium/enterprise-client-go
```
:::
::::

## Test the API Connection

The repositories for our [Python][client-py] and [Go][client-go] implementations include example scripts:

:::: tabs
::: tab Python
```python
#!/usr/bin/env python

import os
from pomerium.client import Client
from pomerium.pb.policy_pb2 import ListPoliciesRequest
from pomerium.pb.namespaces_pb2 import ListNamespacesRequest
from pomerium.pb.routes_pb2 import SetRouteRequest, Route

# get custom CA and service account credentials from environment
ca_cert = os.getenv('CA_CERT', '').encode('utf-8')
sa = os.getenv('SERVICE_ACCOUNT', '')
console_api = 'console-api.localhost.pomerium.io'

client = Client(console_api, sa, root_certificates=ca_cert)

# get id for namespace 'Production'
resp = client.NamespaceService.ListNamespaces(ListNamespacesRequest())
ns = [n for n in resp.namespaces if n.name == 'Production'][0]

# find policy named 'my policy' in namespace 'Production'
resp = client.PolicyService.ListPolicies(
    ListPoliciesRequest(query='my policy', namespace=ns.id)
)
policy = resp.policies[0]

# set route in namespace 'Production', associated to 'my policy'
route = Route(**{
    'namespace_id': ns.id,
    'name': 'my route',
    'from': 'https://test.localhost.pomerium.io',
    'to': ['https://verify.pomerium.com'],
    'policy_ids': [policy.id],
    'pass_identity_headers': True,
})

resp = client.RouteService.SetRoute(SetRouteRequest(route=route))
print(resp)
```
:::
::: tab Go
```go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"

	pb "github.com/pomerium/enterprise-client-go/pb"

	client "github.com/pomerium/enterprise-client-go"
)

var serviceAccountToken = os.Getenv("SERVICE_ACCOUNT")
var target = "console-api.localhost.pomerium.io:443"

func main() {
	err := run()
	if err != nil {
		fmt.Printf("%s\n", err)
	}
}

func run() error {

	ctx := context.Background()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	p, err := client.NewClient(ctx, target, serviceAccountToken, client.WithTlsConfig(tlsConfig))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	nsResp, err := p.NamespaceService.ListNamespaces(ctx, &pb.ListNamespacesRequest{})
	if err != nil {
		return fmt.Errorf("could not list namespaces: %w", err)
	}

	var productionNamespaceId string
	for _, n := range nsResp.GetNamespaces() {
		if n.GetName() == "Production" {
			productionNamespaceId = n.GetId()
		}
	}

	if productionNamespaceId == "" {
		return fmt.Errorf("could not find production namespace")
	}

	policyName := "my policy"
	var policyId string
	polResp, err := p.PolicyService.ListPolicies(ctx, &pb.ListPoliciesRequest{Namespace: productionNamespaceId, Query: &policyName})
	if err != nil {
		return fmt.Errorf("failed to find policy: %w", err)
	}
	if len(polResp.GetPolicies()) == 0 {
		return fmt.Errorf("no policy named '%s' found", policyName)
	}

	policyId = polResp.GetPolicies()[0].GetId()

	passIdHeaders := true
	newRoute := &pb.Route{
		NamespaceId:         productionNamespaceId,
		Name:                "my route",
		From:                "https://test.localhost.pomerium.io",
		To:                  []string{"https://verify.pomerium.com"},
		PolicyIds:           []string{policyId},
		PassIdentityHeaders: &passIdHeaders,
	}

	routeResp, err := p.RouteService.SetRoute(ctx, &pb.SetRouteRequest{Route: newRoute})
	if err != nil {
		return fmt.Errorf("could not create route: %w", err)
	}

	fmt.Printf("created route id: %s\n", routeResp.Route.GetId())
	return nil
}
```
:::
::::

Modify the example script to match your console API path, Namespace(s) and Policy names.

[tls-*]: /enterprise/reference/config.md#tls-ca
[client-py]: https://github.com/pomerium/enterprise-client-python
[client-go]: https://github.com/pomerium/enterprise-client-go

## More Information

To see all endpoints available for both the Python and Go libraries, see the [gRPC API Reference](https://github.com/pomerium/enterprise-client/blob/update_docs_template/API.md).