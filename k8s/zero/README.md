# Installing Pomerium Zero

Visit https://console.pomerium.app and register for an account.

# Install base pomerium zero

```shell
kubectl apply -k https://github.com/pomerium/pomerium/k8s/zero?ref=main
```

(that would install an evergreen `main`)

# Create a secret with Pomerium Zero token to complete your installation

```yaml filename="pomerium-secret.yaml"
apiVersion: v1
kind: Secret
metadata:
  name: pomerium
  namespace: pomerium-zero
type: Opaque
stringData:
    pomerium_zero_token:
```

```shell
kubectl apply -f pomerium-secret.yaml
```

Now your Pomerium deployment should be up and running.

# Update Pomerium cluster configuration

1. The externally available address of your Pomerium Cluster should be set to the value assigned by your Load Balancer:

```shell
kubectl get svc/pomerium-proxy -n pomerium-zero -o=jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

2. Because container is configured to run as non-root, the following should be adjusted:

- http redirect address set to `:8080`
- server address set to `:8443`
