# Pomerium as forward-auth provider for Traefik on Kubernetes

Run this demo locally on your kubernetes capable workstation or:
    - use `kubectl port-forward service/traefik 80:80 443:443` 
    - replace `localhost.pomerium.io` with your own domain

## Includes

- Authentication and Authorization managed by pomerium
- Routing / reverse proxying handled by traefik
- Installation using upstream `helm` charts

## How

- Update `values/pomerium.yaml` for your e-mail address, if not using gmail/google.
- Replace IdP secrets in `values/pomerium.yaml`.
- Run `./add_repos.sh` from this directory.
- Run `./install.sh` from this directory.
- Navigate to `https://hello.localhost.pomerium.io`
