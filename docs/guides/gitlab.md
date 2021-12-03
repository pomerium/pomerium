---
title: GitLab
lang: en-US
meta:
  - name: keywords
    content: >-
      pomerium identity-access-proxy gitlab gitlab-ee docker
      authentication authorization
description: >-
  This guide covers how to secure self-hosted GitLab behind Pomerium, providing authentication and authorization through your IdP.
---

# GitLab

[GitLab] is a highly customizable, highly configurable tool to manage source code, project management, and many other aspects of project development. In addition to the SaaS product, its self-hosted solution and easy free-to-enterprise upgrade path make it a popular choice for those managing sensitive code bases.

This guide demonstrates how to configure a self-hosted GitLab server (a.k.a. gitlab-ee) behind the Pomerium Proxy.

## Before You Being

This guide is written for a docker-based containerized installation of both Pomerium and GitLab.

- This guide assumes a running instance of Pomerium, already configured with an identity Provider (**IdP**) and running as a docker container on the same host/swarm.

    ::: warning
    While Pomerium can be configured to use [GitLab as an IdP], we do not reccommend doing so while also running it behind Pomerium. In addition to the potential to lock out access to the IdP (breaking access to all routes), we consider it best practice to keep a separation of services between your identity provider protected services, especially those housing sensitive data like source code.
    :::

- This configuration includes secure communication between Pomerium and GitLab as an upstream service. GitLab's Omnibus configuration uses Nginx to serve the Ruby-based application, which is configured to serve it at the domain name users will access it from. This guide uses [mkcert] to generate a certificate for the upstream service, but this can be adjusted for your in-house certificate solution.

## Configure mkcert
!!!include(install-mkcert.md)!!!

Create a certificate for the domain that will be used for the GitLab route. For example:

```bash
mkcert "gitlab.pomerium.localhost.io"
```

::: tip Note:
This certificate will only be used by GitLab itself to secure communication from the Pomerium proxy service. The Pomerium configuration determines what certificate is served to the end user.
:::

## Install GitLab

::: warning Note
While we do our best to keep our documentation up to date, changes to third-party systems are outside our control. Refer to [GitLab Docker Images] from GitLab's docs as needed, or [let us know](https://github.com/pomerium/pomerium/issues/new?assignees=&labels=&template=bug_report.md) if we need to re-visit this section.
:::

### Prepare The Environment

1. Configure volumes for persistent data. GitLab suggests defining the environment variable `$GITLAB_HOME` to the root directory for its mounted volumes:

    ```bash
    export GITLAB_HOME=/srv/gitlab #Adjust the path based on your common Docker volume location.
    ```

1. In the `$GITLAB_HOME` directory, create three sub-directorys: `config`, `data`, and `logs`.

    ```bash
    mkdir $GITLAB_HOME/config
    mkdir $GITLAB_HOME/data
    mkdir $GITLAB_HOME/logs
    ```

1. In `$GITLAB_HOME/config` create the directory `ssl`. Move the internal certificate and key, created by mkcert in this example, to the new path:

    ```bash
    mkdir $GITLAB_HOME/config/ssl
    mv gitlab.localhost.pomerium.io.pem $GITLAB_HOME/config/ssl/
    mv gitlab.localhost.pomerium.io.key.pem $GITLAB_HOME/config/ssl/
    ```

### Install and Configure GitLab

1. Create the docker container. The example command below includes custom configuration options in the `GITLAB_OMNIBUS_CONFIG` variable:

    ```bash
    sudo docker run --detach \
    --hostname gitlab-ee \
    --name gitlab \
    --restart always \
    --volume $GITLAB_HOME/config:/etc/gitlab \
    --volume $GITLAB_HOME/logs:/var/log/gitlab \
    --volume $GITLAB_HOME/data:/var/opt/gitlab \
    gitlab/gitlab-ee:latest
    #--publish 8443:443 --publish 8080:80 --publish 2022:22 \
    ```

    The container may take several minutes to initialize. You can monitor the progress by following the log output of the container:

    ```bash
    docker logs -f gitlab
    ```

1. Once the container is initialized, navigate to `$GITLAB_HOME\config` and edit `gitlab.rb` to use the correct external URL and certificate files:

    ```rb
    ...
    external_url "https://gitlab.localhost.pomerium.io"
    ...
    nginx['ssl_certificate'] = "/etc/gitlab/ssl/gitlab.localhost.pomerium.io.pem"
    nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.localhost.pomerium.io-key.pem"
    ```

1. Reconfigure GitLab to use the new configuration:

    ```bash
    docker exec -u 0 -it gitlab gitlab-ctl reconfigure
    ```

## Configure a Pomerium Route

Edit `config.yaml` and add a route for GitLab. Note that this example assumes access to the mkcert CA certificate at `/mkcert/rootCA.pem`:

```yaml
  - from: https://gitlab.localhost.pomerium.io
    to: https://gitlab-ee
    pass_identity_headers: true
    tls_custom_ca_file: /mkcert/rootCA.pem
    tls_server_name: gitlab.localhost.pomerium.io
    preserve_host_header: true
    policy:
      - allow:
          or:
            - domain:
                is: example.com
```

Once the route is applied, you should be able to access GitLab from `https://gitlab.localhost.pomerium.io`:

Use `grep` within the container to find the default root password:

```bash
sudo docker exec -it gitlab grep 'Password:' /etc/gitlab/initial_root_password
```

### Configure TCP Connections

1. An additional route will provide an encrypted TCP tunnel through which users can securly access code using Git:

  ```yaml
    - from: tcp+https://gitlab.localhost.pomerium.io
      to: tcp://gitlab-ee:22
      pass_identity_headers: true
      tls_custom_ca_file: /mkcert/rootCA.pem
      tls_server_name: gitlab.localhost.pomerium.io
      preserve_host_header: true
      policy:
        - allow:
            or:
              - groups:
                  has: devs@example.com
  ```

1. Once this route is applied, users can create an encrypted connection using [pomerium-cli] or the [Pomerium Desktop] app:

    ::::: tabs
    :::: tab Pomerium-CLI
    ```bash
    pomerium-cli tcp ...
    ```
    ::::
    :::: tab Pomerium Desktop
    An Image
    ::::
    :::::

[GitLab]: https://gitlab.com/
[GitLab as an IdP]: /docs/identity-providers/gitlab
[GitLab Docker Images]: https://docs.gitlab.com/ee/install/docker.html
[mkcert]: https://github.com/FiloSottile/mkcert
[pomerium-cli]: /docs/releases.md#pomerium-cli
[Pomerium Desktop]: https://github.com/pomerium/desktop-client/releases