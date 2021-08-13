function(idp, manifests) {
  local pomeriumHelmConfig = {
    apiVersion: 'helm.cattle.io/v1',
    kind: 'HelmChart',
    metadata: {
      name: 'pomerium',
      namespace: 'kube-system',
    },
    spec: {
      chart: 'pomerium',
      targetNamespace: 'default',
      repo: 'https://helm.pomerium.io',
      set: {
        'config.rootDomain': 'localhost.pomerium.io',
        'authenticate.idp.provider': idp,
        'authenticate.idp.url': 'https://mock-idp.localhost.pomerium.io/',
        'authenticate.idp.clientID': 'CLIENT_ID',
        'authenticate.idp.clientSecret': 'CLIENT_SECRET',
        'image.tag': '${POMERIUM_TAG:-master}',
      },
    },
  },

  compose: {
    services: {
      'k3s-server': {
        image: 'rancher/k3s:${K3S_TAG:-latest}',
        command: [
          'server',
          '--disable',
          'traefik',
          '--disable',
          'metrics-server',
        ],
        tmpfs: ['/run', '/var/run'],
        ulimits: {
          nproc: 65535,
          nofile: {
            soft: 65535,
            hard: 65535,
          },
        },
        privileged: true,
        restart: 'always',
        environment: {
          K3S_TOKEN: 'TOKEN',
          K3S_KUBECONFIG_OUTPUT: '/k3s-config/kubeconfig.yaml',
          K3S_KUBECONFIG_MODE: '666',
        },
        healthcheck: {
          test: ['CMD', 'kubectl', 'cluster-info'],
        },
        ports: [
          '6443:6443/tcp',
        ],
        volumes: [
          'k3s-config:/k3s-config',
        ],
      },
      'k3s-agent': {
        image: 'rancher/k3s:${K3S_TAG:-latest}',
        tmpfs: ['/run', '/var/run'],
        ulimits: {
          nproc: 65535,
          nofile: {
            soft: 65535,
            hard: 65535,
          },
        },
        privileged: true,
        restart: 'always',
        environment: {
          K3S_URL: 'https://k3s-server:6443',
          K3S_TOKEN: 'TOKEN',
        },
      },
      'k3s-init': {
        image: 'rancher/k3s:${K3S_TAG:-latest}',
        depends_on: {
          'k3s-server': {
            condition: 'service_healthy',
          },
        },
        entrypoint: [
          'sh',
          '-c',
          |||
            cat /k3s-config/kubeconfig.yaml | sed s/127.0.0.1/k3s-server/g >/tmp/kubeconfig.yaml
            export KUBECONFIG=/tmp/kubeconfig.yaml
          ||| + std.join('\n', std.map(
            function(manifest)
              |||
                cat <<-EOF | tee /tmp/manifest.json
                %s
                EOF
                kubectl apply -f /tmp/manifest.json
              ||| % std.manifestJsonEx(manifest, '  '),
            manifests
          )),
        ],
        volumes: [
          'k3s-config:/k3s-config',
        ],
      },
    },
    volumes: {
      'k3s-config': {
        driver_opts: {
          type: 'none',
          device: '/tmp',
          o: 'bind',
        },
      },
    },
  },
}
