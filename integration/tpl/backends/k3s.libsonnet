function() {
  local pomeriumHelmConfig = {
    apiVersion: 'helm.cattle.io/v1',
    kind: 'HelmChart',
    metadata: {
      name: 'pomerium',
      namespace: 'kube-system',
    },
    spec: {
      chart: 'pomerium/pomerium',
      targetNamespace: 'default',
      repo: 'https://helm.pomerium.io',
    },
  },

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
      },
      volumes: [
        'k3s-manifests:/var/lib/rancher/k3s/server/manifests',
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
      image: 'busybox:latest',
      command: [
        'sh',
        '-c',
        'echo "$$POMERIUM_HELM" > /k3s-manifests/pomerium.yml',
      ],
      environment: {
        POMERIUM_HELM: std.manifestYamlDoc(pomeriumHelmConfig),
      },
      volumes: [
        'k3s-manifests:/k3s-manifests',
      ],
    },
  },
  volumes: {
    'k3s-manifests': {},
  },
}
