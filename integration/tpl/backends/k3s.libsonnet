local entrypoint = [
  'sh',
  '-c',
  |||
    set -x
    # the dev image is only available locally, so load it first
    if [ "${POMERIUM_TAG:-master}" = "dev" ]; then
      sh -c '
        while true ; do
          ctr --connect-timeout=1s --timeout=60s images import /k3s-tmp/pomerium-dev.tar && break
          sleep 1
        done
      ' &
    fi
    k3s "$$@"
  |||,
  'k3s',
];

function(idp, manifests) {
  compose: {
    services: {
      'k3s-server': {
        image: 'rancher/k3s:${K3S_TAG:-latest}',
        entrypoint: entrypoint + [
          'server',
          '--disable',
          'traefik',
          '--disable',
          'metrics-server',
          '--kube-apiserver-arg',
          'service-node-port-range=1-65535',
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
          K3S_KUBECONFIG_OUTPUT: '/k3s-tmp/kubeconfig.yaml',
          K3S_KUBECONFIG_MODE: '666',
        },
        healthcheck: {
          test: ['CMD', 'kubectl', 'cluster-info'],
        },
        ports: [
          '6443:6443/tcp',
          '5443:5443/tcp',
          '443:443/tcp',
          '80:80/tcp',
        ],
        volumes: [
          'k3s-tmp:/k3s-tmp',
        ],
      },
      'k3s-agent': {
        image: 'rancher/k3s:${K3S_TAG:-latest}',
        entrypoint: entrypoint + ['agent'],
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
        volumes: [
          'k3s-tmp:/k3s-tmp',
        ],
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
            cat /k3s-tmp/kubeconfig.yaml | sed s/127.0.0.1/k3s-server/g >/tmp/kubeconfig.yaml
            export KUBECONFIG=/tmp/kubeconfig.yaml
          ||| + std.join('\n', std.map(
            function(manifest)
              |||
                cat <<-END_OF_MANIFEST | tee /tmp/manifest.json
                %s
                END_OF_MANIFEST
                kubectl apply -f /tmp/manifest.json
              ||| % std.manifestJsonEx(manifest, '  '),
            manifests
          )),
        ],
        volumes: [
          'k3s-tmp:/k3s-tmp',
        ],
      },
    },
    volumes: {
      'k3s-tmp': {
        driver_opts: {
          type: 'none',
          device: '/tmp',
          o: 'bind',
        },
      },
    },
  },
}
