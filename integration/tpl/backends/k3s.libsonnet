local utils = import '../utils.libsonnet';

local Command() =
  [
    'sh',
    '-c',
    |||
      set -x
      # the dev image is only available locally, so load it first
      if [ "${POMERIUM_TAG:-main}" = "dev" ]; then
        sh -c '
          while true ; do
            ctr --connect-timeout=1s --timeout=60s images import /k3s-tmp/pomerium-dev.tar && break
            sleep 1
          done
        ' &
      fi
      exec k3s "$$@"
    |||,
    'k3s',
  ];

local InstallManifest(manifest) =
  std.join('\n', [
    'cat <<-END_OF_MANIFEST | tee /tmp/manifest.json',
    std.manifestJsonEx(manifest, '  '),
    'END_OF_MANIFEST',
    'kubectl apply -f /tmp/manifest.json',
  ] + if manifest.kind == 'Deployment' then [
    'kubectl wait --for=condition=available deployment/' + manifest.metadata.name,
  ] else []);

local k3s_tag = 'v1.30.0-k3s1';

function(idp, manifests) {
  compose: {
    services:
      utils.ComposeService('k3s-server', {
        image: 'rancher/k3s:${K3S_TAG:-' + k3s_tag + '}',
        entrypoint: Command() + [
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
      }) +
      utils.ComposeService('k3s-agent', {
        image: 'rancher/k3s:${K3S_TAG:-' + k3s_tag + '}',
        entrypoint: Command() + ['agent'],
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
      }) +
      utils.ComposeService('k3s-init', {
        image: 'rancher/k3s:${K3S_TAG:-' + k3s_tag + '}',
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
            InstallManifest,
            std.sort(manifests, function(manifest) manifest.kind + '/' + manifest.metadata.name)
          )) + '\n' +
          |||
            sleep 30
          |||,
        ],
        volumes: [
          'k3s-tmp:/k3s-tmp',
        ],
      }) +
      utils.ComposeService('k3s-ready', {
        depends_on: {
          'k3s-init': {
            condition: 'service_completed_successfully',
          },
        },
        image: 'busybox:latest',
        command: [
          'sh',
          '-c',
          'exit 0',
        ],
      }),
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
