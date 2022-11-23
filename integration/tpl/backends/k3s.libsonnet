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

      #########################################################################################################################################
      # DISCLAIMER																																																														#
      # Copied from https://github.com/moby/moby/blob/ed89041433a031cafc0a0f19cfe573c31688d377/hack/dind#L28-L37															#
      # Permission granted by Akihiro Suda <akihiro.suda.cz@hco.ntt.co.jp> (https://github.com/k3d-io/k3d/issues/493#issuecomment-827405962)	#
      # Moby License Apache 2.0: https://github.com/moby/moby/blob/ed89041433a031cafc0a0f19cfe573c31688d377/LICENSE														#
      #########################################################################################################################################
      if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        echo "[$(date -Iseconds)] [CgroupV2 Fix] Evacuating Root Cgroup ..."
        # move the processes from the root group to the /init group,
        # otherwise writing subtree_control fails with EBUSY.
        mkdir -p /sys/fs/cgroup/init
        busybox xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
        # enable controllers
        sed -e 's/ / +/g' -e 's/^/+/' <"/sys/fs/cgroup/cgroup.controllers" >"/sys/fs/cgroup/cgroup.subtree_control"
        echo "[$(date -Iseconds)] [CgroupV2 Fix] Done"
      fi

      k3s "$$@"
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

local k3s_tag = 'v1.22.16-k3s1';

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
      utils.ComposeService('k3s-server-ready', {
        image: 'jwilder/dockerize:0.6.1',
        command: [
          '-wait',
          'tcp://k3s-server:6443',
          '-timeout',
          '10m',
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
          'k3s-server-ready': {
            condition: 'service_completed_successfully',
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
