local utils = import '../utils.libsonnet';

function(idp) {
  local name = 'mock-idp',
  local image = 'calebdoxsey/mock-idps:${MOCK_IDPS_TAG:-master}',
  local command = [
    '--provider',
    idp,
    '--port',
    '8024',
    '--root-url',
    'https://mock-idp.localhost.pomerium.io/',
  ],

  compose: {
    services: {
      [name]: {
        image: image,
        command: command,
        ports: [
          '8024:8024/tcp',
        ],
      },
    },
    volumes: {},
  },
  kubernetes: [
    utils.KubernetesDeployment(name, image, command, [
      { name: 'http', containerPort: 8024 },
    ]),
    utils.KubernetesService(name, [
      { name: 'http', port: 8024, targetPort: 'http' },
    ]),
  ],
}
