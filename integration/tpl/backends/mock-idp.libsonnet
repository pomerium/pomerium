local utils = import '../utils.libsonnet';

function(idp) {
  local name = 'mock-idp',
  local image = 'pomerium/mock-idps:${MOCK_IDPS_TAG:-master}',
  local command = [
    '--provider',
    idp,
    '--port',
    '8024',
    '--root-url',
    'https://mock-idp.localhost.pomerium.io/',
  ],

  compose: {
    services:
      utils.ComposeService(name, {
        image: image,
        command: command,
        ports: [
          '8024:8024/tcp',
        ],
      }) +
      utils.ComposeService(name + '-ready', {
        image: 'jwilder/dockerize:0.6.1',
        command: [
          '-wait',
          'http://' + name + ':8024/.well-known/openid-configuration',
          '-timeout',
          '10m',
        ],
      }),
    volumes: {},
  },
  kubernetes: [
    utils.KubernetesDeployment(name, {
      image: image,
      args: command,
      ports: [
        { name: 'http', containerPort: 8024 },
      ],
    }),
    utils.KubernetesService(name, [
      { name: 'http', port: 8024, targetPort: 'http' },
    ]),
  ],
}
