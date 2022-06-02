local utils = import '../utils.libsonnet';

function() {
  local name = 'postgres',
  local image = 'postgres:14.3-alpine',

  compose: {
    services:
      utils.ComposeService(name, {
        image: image,
        environment: {
          POSTGRES_USER: 'pomerium',
          POSTGRES_PASSWORD: 'password',
          POSTGRES_DB: 'test',
        },
      }) +
      utils.ComposeService(name + '-ready', {
        image: 'jwilder/dockerize:0.6.1',
        command: [
          '-wait',
          'tcp://' + name + ':5432',
          '-timeout',
          '10m',
        ],
      }),
  },
  kubernetes: [
    utils.KubernetesDeployment(name, image, null, [
      { name: 'tcp', containerPort: 5432 },
    ]),
    utils.KubernetesService(name, [
      { name: 'tcp', port: 5432, targetPort: 'tcp' },
    ]),
  ],
}
