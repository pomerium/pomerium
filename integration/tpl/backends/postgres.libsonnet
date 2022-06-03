local utils = import '../utils.libsonnet';

function() {
  local name = 'postgres',
  local image = 'postgres:14.3-alpine',
  local env = {
    POSTGRES_USER: 'pomerium',
    POSTGRES_PASSWORD: 'password',
    POSTGRES_DB: 'test',
  },

  compose: {
    services:
      utils.ComposeService(name, {
        image: image,
        environment: env,
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
    utils.KubernetesDeployment(name, {
      image: image,
      ports: [
        { name: 'tcp', containerPort: 5432 },
      ],
      env: [
        { name: k, value: env[k] }
        for k in std.objectFields(env)
      ],
    }),
    utils.KubernetesService(name, [
      { name: 'tcp', port: 5432, targetPort: 'tcp' },
    ]),
  ],
}
