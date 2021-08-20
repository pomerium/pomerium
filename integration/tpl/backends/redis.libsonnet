local utils = import '../utils.libsonnet';

function() {
  local name = 'redis',
  local image = 'redis:6.2.5-alpine',

  compose: {
    services:
      utils.ComposeService(name, {
        image: image,
      }) +
      utils.ComposeService(name + '-ready', {
        image: 'jwilder/dockerize:0.6.1',
        command: [
          '-wait',
          'tcp://' + name + ':6379',
          '-timeout',
          '10m',
        ],
      }),
  },
  kubernetes: [
    utils.KubernetesDeployment(name, image, null, [
      { name: 'tcp', containerPort: 6379 },
    ]),
    utils.KubernetesService(name, [
      { name: 'tcp', port: 6379, targetPort: 'tcp' },
    ]),
  ],
}
