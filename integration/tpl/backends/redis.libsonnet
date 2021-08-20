local utils = import '../utils.libsonnet';

function() {
  local name = 'redis',
  local image = 'redis:6.2.5-alpine',

  compose: {
    services:
      utils.ComposeService('redis', {
        image: image,

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
