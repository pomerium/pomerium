local utils = import '../utils.libsonnet';

function(mode) {
  local name = 'verify',
  local image = 'pomerium/verify:${VERIFY_TAG:-latest}',

  compose: {
    services:
      utils.ComposeService(name, {
        image: image,
        depends_on: {
          [name + '-init']: {
            condition: 'service_completed_successfully',
          },
        },
        environment: {
          SSL_CERT_FILE: '/verify_config/ca.pem',
        },
        volumes: [
          'verify_config:/verify_config',
        ],
      }) +
      utils.ComposeService(name + '-init', {
        image: 'busybox:latest',
        command: [
          'sh',
          '-c',
          "echo '" + (importstr '../files/ca.pem') + "' > /verify_config/ca.pem",
        ],
        volumes: [
          'verify_config:/verify_config',
        ],
      }) +
      utils.ComposeService(name + '-ready', {
        image: 'jwilder/dockerize:0.6.1',
        command: [
          '-wait',
          'http://' + name + ':8000/',
          '-timeout',
          '10m',
        ],
      }),
    volumes: {
      verify_config: {},
    },
  },
  kubernetes: [
    utils.KubernetesService(name, [
      { name: 'http', port: 80, targetPort: 'http' },
    ]),
    utils.KubernetesDeployment(name, {
      image: image,
      ports: [
        { name: 'http', containerPort: 8000 },
      ],
    }),
  ],
}
