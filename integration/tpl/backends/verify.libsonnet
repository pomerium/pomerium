local utils = import '../utils.libsonnet';

function(multi) {
  local name = 'verify',
  local image = 'pomerium/verify:${VERIFY_TAG:-latest}',

  compose: {
    services: {
      verify: {
        image: image,
        depends_on: {
          verify_init: {
            condition: 'service_completed_successfully',
          },
        },
        environment: {
          SSL_CERT_FILE: '/verify_config/ca.pem',
        },
        links: if multi then [
          'pomerium-authenticate:authenticate.localhost.pomerium.io',
        ] else [
          'pomerium:authenticate.localhost.pomerium.io',
        ],
        volumes: [
          'verify_config:/verify_config',
        ],
      },
      verify_init: {
        image: 'busybox:latest',
        command: [
          'sh',
          '-c',
          "echo '" + (importstr '../files/ca.pem') + "' > /verify_config/ca.pem",
        ],
        volumes: [
          'verify_config:/verify_config',
        ],
      },
    },
    volumes: {
      verify_config: {},
    },
  },
  kubernetes: [
    utils.KubernetesService(name, [
      { name: 'http', port: 80, targetPort: 'http' },
    ]),
    utils.KubernetesDeployment(name, image, null, [
      { name: 'http', containerPort: 80 },
    ]),
  ],
}
