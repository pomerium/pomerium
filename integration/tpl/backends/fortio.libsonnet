local utils = import '../utils.libsonnet';

function() {
  compose: {
    services:
      utils.ComposeService('fortio', {
        image: 'fortio/fortio:1.17.0',
        depends_on: {
          fortio_init: {
            condition: 'service_completed_successfully',
          },
        },
        command: [
          'server',
          '-cert',
          '/fortio_config/trusted.pem',
          '-key',
          '/fortio_config/trusted-key.pem',
        ],
        ports: [
          '8079:8079/tcp',
        ],
        volumes: [
          'fortio_config:/fortio_config',
        ],
      }) +
      utils.ComposeService('fortio_init', {
        image: 'busybox:latest',
        command: [
          'sh',
          '-c',
          |||
            echo "$$CERT" >/fortio_config/trusted.pem
            echo "$$KEY" >/fortio_config/trusted-key.pem
          |||,
        ],
        environment: {
          CERT: importstr '../files/trusted.pem',
          KEY: importstr '../files/trusted-key.pem',
        },
        volumes: [
          'fortio_config:/fortio_config',
        ],
      }),
    volumes: {
      fortio_config: {},
    },
  },
  kubernetes: [],
}
