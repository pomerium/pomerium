local utils = import '../utils.libsonnet';

function() {
  local name = 'fortio',
  local image = 'fortio/fortio:1.17.0',

  compose: {
    services:
      utils.ComposeService(name, {
        image: image,
        depends_on: {
          [name + '-init']: {
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
      utils.ComposeService(name + '-init', {
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
      }) +
      utils.ComposeService(name + '-ready', {
        image: 'jwilder/dockerize:0.6.1',
        command: [
          '-wait',
          'http://' + name + ':8080',
          '-timeout',
          '10m',
        ],
      }),
    volumes: {
      fortio_config: {},
    },
  },
  kubernetes: [],
}
