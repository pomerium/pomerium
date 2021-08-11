function() {
  services: {
    fortio: {
      image: 'fortio/fortio:1.17.0',
      depends_on: {
        fortio_init: {
          condition: 'service_completed_successfully',
        },
      },
      command: [
        'server',
        '-cert',
        '/fortio_config/_wildcard.localhost.pomerium.io.pem',
        '-key',
        '/fortio_config/_wildcard.localhost.pomerium.io-key.pem',
      ],
      ports: [
        '8079:8079/tcp',
      ],
      volumes: [
        'fortio_config:/fortio_config',
      ],
    },
    fortio_init: {
      image: 'busybox:latest',
      command: [
        'sh',
        '-c',
        |||
          echo "$$CERT" >/fortio_config/_wildcard.localhost.pomerium.io.pem
          echo "$$KEY" >/fortio_config/_wildcard.localhost.pomerium.io-key.pem
        |||,
      ],
      environment: {
        CERT: importstr '../files/_wildcard.localhost.pomerium.io.pem',
        KEY: importstr '../files/_wildcard.localhost.pomerium.io-key.pem',
      },
      volumes: [
        'fortio_config:/fortio_config',
      ],
    },
  },
  volumes: {
    fortio_config: {},
  },
}
