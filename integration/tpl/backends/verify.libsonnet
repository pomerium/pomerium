function() {
  compose: {
    services: {
      verify: {
        image: 'pomerium/verify:${VERIFY_TAG:-latest}',
        depends_on: {
          verify_init: {
            condition: 'service_completed_successfully',
          },
        },
        environment: {
          SSL_CERT_FILE: '/verify_config/ca.pem',
        },
        links: [
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
}
