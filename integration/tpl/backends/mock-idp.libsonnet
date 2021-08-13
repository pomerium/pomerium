function(idp) {
  compose: {
    services: {
      'mock-idp': {
        image: 'calebdoxsey/mock-idps:${MOCK_IDPS_TAG:-master}',
        command: [
          '--provider',
          idp,
          '--port',
          '8024',
          '--root-url',
          'https://mock-idp.localhost.pomerium.io',
        ],
        ports: [
          '8024:8024/tcp',
        ],
      },
    },
    volumes: {},
  },
}
