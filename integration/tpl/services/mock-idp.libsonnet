function(idp_provider) {
  services: {
    'mock-idp': {
      image: 'calebdoxsey/mock-idps:${MOCK_IDPS_TAG:-master}',
      command: [
        '--provider',
        idp_provider,
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
}
