function() {
  services: {
    'websocket-echo': {
      image: 'pvtmert/websocketd:latest',
      command: [
        '--port',
        '80',
        'echo',
      ],
    },
  },
  volumes: {},
}
