{
  trusted: {
    cert: std.extVar('tls-trusted-cert'),
    key: std.extVar('tls-trusted-key'),
    ca: std.extVar('tls-trusted-ca'),
    client: {
      cert: std.extVar('tls-trusted-client-cert'),
      key: std.extVar('tls-trusted-client-key'),
    },
  },
  'wrongly-named': {
    cert: std.extVar('tls-wrongly-named-cert'),
    key: std.extVar('tls-wrongly-named-key'),
    ca: std.extVar('tls-wrongly-named-ca'),
    client: {
      cert: std.extVar('tls-wrongly-named-client-cert'),
      key: std.extVar('tls-wrongly-named-client-key'),
    },
  },
  untrusted: {
    cert: std.extVar('tls-untrusted-cert'),
    key: std.extVar('tls-untrusted-key'),
    ca: std.extVar('tls-untrusted-ca'),
    client: {
      cert: std.extVar('tls-untrusted-client-cert'),
      key: std.extVar('tls-untrusted-client-key'),
    },
  },
}
