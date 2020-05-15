{
  trusted: {
    cert: std.extVar('tls-trusted-cert'),
    key: std.extVar('tls-trusted-key'),
    ca: std.extVar('tls-trusted-ca'),
  },
  'wrongly-named': {
    cert: std.extVar('tls-wrongly-named-cert'),
    key: std.extVar('tls-wrongly-named-key'),
    ca: std.extVar('tls-wrongly-named-ca'),
  },
  untrusted: {
    cert: std.extVar('tls-untrusted-cert'),
    key: std.extVar('tls-untrusted-key'),
    ca: std.extVar('tls-untrusted-ca'),
  },
}
