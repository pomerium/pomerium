local utils = import '../utils.libsonnet';

function(idp) utils.merge([
  (import '../backends/fortio.libsonnet')(),
  (import '../backends/mock-idp.libsonnet')(idp),
  (import '../backends/pomerium.libsonnet')(idp),
  (import '../backends/verify.libsonnet')(),
  (import '../backends/websocket-echo.libsonnet')(),
])
