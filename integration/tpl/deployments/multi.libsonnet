local utils = import '../utils.libsonnet';

function(idp) utils.Merge([
  (import '../backends/fortio.libsonnet')().compose,
  (import '../backends/httpdetails.libsonnet')().compose,
  (import '../backends/mock-idp.libsonnet')(idp).compose,
  (import '../backends/pomerium.libsonnet')(true, idp).compose,
  (import '../backends/redis.libsonnet')().compose,
  (import '../backends/verify.libsonnet')(true).compose,
  (import '../backends/websocket-echo.libsonnet')().compose,
])
