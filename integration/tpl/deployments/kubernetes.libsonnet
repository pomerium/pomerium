local utils = import '../utils.libsonnet';

function(idp) utils.merge([
  (import '../backends/k3s.libsonnet')(),
])
