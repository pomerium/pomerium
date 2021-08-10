local pomerium = (import '../../services/pomerium.libsonnet')('google');
local verify = (import '../../services/verify.libsonnet')();
local mock_idp = (import '../../services/mock-idp.libsonnet')('google');

{
  services: verify.services + pomerium.services + mock_idp.services,
  volumes: verify.volumes + pomerium.volumes + mock_idp.volumes,
}
