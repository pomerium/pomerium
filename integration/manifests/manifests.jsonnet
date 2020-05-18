local httpdetails = import './lib/httpdetails.libsonnet';
local nginxIngressController = import './lib/nginx-ingress-controller.libsonnet';
local pomerium = import './lib/pomerium.libsonnet';
local openid = import './lib/reference-openid-provider.libsonnet';

{
  apiVersion: 'v1',
  kind: 'List',
  items: nginxIngressController.items + pomerium.items + openid.items + httpdetails.items,
}
