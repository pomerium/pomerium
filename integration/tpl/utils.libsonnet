local MergeArrays(merge, arrays) =
  std.foldl(function(acc, el) acc + el, arrays, []);

local MergeObjects(merge, objects) =
  std.foldl(function(acc, el) {
    [f]: if std.objectHas(acc, f) && std.objectHas(el, f) then
      merge([acc[f], el[f]])
    else if std.objectHas(el, f) then
      el[f]
    else
      acc[f]
    for f in std.setUnion(
      std.set(std.objectFields(acc)),
      std.set(std.objectFields(el))
    )
  }, objects, {});

local Merge(items) =
  if std.foldl(function(acc, el) acc && std.isArray(el), items, true) then
    MergeArrays(Merge, items)
  else if std.foldl(function(acc, el) acc && std.isObject(el), items, true) then
    MergeObjects(Merge, items)
  else
    items[std.length(items) - 1];

local KubernetesDeployment(name, image, command, ports) =
  {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    metadata: {
      namespace: 'default',
      name: name,
    },
    spec: {
      replicas: 1,
      selector: { matchLabels: { app: name } },
      template: {
        metadata: {
          labels: { app: name },
        },
        spec: {
          containers: [
            {
              name: name,
              image: image,
              ports: ports,
            } + if std.type(command) == 'null' then {} else {
              args: command,
            },
          ],
        },
      },
    },
  };


local KubernetesService(name, ports) =
  {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: {
      namespace: 'default',
      name: name,
      labels: { app: name },
    },
    spec: {
      selector: { app: name },
      ports: ports,
    },
  };

{
  Merge: Merge,
  KubernetesDeployment: KubernetesDeployment,
  KubernetesService: KubernetesService,
}
