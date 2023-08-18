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

local KubernetesDeployment(name, container) =
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
            { name: name } + container,
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

local ParseURL(rawURL) =
  {
    local splitLeft(str, pat) =
      local idxs = std.findSubstr(pat, str);
      if std.length(idxs) == 0 then
        [str, '']
      else
        [std.substr(str, 0, idxs[0]), std.substr(str, idxs[0] + std.length(pat), std.length(str))],

    local splitRight(str, pat) =
      local idxs = std.findSubstr(pat, str);
      if std.length(idxs) == 0 then
        ['', str]
      else
        [std.substr(str, 0, idxs[0]), std.substr(str, idxs[0] + std.length(pat), std.length(str))],

    local p0 = ['', rawURL],
    local p1 = splitRight(p0[1], '://'),
    local p2 = splitRight(p1[1], '@'),
    local p3 = splitLeft(p2[1], '/'),
    local p4 = splitLeft(p3[1], '?'),
    local p5 = splitLeft(p4[1], '#'),

    scheme: p1[0],
    user: p2[0],
    host: p3[0],
    path: if p4[0] == '' then '' else '/' + p4[0],
    query: p5[0],
    fragment: p5[1],
  };

local ComposeService(name, definition, additionalAliases=[]) =
  {
    [name]: definition {
      networks+: {
        main+: {
          aliases: [name] + additionalAliases,
        },
      },
    },
  };

{
  ComposeService: ComposeService,
  Merge: Merge,
  KubernetesDeployment: KubernetesDeployment,
  KubernetesService: KubernetesService,
  ParseURL: ParseURL,
}
