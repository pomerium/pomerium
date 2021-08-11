local mergeArrays = function(merge, arrays)
  std.foldl(function(acc, el) acc + el, arrays, []);

local mergeObjects = function(merge, objects)
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

local merge = function(items)
  if std.foldl(function(acc, el) acc && std.isArray(el), items, true) then
    mergeArrays(merge, items)
  else if std.foldl(function(acc, el) acc && std.isObject(el), items, true) then
    mergeObjects(merge, items)
  else
    items[std.length(items) - 1];

{
  merge: merge,
}
