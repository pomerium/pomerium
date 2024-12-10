function envoy_on_request(request_handle)
  local headers = request_handle:headers()
  local path = headers:get(":path")

  if path:find("#") ~= nil then
    return
  end

  local function substitute_query_param(query_param_name, header_name)
    local i, j = path:find(query_param_name .. "=")
    if i ~= nil and (path:sub(i - 1, i - 1) == "&" or path:sub(i - 1, i - 1) == "?") then
      local k = path:find("&", j + 1)
      if k ~= nil then
        k = k - 1
      else
        k = #path
      end
      local value = path:sub(j + 1, k)
      if value ~= nil then
        headers:replace(header_name, value)
        return true
      end
    end
    return false
  end

  if substitute_query_param("pomerium_traceparent", "x-pomerium-traceparent") then
    substitute_query_param("pomerium_tracestate", "x-pomerium-tracestate")
  end
  local traceparent = headers:get("traceparent")
  if traceparent ~= nil and #traceparent == 55 and headers:get("x-pomerium-traceparent") == nil then
    headers:replace("x-pomerium-external-parent-span", traceparent:sub(37, 52))
  end
end

function envoy_on_response(response_handle)
end
