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
  --[[
    NB: Sampling
    ------------
    The goal here is to ensure a consistent sampling decision across multiple
    redirects within a single logical request. The decision made on the client's
    initial request (to envoy) should carry forward through redirects, even
    though those subsequent requests are completely separate from envoy's
    point of view; they carry separate request IDs, separate trace IDs (until
    they are joined by pomerium), and - crucially - separate trace decisions.
    On each new request, envoy will decide whether or not to sample it, and
    that decision will be encoded into the traceparent header of the request.
    Envoy will always send the traceparent header if tracing is enabled.  <-- TODO: verify this

    The sampled bit (0x1) of the flags segment (4th) contains the sampling
    decision made by envoy. If there is an x-pomerium-traceparent header
    present, it will encode the original sampling decision in the same place.

    If the x-pomerium-traceparent header is present and indicates the original
    trace was sampled:
    - If envoy's traceparent header also has the sampled bit set, continue
      as normal.
    - If envoy's traceparent header does NOT have the sampled bit set, force
      it to sample the request by setting the x-envoy-force-trace header.

    If the x-pomerium-traceparent header is present and indicates the original
    trace was NOT sampled:
    - If envoy's traceparent header also does NOT have the sampled bit set,
      continue as normal.
    - If envoy's traceparent header DOES have the sampled bit set, this is
      a bit more complicated. We can propagate the x-pomerium-traceparent
      header which will make sure the spans on the pomerium side do not get
      sampled, but there is no mechanism for forcing envoy to un-sample its
      own spans, meaning it will always export spans from this trace which we
      will need to intentionally drop in our exporter. To do this, we detect
      the presence of the pomerium.traceparent span attribute and if it has
      the sampled bit set to 0, the entire trace is dropped.
    ]] --
  local traceparent = headers:get("traceparent")
  local x_pomerium_traceparent = headers:get("x-pomerium-traceparent")
  if traceparent ~= nil and #traceparent == 55 then
    if x_pomerium_traceparent == nil then
      headers:replace("x-pomerium-external-parent-span", traceparent:sub(37, 52))
    elseif #x_pomerium_traceparent == 55 then
      if traceparent:sub(-1) == "0" and x_pomerium_traceparent:sub(-1) == "1" then
        headers:replace("x-envoy-force-trace", "1")
      end
    end
  end
end

function envoy_on_response(response_handle)
end
