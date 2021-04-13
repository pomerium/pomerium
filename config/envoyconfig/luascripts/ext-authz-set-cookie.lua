function envoy_on_request(request_handle)
    local headers = request_handle:headers()
    local dynamic_meta = request_handle:streamInfo():dynamicMetadata()
    if headers:get("x-pomerium-set-cookie") ~= nil then
        dynamic_meta:set("envoy.filters.http.lua", "pomerium_set_cookie",
                         headers:get("x-pomerium-set-cookie"))
        headers:remove("x-pomerium-set-cookie")
    end
end

function envoy_on_response(response_handle)
    local headers = response_handle:headers()
    local dynamic_meta = response_handle:streamInfo():dynamicMetadata()
    local tbl = dynamic_meta:get("envoy.filters.http.lua")
    if tbl ~= nil and tbl["pomerium_set_cookie"] ~= nil then
        headers:add("set-cookie", tbl["pomerium_set_cookie"])
    end
end
