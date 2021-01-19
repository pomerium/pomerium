function envoy_on_request(request_handle)
    local headers = request_handle:headers()
    local dynamic_meta = request_handle:streamInfo():dynamicMetadata()

    local authority = headers:get(":authority")

    -- store the authority header in the metadata so we can retrieve it in the response
    dynamic_meta:set("envoy.filters.http.lua", "request.authority", authority)
end

function envoy_on_response(response_handle)
    local headers = response_handle:headers()
    local dynamic_meta = response_handle:streamInfo():dynamicMetadata()

    local authority =
        dynamic_meta:get("envoy.filters.http.lua")["request.authority"]

    -- if we got a 404 (no route found) and the authority header doens't match
    -- assume we've coalesced http/2 connections and return a 421
    if headers:get(":status") == "404" and authority ~= "%s" then
        headers:replace(":status", "421")
    end
end
