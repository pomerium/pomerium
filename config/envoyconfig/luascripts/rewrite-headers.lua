function replace_prefix(str, prefix, value)
    if str:sub(0, prefix:len()) == prefix then
        return value..str:sub(prefix:len()+1)
    end
    return str
end

function envoy_on_request(request_handle)
end

function envoy_on_response(response_handle)
    local headers = response_handle:headers()
    local metadata = response_handle:metadata()

    -- should be in the form:
    -- [{
    --   "header":"Location",
    --   "prefix":"http://localhost:8000/two/",
    --   "value":"http://frontend/one/"
    -- }]
    local rewrite_response_headers = metadata:get("rewrite_response_headers")
    if rewrite_response_headers then
        for _, obj in pairs(rewrite_response_headers) do
            local hdr = headers:get(obj.header)
            if hdr ~= nil then
                local newhdr = replace_prefix(hdr, obj.prefix, obj.value)
                headers:replace(obj.header, newhdr)
            end
        end
    end
end
