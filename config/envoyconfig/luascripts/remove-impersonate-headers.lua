local function starts_with(str, start)
    return str:sub(1, #start) == start
end

function envoy_on_request(request_handle)
    local headers = request_handle:headers()
    local metadata = request_handle:metadata()

    local remove_impersonate_headers = metadata:get("remove_impersonate_headers")
    if remove_impersonate_headers then
        local to_remove = {}
        for k, v in pairs(headers) do
            if starts_with(k, "impersonate-extra-") or k == "impersonate-group" or k == "impersonate-user" then
                table.insert(to_remove, k)
            end
        end

        for k, v in pairs(to_remove) do
            headers:remove(v)
        end
    end
end

function envoy_on_response(response_handle)
end
