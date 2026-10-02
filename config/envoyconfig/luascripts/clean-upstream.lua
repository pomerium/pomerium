function remove_pomerium_cookie(cookie_name, cookie)
    local result = ""
    for c in cookie:gmatch("([^;]+)") do
        c = c:gsub("^ +","")
        local name = c:match("^([^=]+)")
        if name ~= cookie_name then
            if string.len(result) > 0 then
                result = result .. "; " .. c
            else
                result = result .. c
            end
        end
    end
    return result
end

function envoy_on_request(request_handle)
    local headers = request_handle:headers()
    local metadata = request_handle:metadata()

    local remove_cookie_name = metadata:get("remove_pomerium_cookie")
    if remove_cookie_name then
        local cookie = headers:get("cookie")
        if cookie ~= nil then
            local newcookie = remove_pomerium_cookie(remove_cookie_name, cookie)
            headers:replace("cookie", newcookie)
        end
    end
end

function envoy_on_response(response_handle) end
