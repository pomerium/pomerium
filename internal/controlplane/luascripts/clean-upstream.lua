function remove_pomerium_cookie(cookie_name, cookie)
    -- lua doesn't support optional capture groups
    -- so we replace twice to handle pomerium=xyz at the end of the string
    cookie = cookie:gsub(cookie_name .. "=[^;]+; ", "")
    cookie = cookie:gsub(cookie_name .. "=[^;]+", "")
    return cookie
end

function has_prefix(str, prefix)
    return str ~= nil and str:sub(1, #prefix) == prefix
end

function envoy_on_request(request_handle)
    local headers = request_handle:headers()
    local metadata = request_handle:metadata()

    local remove_cookie_name = metadata:get("remove_pomerium_cookie")
    if remove_cookie_name then
        local cookie = headers:get("cookie")
        if cookie ~= nil then
            newcookie = remove_pomerium_cookie(remove_cookie_name, cookie)
            headers:replace("cookie", newcookie)
        end
    end

    local remove_authorization = metadata:get("remove_pomerium_authorization")
    if remove_authorization then
        local authorization = headers:get("authorization")
        local authorization_prefix = "Pomerium "
        if has_prefix(authorization, authorization_prefix) then
            headers:remove("authorization")
        end
    end
end
