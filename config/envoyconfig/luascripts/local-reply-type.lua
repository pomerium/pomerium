-- This filter interprets the accept header of an incoming request and attempts to map it to
-- a metadata value of either "html", "json" or "plain". This metadata value is used to format
-- local replies in a format the client expects.

function parse_accept_header(header_value)
    -- returns a table with a type field, the table is sorted by position and weight
    if header_value == nil then
        return {}
    end

    local content_types = {}
    local start_idx = 1
    local position = 1
    while true do
        local end_idx = string.find(header_value, ",", start_idx)
        local segment
        if end_idx == nil then
            segment = string.sub(header_value, start_idx)
        else
            segment = string.sub(header_value, start_idx, end_idx-1)
        end

        local mime_type = segment
        local q = 1.0
        local semicolon_idx = string.find(segment, ';')
        if semicolon_idx ~= nil then
            mime_type = string.sub(segment, 1, semicolon_idx-1)
            q_idx = string.find(segment, "q=", semicolon_idx+1)
            if q_idx ~= nil then
                q_str = string.sub(segment, q_idx+2)
                q = tonumber(q_str)
            end
        end

        table.insert(content_types, { type=mime_type, q=q, position=position })
        position = position+1

        if end_idx == nil then
            break
        else
            start_idx = end_idx+1
        end
    end
    table.sort(content_types, function(a,b)
        if a.q == b.q then
            return a.position < b.position
        end
        return a.q > b.q
    end)
    return content_types
end

function envoy_on_request(request_handle)
    local headers = request_handle:headers()
    local dynamic_meta = request_handle:streamInfo():dynamicMetadata()

    local content_types = parse_accept_header(headers:get("accept"))
    for _, v in pairs(content_types) do
        if v.type == "text/html" or v.type == "text/*"  then
            dynamic_meta:set("envoy.filters.http.lua", "pomerium_local_reply_type", "html")
            return
        elseif v.type == "text/plain" then
            dynamic_meta:set("envoy.filters.http.lua", "pomerium_local_reply_type", "plain")
            return
        elseif v.type == "application/json" or v.type == "application/*" then
            dynamic_meta:set("envoy.filters.http.lua", "pomerium_local_reply_type", "json")
            return
        end
    end
    -- if nothing matched, just return html
    dynamic_meta:set("envoy.filters.http.lua", "pomerium_local_reply_type", "html")
end

function envoy_on_response(response_handle)
    -- unused
end
