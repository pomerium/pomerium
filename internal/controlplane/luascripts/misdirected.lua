function envoy_on_request(request_handle) end

-- replace 404s due to http2 coalescing with 421 misdirected request
-- https://github.com/envoyproxy/envoy/issues/6767#issuecomment-688017034
function envoy_on_response(response_handle)
    if response_handle:headers():get(":status") == "404" and
        response_handle:headers():get("x-envoy-upstream-service-time") == nil then
        response_handle:headers():replace(":status", "421")
    end
end
