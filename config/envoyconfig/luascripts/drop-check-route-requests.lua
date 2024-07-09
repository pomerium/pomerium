function envoy_on_request(request_handle)
  local headers = request_handle:headers()
  if headers:get("x-pomerium-check-route") ~= nil then
    request_handle:logErr("check-route request caught by filter")
    request_handle:respond({[":status"] = "500"}, "Internal Server Error")
  end
end