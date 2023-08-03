function envoy_on_request(request_handle)
    local metadata = request_handle:streamInfo():dynamicMetadata()
    local ssl = request_handle:streamInfo():downstreamSslConnection()
    metadata:set("com.pomerium.client-certificate-info", "presented",
                 ssl:peerCertificatePresented())
    metadata:set("com.pomerium.client-certificate-info", "chain",
                 ssl:urlEncodedPemEncodedPeerCertificateChain())
end

function envoy_on_response(response_handle) end
