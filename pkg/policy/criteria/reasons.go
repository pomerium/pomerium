package criteria

import "sort"

// A Reason is a reason for why a policy criterion passes or fails.
type Reason string

// Well-known reasons.
const (
	ReasonAccept                        = "accept"
	ReasonClaimOK                       = "claim-ok"
	ReasonClaimUnauthorized             = "claim-unauthorized"
	ReasonClientCertificateOK           = "client-certificate-ok"
	ReasonClientCertificateUnauthorized = "client-certificate-unauthorized"
	ReasonClientCertificateRequired     = "client-certificate-required"
	ReasonCORSRequest                   = "cors-request"
	ReasonDeviceOK                      = "device-ok"
	ReasonDeviceUnauthenticated         = "device-unauthenticated"
	ReasonDeviceUnauthorized            = "device-unauthorized"
	ReasonDomainOK                      = "domain-ok"
	ReasonDomainUnauthorized            = "domain-unauthorized"
	ReasonEmailOK                       = "email-ok"
	ReasonEmailUnauthorized             = "email-unauthorized"
	ReasonGroupsOK                      = "groups-ok"
	ReasonGroupsUnauthorized            = "groups-unauthorized"
	ReasonHTTPMethodOK                  = "http-method-ok"
	ReasonHTTPMethodUnauthorized        = "http-method-unauthorized"
	ReasonHTTPPathOK                    = "http-path-ok"
	ReasonHTTPPathUnauthorized          = "http-path-unauthorized"
	ReasonInvalidClientCertificate      = "invalid-client-certificate"
	ReasonMCPHandshake                  = "mcp-handshake" // part of MCP protocol handshake
	ReasonMCPMethodOK                   = "mcp-method-ok"
	ReasonMCPMethodUnauthorized         = "mcp-method-unauthorized"
	ReasonMCPToolOK                     = "mcp-tool-ok"
	ReasonMCPNotAToolCall               = "mcp-not-a-tool-call" // MCP method is not a tool call
	ReasonMCPToolUnauthorized           = "mcp-tool-unauthorized"
	ReasonNonCORSRequest                = "non-cors-request"
	ReasonNonPomeriumRoute              = "non-pomerium-route"
	ReasonPomeriumRoute                 = "pomerium-route"
	ReasonReject                        = "reject"
	ReasonRouteNotFound                 = "route-not-found"
	ReasonSSHPublickeyOK                = "ssh-publickey-ok"
	ReasonSSHPublickeyUnauthorized      = "ssh-publickey-unauthorized"
	ReasonSSHUsernameOK                 = "ssh-username-ok"
	ReasonSSHUsernameUnauthorized       = "ssh-username-unauthorized"
	ReasonUserOK                        = "user-ok"
	ReasonUserUnauthenticated           = "user-unauthenticated" // user needs to log in
	ReasonUserUnauthorized              = "user-unauthorized"    // user does not have access
	ReasonValidClientCertificate        = "valid-client-certificate"
)

// Reasons is a collection of reasons.
type Reasons map[Reason]struct{}

// NewReasons creates a new Reasons collection.
func NewReasons(reasons ...Reason) Reasons {
	rs := make(Reasons)
	for _, r := range reasons {
		rs.Add(r)
	}
	return rs
}

// Add adds a reason to the collection.
func (rs Reasons) Add(r Reason) {
	rs[r] = struct{}{}
}

// Has returns true if the reason is found in the collection.
func (rs Reasons) Has(r Reason) bool {
	_, ok := rs[r]
	return ok
}

// Strings returns the reason collection as a slice of strings.
func (rs Reasons) Strings() []string {
	var arr []string
	for r := range rs {
		arr = append(arr, string(r))
	}
	sort.Strings(arr)
	return arr
}

// Union merges two reason collections together.
func (rs Reasons) Union(other Reasons) Reasons {
	merged := make(Reasons)
	for r := range rs {
		merged.Add(r)
	}
	for r := range other {
		merged.Add(r)
	}
	return merged
}
