package management

type ResourceServer struct {

	// A generated string identifying the resource server.
	ID *string `json:"id,omitempty"`

	// The name of the resource server. Must contain at least one character.
	// Does not allow '<' or '>'
	Name *string `json:"name,omitempty"`

	// The identifier of the resource server.
	Identifier *string `json:"identifier,omitempty"`

	// Scopes supported by the resource server.
	Scopes []*ResourceServerScope `json:"scopes,omitempty"`

	// The algorithm used to sign tokens ["HS256" or "RS256"].
	SigningAlgorithm *string `json:"signing_alg,omitempty"`

	// The secret used to sign tokens when using symmetric algorithms.
	SigningSecret *string `json:"signing_secret,omitempty"`

	// Allows issuance of refresh tokens for this entity.
	AllowOfflineAccess *bool `json:"allow_offline_access,omitempty"`

	// The amount of time in seconds that the token will be valid after being
	// issued.
	TokenLifetime *int `json:"token_lifetime,omitempty"`

	// The amount of time in seconds that the token will be valid after being
	// issued from browser based flows. Value cannot be larger than
	// token_lifetime.
	TokenLifetimeForWeb *int `json:"token_lifetime_for_web,omitempty"`

	// Flag this entity as capable of skipping consent.
	SkipConsentForVerifiableFirstPartyClients *bool `json:"skip_consent_for_verifiable_first_party_clients,omitempty"`

	// A URI from which to retrieve JWKs for this resource server used for
	// verifying the JWT sent to Auth0 for token introspection.
	VerificationLocation *string `json:"verificationLocation,omitempty"`

	Options map[string]interface{} `json:"options,omitempty"`

	// Enables the enforcement of the authorization policies.
	EnforcePolicies *bool `json:"enforce_policies,omitempty"`

	// The dialect for the access token ["access_token" or "access_token_authz"].
	TokenDialect *string `json:"token_dialect,omitempty"`
}

type ResourceServerScope struct {
	// The scope name. Use the format <action>:<resource> for example
	// 'delete:client_grants'.
	Value *string `json:"value,omitempty"`

	// Description of the scope
	Description *string `json:"description,omitempty"`
}

type ResourceServerList struct {
	List
	ResourceServers []*ResourceServer `json:"resource_servers"`
}

type ResourceServerManager struct {
	*Management
}

func newResourceServerManager(m *Management) *ResourceServerManager {
	return &ResourceServerManager{m}
}

// Create a resource server.
//
// See: https://auth0.com/docs/api/management/v2#!/Resource_Servers/post_resource_servers
func (m *ResourceServerManager) Create(rs *ResourceServer) (err error) {
	return m.post(m.uri("resource-servers"), rs)
}

// Read retrieves a resource server by its id or audience.
//
// See: https://auth0.com/docs/api/management/v2#!/Resource_Servers/get_resource_servers_by_id
func (m *ResourceServerManager) Read(id string) (rs *ResourceServer, err error) {
	err = m.get(m.uri("resource-servers", id), &rs)
	return
}

// Update a resource server.
//
// See: https://auth0.com/docs/api/management/v2#!/Resource_Servers/patch_resource_servers_by_id
func (m *ResourceServerManager) Update(id string, rs *ResourceServer) (err error) {
	return m.patch(m.uri("resource-servers", id), rs)
}

// Delete a resource server.
//
// See: https://auth0.com/docs/api/management/v2#!/Resource_Servers/delete_resource_servers_by_id
func (m *ResourceServerManager) Delete(id string) (err error) {
	return m.delete(m.uri("resource-servers", id))
}

// List all resource server.
//
// See: https://auth0.com/docs/api/management/v2#!/Resource_Servers/get_resource_servers
func (m *ResourceServerManager) List(opts ...ListOption) (rl *ResourceServerList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("users")+m.q(opts), &rl)
	return
}

// Stream is a helper method which handles pagination
func (m *ResourceServerManager) Stream(fn func(s *ResourceServer)) error {
	var page int
	for {
		l, err := m.List(Page(page))
		if err != nil {
			return err
		}
		for _, s := range l.ResourceServers {
			fn(s)
		}
		if !l.HasNext() {
			break
		}
		page++
	}
	return nil
}
