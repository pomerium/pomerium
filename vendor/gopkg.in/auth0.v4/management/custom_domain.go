package management

type CustomDomain struct {

	// The id of the custom domain
	ID *string `json:"custom_domain_id,omitempty"`

	// The custom domain.
	Domain *string `json:"domain,omitempty"`

	// The custom domain provisioning type. Can be either "auth0_managed_certs"
	// or "self_managed_certs"
	Type *string `json:"type,omitempty"`

	// Primary is true if the domain was marked as "primary", false otherwise.
	Primary *bool `json:"primary,omitempty"`

	// The custom domain configuration status. Can be any of the following:
	//
	// "disabled", "pending", "pending_verification" or "ready"
	Status *string `json:"status,omitempty"`

	// The custom domain verification method. The only allowed value is "txt".
	VerificationMethod *string `json:"verification_method,omitempty"`

	Verification *CustomDomainVerification `json:"verification,omitempty"`
}

type CustomDomainVerification struct {

	// The custom domain verification methods.
	Methods []map[string]interface{} `json:"methods,omitempty"`
}

type CustomDomainManager struct {
	*Management
}

func newCustomDomainManager(m *Management) *CustomDomainManager {
	return &CustomDomainManager{m}
}

// Create a new custom domain.
//
// Note: The custom domain will need to be verified before it starts accepting
// requests.
//
// See: https://auth0.com/docs/api/management/v2#!/Custom_Domains/post_custom_domains
func (m *CustomDomainManager) Create(c *CustomDomain) (err error) {
	return m.post(m.uri("custom-domains"), c)
}

// Retrieve a custom domain configuration and status.
//
// See: https://auth0.com/docs/api/management/v2#!/Custom_Domains/get_custom_domains_by_id
func (m *CustomDomainManager) Read(id string) (*CustomDomain, error) {
	c := new(CustomDomain)
	err := m.get(m.uri("custom-domains", id), c)
	return c, err
}

// Run the verification process on a custom domain.
//
// See: https://auth0.com/docs/api/management/v2#!/Custom_Domains/post_verify
func (m *CustomDomainManager) Verify(id string) (*CustomDomain, error) {
	c := new(CustomDomain)
	err := m.post(m.uri("custom-domains", id, "verify"), c)
	return c, err
}

// Delete a custom domain and stop serving requests for it.
//
// See: https://auth0.com/docs/api/management/v2#!/Custom_Domains/delete_custom_domains_by_id
func (m *CustomDomainManager) Delete(id string) (err error) {
	return m.delete(m.uri("custom-domains", id))
}

// List all custom domains.
//
// See: https://auth0.com/docs/api/management/v2#!/Custom_Domains/get_custom_domains
func (m *CustomDomainManager) List(opts ...ListOption) (c []*CustomDomain, err error) {
	err = m.get(m.uri("custom-domains")+m.q(opts), &c)
	return
}
