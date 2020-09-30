package management

type ClientGrant struct {

	// A generated string identifying the client grant.
	ID *string `json:"id,omitempty"`

	// The identifier of the client.
	ClientID *string `json:"client_id,omitempty"`

	// The audience.
	Audience *string `json:"audience,omitempty"`

	Scope []interface{} `json:"scope"`
}

type ClientGrantList struct {
	List
	ClientGrants []*ClientGrant `json:"client_grants"`
}

type ClientGrantManager struct {
	*Management
}

func newClientGrantManager(m *Management) *ClientGrantManager {
	return &ClientGrantManager{m}
}

// Create a client grant.
//
// See: https://auth0.com/docs/api/management/v2#!/Client_Grants/post_client_grants
func (m *ClientGrantManager) Create(g *ClientGrant) (err error) {
	return m.post(m.uri("client-grants"), g)
}

// Retrieves a client grant by its id.
//
// The Auth0 Management API does not offer a method to retrieve a client grant
// by id, we fake this by listing all client grants and matching by id on the
// client side. For this reason this method should be used with caution.
func (m *ClientGrantManager) Read(id string) (*ClientGrant, error) {
	var page int
	for {
		l, err := m.List(Page(page))
		if err != nil {
			return nil, err
		}
		for _, g := range l.ClientGrants {
			if g.GetID() == id {
				return g, nil
			}
		}
		if !l.HasNext() {
			break
		}
		page++
	}
	return nil, &managementError{
		StatusCode: 404,
		Err:        "Not Found",
		Message:    "Client grant not found",
	}
}

// Update a client grant.
//
// See: https://auth0.com/docs/api/management/v2#!/Client_Grants/patch_client_grants_by_id
func (m *ClientGrantManager) Update(id string, g *ClientGrant) (err error) {
	return m.patch(m.uri("client-grants", id), g)
}

// Delete a client grant.
//
// See: https://auth0.com/docs/api/management/v2#!/Client_Grants/delete_client_grants_by_id
func (m *ClientGrantManager) Delete(id string) (err error) {
	return m.delete(m.uri("client-grants", id))
}

// List all client grants.
//
// This method forces the `include_totals=true` and defaults to `per_page=50` if
// not provided.
//
// See: https://auth0.com/docs/api/management/v2#!/Client_Grants/get_client_grants
func (m *ClientGrantManager) List(opts ...ListOption) (gs *ClientGrantList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("client-grants")+m.q(opts), &gs)
	return
}
