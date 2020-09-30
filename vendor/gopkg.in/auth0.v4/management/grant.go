package management

type Grant struct {

	// The id of the grant.
	ID *string `json:"id,omitempty"`

	// The id of the client.
	ClientID *string `json:"clientID,omitempty"`

	// The id of the user.
	UserID *string `json:"user_id"`

	// The grant's audience.
	Audience *string `json:"audience,omitempty"`

	Scope []interface{} `json:"scope,omitempty"`
}

type GrantManager struct {
	*Management
}

func newGrantManager(m *Management) *GrantManager {
	return &GrantManager{m}
}

// List the grants associated with your account.
//
// See: https://auth0.com/docs/api/management/v2#!/Grants/get_grants
func (m *GrantManager) List(opts ...ListOption) (g []*Grant, err error) {
	err = m.get(m.uri("grants")+m.q(opts), &g)
	return
}

// Delete revokes a grant associated with a user-id
// https://auth0.com/docs/api/management/v2#!/Grants/delete_grants_by_id
func (m *GrantManager) Delete(id string, opts ...ListOption) error {
	return m.delete(m.uri("grants", id) + m.q(opts))
}
