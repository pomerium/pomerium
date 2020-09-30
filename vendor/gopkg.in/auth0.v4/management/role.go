package management

type Role struct {
	// A unique ID for the role.
	ID *string `json:"id,omitempty"`

	// The name of the role created.
	Name *string `json:"name,omitempty"`

	// A description of the role created.
	Description *string `json:"description,omitempty"`
}

type RoleList struct {
	List
	Roles []*Role `json:"roles"`
}

type Permission struct {
	// The resource server that the permission is attached to.
	ResourceServerIdentifier *string `json:"resource_server_identifier,omitempty"`

	// The name of the resource server.
	ResourceServerName *string `json:"resource_server_name,omitempty"`

	// The name of the permission.
	Name *string `json:"permission_name,omitempty"`

	// The description of the permission.
	Description *string `json:"description,omitempty"`
}

type PermissionList struct {
	List
	Permissions []*Permission `json:"permissions"`
}

type RoleManager struct {
	*Management
}

func newRoleManager(m *Management) *RoleManager {
	return &RoleManager{m}
}

// Create a new role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/post_roles
func (m *RoleManager) Create(r *Role) error {
	return m.post(m.uri("roles"), r)
}

// Retrieve a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/get_roles_by_id
func (m *RoleManager) Read(id string) (r *Role, err error) {
	err = m.get(m.uri("roles", id), &r)
	return
}

// Update a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/patch_roles_by_id
func (m *RoleManager) Update(id string, r *Role) (err error) {
	return m.patch(m.uri("roles", id), r)
}

// Delete a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/delete_roles_by_id
func (m *RoleManager) Delete(id string) (err error) {
	return m.delete(m.uri("roles", id))
}

// List all roles that can be assigned to users or groups.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/get_roles
func (m *RoleManager) List(opts ...ListOption) (r *RoleList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("roles")+m.q(opts), &r)
	return
}

// AssignUsers assigns users to a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/post_role_users
func (m *RoleManager) AssignUsers(id string, users ...*User) error {
	u := make(map[string][]*string)
	u["users"] = make([]*string, len(users))
	for i, user := range users {
		u["users"][i] = user.ID
	}
	return m.post(m.uri("roles", id, "users"), &u)
}

// Users retrieves all users associated with a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/get_role_user
func (m *RoleManager) Users(id string, opts ...ListOption) (u *UserList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("roles", id, "users")+m.q(opts), &u)
	return
}

// AssociatePermissions associates permissions to a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/post_role_permission_assignment
func (m *RoleManager) AssociatePermissions(id string, permissions ...*Permission) error {
	p := make(map[string][]*Permission)
	p["permissions"] = permissions
	return m.post(m.uri("roles", id, "permissions"), &p)
}

// Permissions retrieves all permissions granted by a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/get_role_permission
func (m *RoleManager) Permissions(id string, opts ...ListOption) (p *PermissionList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("roles", id, "permissions")+m.q(opts), &p)
	return
}

// RemovePermissions removes permissions associated to a role.
//
// See: https://auth0.com/docs/api/management/v2#!/Roles/delete_role_permission_assignment
func (m *RoleManager) RemovePermissions(id string, permissions ...*Permission) error {
	p := make(map[string][]*Permission)
	p["permissions"] = permissions
	return m.request("DELETE", m.uri("roles", id, "permissions"), &p)
}
