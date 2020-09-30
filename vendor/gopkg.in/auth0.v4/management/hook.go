package management

type Hook struct {

	// The hook's identifier.
	ID *string `json:"id,omitempty"`

	// The name of the hook. Can only contain alphanumeric characters, spaces
	// and '-'. Can neither start nor end with '-' or spaces.
	Name *string `json:"name,omitempty"`

	// A script that contains the hook's code.
	Script *string `json:"script,omitempty"`

	// The extensibility point name
	// Can currently be any of the following:
	// "credentials-exchange", "pre-user-registration",
	// "post-user-registration", "post-change-password"
	TriggerID *string `json:"triggerId,omitempty"`

	// Used to store additional metadata
	Dependencies *map[string]interface{} `json:"dependencies,omitempty"`

	// Enabled should be set to true if the hook is enabled, false otherwise.
	Enabled *bool `json:"enabled,omitempty"`
}

type HookList struct {
	List
	Hooks []*Hook `json:"hooks"`
}

// HookSecrets are the secret keys and values associated with a hook
type HookSecrets map[string]string

type HookManager struct {
	*Management
}

func newHookManager(m *Management) *HookManager {
	return &HookManager{m}
}

// Create a new hook.
//
// Note: Changing a hook's trigger changes the signature of the script and should be done with caution.
//
// See: https://auth0.com/docs/api/management/v2#!/Hooks/post_hooks
func (m *HookManager) Create(r *Hook) error {
	return m.post(m.uri("hooks"), r)
}

// Retrieve hook details. Accepts a list of fields to include or exclude in the result.
//
// See: https://auth0.com/docs/api/management/v2/#!/Hooks/get_hooks_by_id
func (m *HookManager) Read(id string) (r *Hook, err error) {
	err = m.get(m.uri("hooks", id), &r)
	return
}

// Update an existing hook.
//
// See: https://auth0.com/docs/api/management/v2/#!/Hooks/patch_hooks_by_id
func (m *HookManager) Update(id string, r *Hook) error {
	return m.patch(m.uri("hooks", id), r)
}

// Delete a hook.
//
// See: https://auth0.com/docs/api/management/v2/#!/Hooks/delete_hooks_by_id
func (m *HookManager) Delete(id string) error {
	return m.delete(m.uri("hooks", id))
}

// List all hooks.
//
// See: https://auth0.com/docs/api/management/v2/#!/Hooks/get_hooks
func (m *HookManager) List(opts ...ListOption) (r *HookList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("roles")+m.q(opts), &r)
	return
}

// CreateSecrets creates hook secrets on a hook that has no secrets defined
//
// See: https://auth0.com/docs/api/management/v2#!/Hooks/post_secrets
func (m *HookManager) CreateSecrets(hookID string, r *HookSecrets) (err error) {
	return m.post(m.uri("hooks", hookID, "secrets"), r)
}

// UpdateSecrets updates the values of a hook's secrets that have previously been created
//
// See: https://auth0.com/docs/api/management/v2#!/Hooks/patch_secrets
func (m *HookManager) UpdateSecrets(hookID string, r *HookSecrets) (err error) {
	return m.patch(m.uri("hooks", hookID, "secrets"), r)
}

// Secrets list all secrets configured for the given hook
//
// Note: For security, hook secret values cannot be retrieved outside rule
// execution (they all appear as "_VALUE_NOT_SHOWN_")
//
// See: https://auth0.com/docs/api/management/v2/#!/Hooks/get_secrets
func (m *HookManager) Secrets(hookID string) (r *HookSecrets, err error) {
	err = m.get(m.uri("hooks", hookID, "secrets"), &r)
	return
}

// RemoveSecrets removes a list of hook secret keys from a given hook's secrets by the keys of the secrets
//
// See: https://auth0.com/docs/api/management/v2/#!/Hooks/delete_secrets
func (m *HookManager) RemoveSecrets(hookID string, keys ...string) (err error) {
	return m.request("DELETE", m.uri("hooks", hookID, "secrets"), keys)
}

// RemoveAllSecrets removes all secrets associated with a given hook
func (m *HookManager) RemoveAllSecrets(hookID string) (err error) {
	r, err := m.Secrets(hookID)
	if err == nil {
		keys := r.Keys()
		if len(keys) > 0 {
			err = m.RemoveSecrets(hookID, keys...)
		}
	}
	return err
}

// Keys gets the configured hook secret keys
func (s *HookSecrets) Keys() []string {
	keys := make([]string, len(*s))
	i := 0
	for k := range *s {
		keys[i] = k
		i++
	}
	return keys
}
