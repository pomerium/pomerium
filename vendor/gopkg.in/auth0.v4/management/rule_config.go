package management

type RuleConfig struct {

	// The key for a RuleConfigs config
	Key *string `json:"key,omitempty"`

	// The value for the rules config
	Value *string `json:"value,omitempty"`
}

type RuleConfigManager struct {
	*Management
}

func newRuleConfigManager(m *Management) *RuleConfigManager {
	return &RuleConfigManager{m}
}

// Upsert sets a rule configuration variable.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules_Configs/put_rules_configs_by_key
func (m *RuleConfigManager) Upsert(key string, r *RuleConfig) (err error) {
	return m.put(m.uri("rules-configs", key), r)
}

// Read a rule configuration variable by key.
//
// Note: For security, config variable values cannot be retrieved outside rule
// execution.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules_Configs/get_rules_configs
func (m *RuleConfigManager) Read(key string) (*RuleConfig, error) {
	rs, err := m.List()
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.GetKey() == key {
			return r, nil
		}
	}
	return nil, &managementError{404, "Not Found", "Rule config not found"}
}

// Delete a rule configuration variable identified by its key.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules_Configs/delete_rules_configs_by_key
func (m *RuleConfigManager) Delete(key string) (err error) {
	return m.delete(m.uri("rules-configs", key))
}

// List all rule configuration variables.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules_Configs/get_rules_configs
func (m *RuleConfigManager) List(opts ...ListOption) (r []*RuleConfig, err error) {
	err = m.get(m.uri("rules-configs")+m.q(opts), &r)
	return
}
