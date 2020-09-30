package management

type Rule struct {

	// The rule's identifier.
	ID *string `json:"id,omitempty"`

	// The name of the rule. Can only contain alphanumeric characters, spaces
	// and '-'. Can neither start nor end with '-' or spaces.
	Name *string `json:"name,omitempty"`

	// A script that contains the rule's code.
	Script *string `json:"script,omitempty"`

	// The rule's order in relation to other rules. A rule with a lower order
	// than another rule executes first. If no order is provided it will
	// automatically be one greater than the current maximum.
	Order *int `json:"order,omitempty"`

	// Enabled should be set to true if the rule is enabled, false otherwise.
	Enabled *bool `json:"enabled,omitempty"`
}

type RuleList struct {
	List
	Rules []*Rule `json:"rules"`
}

type RuleManager struct {
	*Management
}

func newRuleManager(m *Management) *RuleManager {
	return &RuleManager{m}
}

// Create a new rule.
//
// Note: Changing a rule's stage of execution from the default `login_success`
// can change the rule's function signature to have user omitted.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules/post_rules
func (m *RuleManager) Create(r *Rule) error {
	return m.post(m.uri("rules"), r)
}

// Retrieve rule details. Accepts a list of fields to include or exclude in the result.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules/get_rules_by_id
func (m *RuleManager) Read(id string) (r *Rule, err error) {
	err = m.get(m.uri("rules", id), &r)
	return
}

// Update an existing rule.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules/patch_rules_by_id
func (m *RuleManager) Update(id string, r *Rule) error {
	return m.patch(m.uri("rules", id), r)
}

// Delete a rule.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules/delete_rules_by_id
func (m *RuleManager) Delete(id string) error {
	return m.delete(m.uri("rules", id))
}

// List all rules.
//
// See: https://auth0.com/docs/api/management/v2#!/Rules/get_rules
func (m *RuleManager) List(opts ...ListOption) (r *RuleList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("rules")+m.q(opts), &r)
	return
}
