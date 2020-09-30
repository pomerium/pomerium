package management

type Email struct {

	// The name of the email provider. Can be one of "mandrill", "sendgrid",
	// "sparkpost", "ses" or "smtp".
	Name *string `json:"name,omitempty"`

	// True if the email provider is enabled, false otherwise (defaults to true)
	Enabled *bool `json:"enabled,omitempty"`

	// The default FROM address
	DefaultFromAddress *string `json:"default_from_address,omitempty"`

	Credentials *EmailCredentials      `json:"credentials,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type EmailCredentials struct {
	// API User
	APIUser *string `json:"api_user,omitempty"`
	// API Key
	APIKey *string `json:"api_key,omitempty"`
	// AWS Access Key ID
	AccessKeyID *string `json:"accessKeyId,omitempty"`
	// AWS Secret Access Key
	SecretAccessKey *string `json:"secretAccessKey,omitempty"`
	// AWS default region
	Region *string `json:"region,omitempty"`
	// SMTP host
	SMTPHost *string `json:"smtp_host,omitempty"`
	// SMTP port
	SMTPPort *int `json:"smtp_port,omitempty"`
	// SMTP user
	SMTPUser *string `json:"smtp_user,omitempty"`
	// SMTP password
	SMTPPass *string `json:"smtp_pass,omitempty"`
	// Domain
	Domain *string `json:"domain,omitempty"`
}

type EmailManager struct {
	*Management
}

func newEmailManager(m *Management) *EmailManager {
	return &EmailManager{m}
}

// Create an email provider.
//
// The credentials object requires different properties depending on the email
// provider (which is specified using the name property):
//
// - `mandrill` requires `api_key`
// - `sendgrid` requires `api_key`
// - `sparkpost` requires `api_key`. Optionally, set `region` to `eu` to use the
// SparkPost service hosted in Western Europe; set to `null` to use the
// SparkPost service hosted in North America. `eu` or `null` are the only valid
// values for `region`.
// - ses requires accessKeyId, secretAccessKey, and region
// - smtp requires smtp_host, smtp_port, smtp_user, and smtp_pass
// - `mailgun` requires `api_key` and `domain`. Optionally, set region to eu to
// use the Mailgun service hosted in Europe; set to null otherwise. eu or null
// are the only valid values for region.
//
// Depending on the type of provider it is possible to specify settings object
// with different configuration options, which will be used when sending an
// email:
//
// - `smtp` provider, `settings` may contain `headers` object. When using AWS
// SES SMTP host, you may provide a name of configuration set in an
// `X-SES-Configuration-Set` header. The value must be a string.
//
// See: https://auth0.com/docs/api/management/v2#!/Emails/post_provider
func (m *EmailManager) Create(e *Email) error {
	return m.post(m.uri("emails", "provider"), e)
}

// Retrieve email provider details.
//
// See: https://auth0.com/docs/api/management/v2#!/Emails/get_provider
func (m *EmailManager) Read() (e *Email, err error) {
	err = m.get(m.uri("emails", "provider")+m.q([]ListOption{
		WithFields("name", "enabled", "default_from_address", "credentials", "settings"),
	}), &e)
	return
}

// Update an email provider.
//
// See: https://auth0.com/docs/api/management/v2#!/Emails/patch_provider
func (m *EmailManager) Update(e *Email) (err error) {
	return m.patch(m.uri("emails", "provider"), e)
}

// Delete the email provider.
//
// See: https://auth0.com/docs/api/management/v2#!/Emails/delete_provider
func (m *EmailManager) Delete() (err error) {
	return m.delete(m.uri("emails", "provider"))
}
