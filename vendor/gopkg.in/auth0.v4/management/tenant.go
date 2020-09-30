package management

type Tenant struct {
	// Change password page settings
	ChangePassword *TenantChangePassword `json:"change_password,omitempty"`

	// Guardian MFA page settings
	GuardianMFAPage *TenantGuardianMFAPage `json:"guardian_mfa_page,omitempty"`

	// Default audience for API Authorization
	DefaultAudience *string `json:"default_audience,omitempty"`

	// Name of the connection that will be used for password grants at the token
	// endpoint. Only the following connection types are supported: LDAP, AD,
	// Database Connections, Passwordless, Windows Azure Active Directory, ADFS.
	DefaultDirectory *string `json:"default_directory,omitempty"`

	ErrorPage *TenantErrorPage `json:"error_page,omitempty"`

	DeviceFlow *TenantDeviceFlow `json:"device_flow,omitempty"`

	Flags *TenantFlags `json:"flags,omitempty"`

	// The friendly name of the tenant
	FriendlyName *string `json:"friendly_name,omitempty"`

	// The URL of the tenant logo (recommended size: 150x150)
	PictureURL *string `json:"picture_url,omitempty"`

	// User support email
	SupportEmail *string `json:"support_email,omitempty"`

	// User support URL
	SupportURL *string `json:"support_url,omitempty"`

	// Used to store additional metadata
	UniversalLogin *TenantUniversalLogin `json:"universal_login,omitempty"`

	// A set of URLs that are valid to redirect to after logout from Auth0.
	AllowedLogoutURLs []interface{} `json:"allowed_logout_urls,omitempty"`

	// Login session lifetime, how long the session will stay valid (unit:
	// hours).
	SessionLifetime *int `json:"session_lifetime,omitempty"`

	// Force a user to login after they have been inactive for the specified number (unit: hours)
	IdleSessionLifetime *int `json:"idle_session_lifetime,omitempty"`

	// The selected sandbox version to be used for the extensibility environment
	SandboxVersion *string `json:"sandbox_version,omitempty"`

	// A set of available sandbox versions for the extensibility environment
	SandboxVersionAvailable []interface{} `json:"sandbox_versions_available,omitempty"`

	// The default absolute redirection uri, must be https and cannot contain a
	// fragment.
	DefaultRedirectionURI *string `json:"default_redirection_uri,omitempty"`

	// Supported locales for the UI
	EnabledLocales []interface{} `json:"enabled_locales,omitempty"`
}

type TenantChangePassword struct {
	// True to use the custom change password html, false otherwise.
	Enabled *bool `json:"enabled,omitempty"`
	// Replace default change password page with a custom HTML (Liquid syntax is
	// supported).
	HTML *string `json:"html,omitempty"`
}

type TenantGuardianMFAPage struct {
	// True to use the custom html for Guardian page, false otherwise.
	Enabled *bool `json:"enabled,omitempty"`
	// Replace default Guardian page with a custom HTML (Liquid syntax is
	// supported).
	HTML *string `json:"html,omitempty"`
}

type TenantErrorPage struct {
	// Replace default error page with a custom HTML (Liquid syntax is
	// supported).
	HTML *string `json:"html,omitempty"`
	// True to show link to log as part of the default error page, false
	// otherwise (default: true).
	ShowLogLink *bool `json:"show_log_link,omitempty"`
	// Redirect to specified url instead of show the default error page
	URL *string `json:"url,omitempty"`
}

type TenantFlags struct {
	// Enables the first version of the Change Password flow. We've deprecated
	// this option and recommending a safer flow. This flag is only for
	// backwards compatibility.
	ChangePasswordFlowV1 *bool `json:"change_pwd_flow_v1,omitempty"`

	// This flag determines whether all current connections shall be enabled
	// when a new client is created. Default value is true.
	EnableClientConnections *bool `json:"enable_client_connections,omitempty"`

	// This flag enables the API section in the Auth0 Management Dashboard.
	EnableAPIsSection *bool `json:"enable_apis_section,omitempty"`

	// If set to true all Impersonation functionality is disabled for the
	// Tenant. This is a read-only attribute.
	DisableImpersonation *bool `json:"disable_impersonation,omitempty"`

	// This flag enables advanced API Authorization scenarios.
	EnablePipeline2 *bool `json:"enable_pipeline2,omitempty"`

	// This flag enables dynamic client registration.
	EnableDynamicClientRegistration *bool `json:"enable_dynamic_client_registration,omitempty"`

	// If enabled, All your email links and urls will use your configured custom
	// domain. If no custom domain is found the email operation will fail.
	EnableCustomDomainInEmails *bool `json:"enable_custom_domain_in_emails,omitempty"`

	// If enabled, users will not be prompted to confirm log in before SSO
	// redirection.
	EnableSSO *bool `json:"enable_sso,omitempty"`

	// Whether the `EnableSSO` setting can be changed.
	AllowChangingEnableSSO *bool `json:"allow_changing_enable_sso,omitempty"`

	// If enabled, activate the new look and feel for Universal Login
	UniversalLogin *bool `json:"universal_login,omitempty"`

	// If enabled, the legacy Logs Search Engine V2 will be enabled for your
	// account.
	//
	// Turn it off to opt-in for the latest Logs Search Engine V3.
	EnableLegacyLogsSearchV2 *bool `json:"enable_legacy_logs_search_v2,omitempty"`

	// If enabled, additional HTTP security headers will not be included in the
	// response to prevent embedding of the Universal Login prompts in an
	// IFRAME.
	DisableClickjackProtectionHeaders *bool `json:"disable_clickjack_protection_headers,omitempty"`

	// If enabled, this will use a generic response in the public signup API
	// which will prevent users from being able to find out if an e-mail address
	// or username has previously registered.
	EnablePublicSignupUserExistsError *bool `json:"enable_public_signup_user_exists_error,omitempty"`

	// If enabled, this will use the scope description when generating a consent
	// prompt. Otherwise the scope name is used.
	UseScopeDescriptionsForConsent *bool `json:"use_scope_descriptions_for_consent,omitempty"`
}

type TenantUniversalLogin struct {
	Colors *TenantUniversalLoginColors `json:"colors,omitempty"`
}

type TenantUniversalLoginColors struct {
	// Primary button background color
	Primary *string `json:"primary,omitempty"`

	// Background color of your login pages
	PageBackground *string `json:"page_background,omitempty"`
}

type TenantDeviceFlow struct {
	// The character set for generating a User Code ['base20' or 'digits']
	Charset *string `json:"charset,omitempty"`

	// The mask used to format the generated User Code to a friendly, readable
	// format with possible spaces or hyphens
	Mask *string `json:"mask,omitempty"`
}

type TenantManager struct {
	*Management
}

func newTenantManager(m *Management) *TenantManager {
	return &TenantManager{m}
}

// Retrieve tenant settings. A list of fields to include or exclude may also be
// specified.
//
// See: https://auth0.com/docs/api/management/v2#!/Tenants/get_settings
func (m *TenantManager) Read() (t *Tenant, err error) {
	err = m.get(m.uri("tenants", "settings"), &t)
	return
}

// Update settings for a tenant.
//
// See: https://auth0.com/docs/api/management/v2#!/Tenants/patch_settings
func (m *TenantManager) Update(t *Tenant) (err error) {
	return m.patch(m.uri("tenants", "settings"), t)
}
