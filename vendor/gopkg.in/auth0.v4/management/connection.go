package management

import (
	"encoding/json"
	"sort"
	"strings"

	"gopkg.in/auth0.v4/internal/tag"
)

const (
	ConnectionStrategyAuth0               = "auth0"
	ConnectionStrategyGoogleOAuth2        = "google-oauth2"
	ConnectionStrategyFacebook            = "facebook"
	ConnectionStrategyApple               = "apple"
	ConnectionStrategyLinkedin            = "linkedin"
	ConnectionStrategyGitHub              = "github"
	ConnectionStrategyWindowsLive         = "windowslive"
	ConnectionStrategySalesforce          = "salesforce"
	ConnectionStrategySalesforceCommunity = "salesforce-community"
	ConnectionStrategySalesforceSandbox   = "salesforce-sandbox"
	ConnectionStrategyEmail               = "email"
	ConnectionStrategySMS                 = "sms"
	ConnectionStrategyOIDC                = "oidc"
	ConnectionStrategyOAuth2              = "oauth2"
	ConnectionStrategyAD                  = "ad"
	ConnectionStrategyAzureAD             = "waad"
	ConnectionStrategySAML                = "samlp"
)

type Connection struct {
	// A generated string identifying the connection.
	ID *string `json:"id,omitempty"`

	// The name of the connection. Must start and end with an alphanumeric
	// character and can only contain alphanumeric characters and '-'. Max
	// length 128.
	Name        *string `json:"name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`

	// The identity provider identifier for the connection. Can be any of the
	// following:
	//
	// "ad", "adfs", "amazon", "dropbox", "bitbucket", "aol", "auth0-adldap",
	// "auth0-oidc", "auth0", "baidu", "bitly", "box", "custom", "daccount",
	// "dwolla", "email", "evernote-sandbox", "evernote", "exact", "facebook",
	// "fitbit", "flickr", "github", "google-apps", "google-oauth2", "guardian",
	//  "instagram", "ip", "linkedin", "miicard", "oauth1", "oauth2",
	// "office365", "paypal", "paypal-sandbox", "pingfederate",
	// "planningcenter", "renren", "salesforce-community", "salesforce-sandbox",
	//  "salesforce", "samlp", "sharepoint", "shopify", "sms", "soundcloud",
	// "thecity-sandbox", "thecity", "thirtysevensignals", "twitter", "untappd",
	//  "vkontakte", "waad", "weibo", "windowslive", "wordpress", "yahoo",
	// "yammer" or "yandex".
	Strategy *string `json:"strategy,omitempty"`

	// True if the connection is domain level
	IsDomainConnection *bool `json:"is_domain_connection,omitempty"`

	// Options for validation.
	Options    interface{}     `json:"-"`
	RawOptions json.RawMessage `json:"options,omitempty"`

	// The identifiers of the clients for which the connection is to be
	// enabled. If the array is empty or the property is not specified, no
	// clients are enabled.
	EnabledClients []interface{} `json:"enabled_clients,omitempty"`

	// Defines the realms for which the connection will be used (ie: email
	// domains). If the array is empty or the property is not specified, the
	// connection name will be added as realm.
	Realms []interface{} `json:"realms,omitempty"`

	Metadata *interface{} `json:"metadata,omitempty"`
}

func (c *Connection) MarshalJSON() ([]byte, error) {

	type connection Connection

	if c.Options != nil {
		b, err := json.Marshal(c.Options)
		if err != nil {
			return nil, err
		}
		c.RawOptions = b
	}

	return json.Marshal((*connection)(c))
}

func (c *Connection) UnmarshalJSON(b []byte) error {

	type connection Connection

	err := json.Unmarshal(b, (*connection)(c))
	if err != nil {
		return err
	}

	if c.Strategy != nil {

		var v interface{}

		switch *c.Strategy {
		case ConnectionStrategyAuth0:
			v = &ConnectionOptions{}
		case ConnectionStrategyGoogleOAuth2:
			v = &ConnectionOptionsGoogleOAuth2{}
		case ConnectionStrategyFacebook:
			v = &ConnectionOptionsFacebook{}
		case ConnectionStrategyApple:
			v = &ConnectionOptionsApple{}
		case ConnectionStrategyLinkedin:
			v = &ConnectionOptionsLinkedin{}
		case ConnectionStrategyGitHub:
			v = &ConnectionOptionsGitHub{}
		case ConnectionStrategyWindowsLive:
			v = &ConnectionOptionsWindowsLive{}
		case ConnectionStrategySalesforce,
			ConnectionStrategySalesforceCommunity,
			ConnectionStrategySalesforceSandbox:
			v = &ConnectionOptionsSalesforce{}
		case ConnectionStrategyEmail:
			v = &ConnectionOptionsEmail{}
		case ConnectionStrategySMS:
			v = &ConnectionOptionsSMS{}
		case ConnectionStrategyOIDC:
			v = &ConnectionOptionsOIDC{}
		case ConnectionStrategyOAuth2:
			v = &ConnectionOptionsOAuth2{}
		case ConnectionStrategyAD:
			v = &ConnectionOptionsAD{}
		case ConnectionStrategyAzureAD:
			v = &ConnectionOptionsAzureAD{}
		case ConnectionStrategySAML:
			v = &ConnectionOptionsSAML{}
		default:
			v = make(map[string]interface{})
		}

		err = json.Unmarshal(c.RawOptions, &v)
		if err != nil {
			return err
		}

		c.Options = v
	}

	return nil
}

type ConnectionOptions struct {

	// Options for multifactor authentication. Can be used to set active and
	// return_enroll_settings.
	MFA map[string]interface{} `json:"mfa,omitempty"`

	// Options for validation.
	Validation map[string]interface{} `json:"validation,omitempty"`

	// Password strength level, can be one of:
	// "none", "low", "fair", "good", "excellent" or null.
	PasswordPolicy *string `json:"passwordPolicy,omitempty"`

	// Options for password history policy.
	PasswordHistory map[string]interface{} `json:"password_history,omitempty"`

	// Options for password expiration policy.
	PasswordNoPersonalInfo map[string]interface{} `json:"password_no_personal_info,omitempty"`

	// Options for password dictionary policy.
	PasswordDictionary map[string]interface{} `json:"password_dictionary,omitempty"`

	// Options for password complexity options.
	PasswordComplexityOptions map[string]interface{} `json:"password_complexity_options,omitempty"`

	EnabledDatabaseCustomization *bool `json:"enabledDatabaseCustomization,omitempty"`

	BruteForceProtection *bool `json:"brute_force_protection,omitempty"`

	ImportMode *bool `json:"import_mode,omitempty"`

	DisableSignup *bool `json:"disable_signup,omitempty"`

	RequiresUsername *bool `json:"requires_username,omitempty"`

	// Scripts for the connection
	// Allowed keys are: "get_user", "login", "create", "verify", "change_password", "delete" or "change_email".
	CustomScripts map[string]interface{} `json:"customScripts,omitempty"`
	// configuration variables that can be used in custom scripts
	Configuration map[string]interface{} `json:"configuration,omitempty"`

	StrategyVersion *int `json:"strategy_version,omitempty"`
}

type ConnectionOptionsGoogleOAuth2 struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	AllowedAudiences []interface{} `json:"allowed_audiences,omitempty"`

	Email                  *bool `json:"email,omitempty" scope:"email"`
	Profile                *bool `json:"profile,omitempty" scope:"profile"`
	Contacts               *bool `json:"contacts,omitempty" scope:"contacts"`
	Blogger                *bool `json:"blogger,omitempty" scope:"blogger"`
	Calendar               *bool `json:"calendar,omitempty" scope:"calendar"`
	Gmail                  *bool `json:"gmail,omitempty" scope:"gmail"`
	GooglePlus             *bool `json:"google_plus,omitempty" scope:"google_plus"`
	Orkut                  *bool `json:"orkut,omitempty" scope:"orkut"`
	PicasaWeb              *bool `json:"picasa_web,omitempty" scope:"picasa_web"`
	Tasks                  *bool `json:"tasks,omitempty" scope:"tasks"`
	Youtube                *bool `json:"youtube,omitempty" scope:"youtube"`
	AdsenseManagement      *bool `json:"adsense_management,omitempty" scope:"adsense_management"`
	GoogleAffiliateNetwork *bool `json:"google_affiliate_network,omitempty" scope:"google_affiliate_network"`
	Analytics              *bool `json:"analytics,omitempty" scope:"analytics"`
	GoogleBooks            *bool `json:"google_books,omitempty" scope:"google_books"`
	GoogleCloudStorage     *bool `json:"google_cloud_storage,omitempty" scope:"google_cloud_storage"`
	ContentAPIForShopping  *bool `json:"content_api_for_shopping,omitempty" scope:"content_api_for_shopping"`
	ChromeWebStore         *bool `json:"chrome_web_store,omitempty" scope:"chrome_web_store"`
	DocumentList           *bool `json:"document_list,omitempty" scope:"document_list"`
	GoogleDrive            *bool `json:"google_drive,omitempty" scope:"google_drive"`
	GoogleDriveFiles       *bool `json:"google_drive_files,omitempty" scope:"google_drive_files"`
	LatitudeBest           *bool `json:"latitude_best,omitempty" scope:"latitude_best"`
	LatitudeCity           *bool `json:"latitude_city,omitempty" scope:"latitude_city"`
	Moderator              *bool `json:"moderator,omitempty" scope:"moderator"`
	Sites                  *bool `json:"sites,omitempty" scope:"sites"`
	Spreadsheets           *bool `json:"spreadsheets,omitempty" scope:"spreadsheets"`
	URLShortener           *bool `json:"url_shortener,omitempty" scope:"url_shortener"`
	WebmasterTools         *bool `json:"webmaster_tools,omitempty" scope:"webmaster_tools"`
	Coordinate             *bool `json:"coordinate,omitempty" scope:"coordinate"`
	CoordinateReadonly     *bool `json:"coordinate_readonly,omitempty" scope:"coordinate_readonly"`

	Scope []interface{} `json:"scope,omitempty"`
}

func (c *ConnectionOptionsGoogleOAuth2) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsGoogleOAuth2) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsFacebook struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	AllowContextProfileField *bool `json:"allow_context_profile_field,omitempty"`

	Email                       *bool `json:"email,omitempty" scope:"email"`
	GroupsAccessMemberInfo      *bool `json:"groups_access_member_info,omitempty" scope:"groups_access_member_info"`
	PublishToGroups             *bool `json:"publish_to_groups,omitempty" scope:"publish_to_groups"`
	UserAgeRange                *bool `json:"user_age_range,omitempty" scope:"user_age_range"`
	UserBirthday                *bool `json:"user_birthday,omitempty" scope:"user_birthday"`
	AdsManagement               *bool `json:"ads_management,omitempty" scope:"ads_management"`
	AdsRead                     *bool `json:"ads_read,omitempty" scope:"ads_read"`
	ReadAudienceNetworkInsights *bool `json:"read_audience_network_insights,omitempty" scope:"read_audience_network_insights"`
	ReadInsights                *bool `json:"read_insights,omitempty" scope:"read_insights"`
	ManageNotifications         *bool `json:"manage_notifications,omitempty" scope:"manage_notifications"`
	PublishActions              *bool `json:"publish_actions,omitempty" scope:"publish_actions"`
	ReadMailbox                 *bool `json:"read_mailbox,omitempty" scope:"read_mailbox"`
	PublicProfile               *bool `json:"public_profile,omitempty" scope:"public_profile"`
	UserEvents                  *bool `json:"user_events,omitempty" scope:"user_events"`
	UserFriends                 *bool `json:"user_friends,omitempty" scope:"user_friends"`
	UserGender                  *bool `json:"user_gender,omitempty" scope:"user_gender"`
	UserHometown                *bool `json:"user_hometown,omitempty" scope:"user_hometown"`
	UserLikes                   *bool `json:"user_likes,omitempty" scope:"user_likes"`
	UserLink                    *bool `json:"user_link,omitempty" scope:"user_link"`
	UserLocation                *bool `json:"user_location,omitempty" scope:"user_location"`
	UserPhotos                  *bool `json:"user_photos,omitempty" scope:"user_photos"`
	UserPosts                   *bool `json:"user_posts,omitempty" scope:"user_posts"`
	UserTaggedPlaces            *bool `json:"user_tagged_places,omitempty" scope:"user_tagged_places"`
	UserVideos                  *bool `json:"user_videos,omitempty" scope:"user_videos"`
	BusinessManagement          *bool `json:"business_management,omitempty" scope:"business_management"`
	LeadsRetrieval              *bool `json:"leads_retrieval,omitempty" scope:"leads_retrieval"`
	ManagePages                 *bool `json:"manage_pages,omitempty" scope:"manage_pages"`
	PagesManageCTA              *bool `json:"pages_manage_cta,omitempty" scope:"pages_manage_cta"`
	PagesManageInstantArticles  *bool `json:"pages_manage_instant_articles,omitempty" scope:"pages_manage_instant_articles"`
	PagesShowList               *bool `json:"pages_show_list,omitempty" scope:"pages_show_list"`
	PagesMessaging              *bool `json:"pages_messaging,omitempty" scope:"pages_messaging"`
	PagesMessagingPhoneNumber   *bool `json:"pages_messaging_phone_number,omitempty" scope:"pages_messaging_phone_number"`
	PagesMessagingSubscriptions *bool `json:"pages_messaging_subscriptions,omitempty" scope:"pages_messaging_subscriptions"`
	PublishPages                *bool `json:"publish_pages,omitempty" scope:"publish_pages"`
	PublishVideo                *bool `json:"publish_video,omitempty" scope:"publish_video"`
	ReadPageMailboxes           *bool `json:"read_page_mailboxes,omitempty" scope:"read_page_mailboxes"`
	ReadStream                  *bool `json:"read_stream,omitempty" scope:"read_stream"`
	UserGroups                  *bool `json:"user_groups,omitempty" scope:"user_groups"`
	UserManagedGroups           *bool `json:"user_managed_groups,omitempty" scope:"user_managed_groups"`
	UserStatus                  *bool `json:"user_status,omitempty" scope:"user_status"`

	// Scope is a comma separated list of scopes.
	Scope *string `json:"scope,omitempty"`
}

func (c *ConnectionOptionsFacebook) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsFacebook) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsApple struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"app_secret,omitempty"`

	TeamID *string `json:"team_id,omitempty"`
	KeyID  *string `json:"kid,omitempty"`

	Name  *bool `json:"name,omitempty" scope:"name"`
	Email *bool `json:"email,omitempty" scope:"email"`

	Scope *string `json:"scope,omitempty"`
}

func (c *ConnectionOptionsApple) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsApple) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsLinkedin struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	StrategyVersion *int `json:"strategy_version,omitempty"`

	Email        *bool `json:"email,omitempty" scope:"email"`
	Profile      *bool `json:"profile,omitempty" scope:"profile"`
	BasicProfile *bool `json:"basic_profile,omitempty" scope:"basic_profile"`

	Scope []interface{} `json:"scope,omitempty"`

	SetUserAttributes *string `json:"set_user_root_attributes,omitempty"`
}

func (c *ConnectionOptionsLinkedin) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsLinkedin) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsGitHub struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	Email          *bool `json:"email,omitempty" scope:"email"`
	ReadUser       *bool `json:"read_user,omitempty" scope:"read_user"`
	Follow         *bool `json:"follow,omitempty" scope:"follow"`
	PublicRepo     *bool `json:"public_repo,omitempty" scope:"public_repo"`
	Repo           *bool `json:"repo,omitempty" scope:"repo"`
	RepoDeployment *bool `json:"repo_deployment,omitempty" scope:"repo_deployment"`
	RepoStatus     *bool `json:"repo_status,omitempty" scope:"repo_status"`
	DeleteRepo     *bool `json:"delete_repo,omitempty" scope:"delete_repo"`
	Notifications  *bool `json:"notifications,omitempty" scope:"notifications"`
	Gist           *bool `json:"gist,omitempty" scope:"gist"`
	ReadRepoHook   *bool `json:"read_repo_hook,omitempty" scope:"read_repo_hook"`
	WriteRepoHook  *bool `json:"write_repo_hook,omitempty" scope:"write_repo_hook"`
	AdminRepoHook  *bool `json:"admin_repo_hook,omitempty" scope:"admin_repo_hook"`
	ReadOrg        *bool `json:"read_org,omitempty" scope:"read_org"`
	AdminOrg       *bool `json:"admin_org,omitempty" scope:"admin_org"`
	ReadPublicKey  *bool `json:"read_public_key,omitempty" scope:"read_public_key"`
	WritePublicKey *bool `json:"write_public_key,omitempty" scope:"write_public_key"`
	AdminPublicKey *bool `json:"admin_public_key,omitempty" scope:"admin_public_key"`
	WriteOrg       *bool `json:"write_org,omitempty" scope:"write_org"`
	Profile        *bool `json:"profile,omitempty" scope:"profile"`

	Scope []interface{} `json:"scope,omitempty"`

	SetUserAttributes *string `json:"set_user_root_attributes,omitempty"`
}

func (c *ConnectionOptionsGitHub) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsGitHub) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsEmail struct {
	Name  *string                         `json:"name,omitempty"`
	Email *ConnectionOptionsEmailSettings `json:"email,omitempty"`

	OTP *ConnectionOptionsOTP `json:"totp,omitempty"`

	AuthParams map[string]string `json:"authParams,omitempty"`

	DisableSignup        *bool `json:"disable_signup,omitempty"`
	BruteForceProtection *bool `json:"brute_force_protection,omitempty"`
}

type ConnectionOptionsEmailSettings struct {
	Syntax  *string `json:"syntax,omitempty"`
	From    *string `json:"from,omitempty"`
	Subject *string `json:"subject,omitempty"`
	Body    *string `json:"body,omitempty"`
}

type ConnectionOptionsOTP struct {
	TimeStep *int `json:"time_step,omitempty"`
	Length   *int `json:"length,omitempty"`
}

type ConnectionOptionsSMS struct {
	Name     *string `json:"name,omitempty"`
	From     *string `json:"from,omitempty"`
	Syntax   *string `json:"syntax,omitempty"`
	Template *string `json:"template,omitempty"`

	OTP *ConnectionOptionsOTP `json:"totp,omitempty"`

	AuthParams map[string]string `json:"authParams,omitempty"`

	TwilioSID           *string `json:"twilio_sid"`
	TwilioToken         *string `json:"twilio_token"`
	MessagingServiceSID *string `json:"messaging_service_sid"`

	DisableSignup        *bool `json:"disable_signup,omitempty"`
	BruteForceProtection *bool `json:"brute_force_protection,omitempty"`
}

type ConnectionOptionsWindowsLive struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	StrategyVersion *int `json:"strategy_version,omitempty"`

	OfflineAccess   *bool `json:"offline_access,omitempty" scope:"offline_access"`
	UserUpdate      *bool `json:"graph_user_update,omitempty" scope:"graph_user_update"`
	UserActivity    *bool `json:"graph_user_activity,omitempty" scope:"graph_user_activity"`
	Device          *bool `json:"graph_device,omitempty" scope:"graph_device"`
	Emails          *bool `json:"graph_emails,omitempty" scope:"graph_emails"`
	NotesUpdate     *bool `json:"graph_notes_update,omitempty" scope:"graph_notes_update"`
	User            *bool `json:"graph_user,omitempty" scope:"graph_user"`
	DeviceCommand   *bool `json:"graph_device_command,omitempty" scope:"graph_device_command"`
	EmailsUpdate    *bool `json:"graph_emails_update,omitempty" scope:"graph_emails_update"`
	Calendars       *bool `json:"graph_calendars,omitempty" scope:"graph_calendars"`
	CalendarsUpdate *bool `json:"graph_calendars_update,omitempty" scope:"graph_calendars_update"`
	Contacts        *bool `json:"graph_contacts,omitempty" scope:"graph_contacts"`
	ContactsUpdate  *bool `json:"graph_contacts_update,omitempty" scope:"graph_contacts_update"`
	Files           *bool `json:"graph_files,omitempty" scope:"graph_files"`
	FilesAll        *bool `json:"graph_files_all,omitempty" scope:"graph_files_all"`
	FilesUpdate     *bool `json:"graph_files_update,omitempty" scope:"graph_files_update"`
	FilesAllUpdate  *bool `json:"graph_files_all_update,omitempty" scope:"graph_files_all_update"`
	Notes           *bool `json:"graph_notes,omitempty" scope:"graph_notes"`
	NotesCreate     *bool `json:"graph_notes_create,omitempty" scope:"graph_notes_create"`
	Tasks           *bool `json:"graph_tasks,omitempty" scope:"graph_tasks"`
	TasksUpdate     *bool `json:"graph_tasks_update,omitempty" scope:"graph_tasks_update"`
	Signin          *bool `json:"signin,omitempty" scope:"signin"`

	Scope []interface{} `json:"scope,omitempty"`

	SetUserAttributes *string `json:"set_user_root_attributes,omitempty"`
}

func (c *ConnectionOptionsWindowsLive) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsWindowsLive) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsSalesforce struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	Profile *bool `json:"profile,omitempty" scope:"profile"`

	Scope []interface{} `json:"scope,omitempty"`

	CommunityBaseURL  *string `json:"community_base_url,omitempty"`
	SetUserAttributes *string `json:"set_user_root_attributes,omitempty"`
}

func (c *ConnectionOptionsSalesforce) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsSalesforce) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsOIDC struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	TenantDomain  *string       `json:"tenant_domain,omitempty"`
	DomainAliases []interface{} `json:"domain_aliases,omitempty"`
	LogoURL       *string       `json:"icon_url,omitempty"`

	DiscoveryURL          *string `json:"discovery_url"`
	AuthorizationEndpoint *string `json:"authorization_endpoint"`
	Issuer                *string `json:"issuer"`
	JWKSURI               *string `json:"jwks_uri"`
	Type                  *string `json:"type"`
	UserInfoEndpoint      *string `json:"userinfo_endpoint"`
	TokenEndpoint         *string `json:"token_endpoint"`

	Scope *string `json:"scope,omitempty"`
}

func (c *ConnectionOptionsOIDC) Scopes() []string {
	return strings.Fields(c.GetScope())
}

func (c *ConnectionOptionsOIDC) SetScopes(enable bool, scopes ...string) {
	scopeMap := make(map[string]bool)
	for _, scope := range c.Scopes() {
		scopeMap[scope] = true
	}
	for _, scope := range scopes {
		scopeMap[scope] = enable
	}
	scopeSlice := make([]string, 0, len(scopeMap))
	for scope, enabled := range scopeMap {
		if enabled {
			scopeSlice = append(scopeSlice, scope)
		}
	}
	sort.Strings(scopeSlice)
	scope := strings.Join(scopeSlice, " ")
	c.Scope = &scope
}

type ConnectionOptionsOAuth2 struct {
	ClientID              *string `json:"client_id,omitempty"`
	ClientSecret          *string `json:"client_secret,omitempty"`
	AuthorizationEndpoint *string `json:"authorization_endpoint"`
	TokenEndpoint         *string `json:"token_endpoint"`
	Scope                 *string `json:"scope,omitempty"`

	// Scripts for the connection
	// Allowed keys are: "fetchUserProfile"
	Scripts map[string]interface{} `json:"scripts,omitempty"`
}

func (c *ConnectionOptionsOAuth2) Scopes() []string {
	return strings.Fields(c.GetScope())
}

func (c *ConnectionOptionsOAuth2) SetScopes(enable bool, scopes ...string) {
	scopeMap := make(map[string]bool)
	for _, scope := range c.Scopes() {
		scopeMap[scope] = true
	}
	for _, scope := range scopes {
		scopeMap[scope] = enable
	}
	scopeSlice := make([]string, 0, len(scopeMap))
	for scope, enabled := range scopeMap {
		if enabled {
			scopeSlice = append(scopeSlice, scope)
		}
	}
	sort.Strings(scopeSlice)
	scope := strings.Join(scopeSlice, " ")
	c.Scope = &scope
}

type ConnectionOptionsAD struct {
	TenantDomain  *string       `json:"tenant_domain,omitempty"`
	DomainAliases []interface{} `json:"domain_aliases,omitempty"`
	LogoURL       *string       `json:"icon_url,omitempty"`
	IPs           []interface{} `json:"ips"`

	CertAuth             *bool `json:"certAuth,omitempty"`
	Kerberos             *bool `json:"kerberos,omitempty"`
	DisableCache         *bool `json:"disable_cache,omitempty"`
	BruteForceProtection *bool `json:"brute_force_protection,omitempty"`

	SetUserAttributes *string `json:"set_user_root_attributes,omitempty"`
}

type ConnectionOptionsAzureAD struct {
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`

	AppID         *string       `json:"app_id,omitempty"`
	TenantDomain  *string       `json:"tenant_domain,omitempty"`
	Domain        *string       `json:"domain,omitempty"`
	DomainAliases []interface{} `json:"domain_aliases,omitempty"`
	LogoURL       *string       `json:"icon_url,omitempty"`

	IdentityAPI *string `json:"identity_api"`

	WAADProtocol       *string `json:"waad_protocol,omitempty"`
	WAADCommonEndpoint *bool   `json:"waad_common_endpoint,omitempty"`

	UseWSFederation     *bool   `json:"use_wsfed,omitempty"`
	UseCommonEndpoint   *bool   `json:"useCommonEndpoint,omitempty"`
	EnableUsersAPI      *bool   `json:"api_enable_users,omitempty"`
	MaxGroupsToRetrieve *string `json:"max_groups_to_retrieve,omitempty"`

	BasicProfile    *bool `json:"basic_profile,omitempty" scope:"basic_profile"`
	ExtendedProfile *bool `json:"ext_profile,omitempty" scope:"ext_profile"`
	Groups          *bool `json:"ext_groups,omitempty" scope:"ext_groups"`
	NestedGroups    *bool `json:"ext_nested_groups,omitempty" scope:"ext_nested_groups"`
	Admin           *bool `json:"ext_admin,omitempty" scope:"ext_admin"`
	IsSuspended     *bool `json:"ext_is_suspended,omitempty" scope:"ext_is_suspended"`
	AgreedTerms     *bool `json:"ext_agreed_terms,omitempty" scope:"ext_agreed_terms"`
	AssignedPlans   *bool `json:"ext_assigned_plans,omitempty" scope:"ext_assigned_plans"`
}

func (c *ConnectionOptionsAzureAD) Scopes() []string {
	return tag.Scopes(c)
}

func (c *ConnectionOptionsAzureAD) SetScopes(enable bool, scopes ...string) {
	tag.SetScopes(c, enable, scopes...)
}

type ConnectionOptionsADFS struct {
	TenantDomain  *string       `json:"tenant_domain,omitempty"`
	DomainAliases []interface{} `json:"domain_aliases,omitempty"`
	LogoURL       *string       `json:"icon_url,omitempty"`
	ADFSServer    *string       `json:"adfs_server,omitempty"`

	EnableUsersAPI *bool `json:"api_enable_users,omitempty"`

	// Set to on_first_login to avoid setting user attributes at each login.
	SetUserAttributes *string `json:"set_user_root_attributes,omitempty"`
}

type ConnectionOptionsSAML struct {
	Cert               *string                            `json:"cert,omitempty"`
	Debug              *bool                              `json:"debug,omitempty"`
	Expires            *string                            `json:"expires,omitempty"`
	IdpInitiated       *ConnectionOptionsSAMLIdpInitiated `json:"idpinitiated,omitempty"`
	SigningCert        *string                            `json:"signingCert,omitempty"`
	Thumbprints        []interface{}                      `json:"thumbprints,omitempty"`
	ProtocolBinding    *string                            `json:"protocolBinding,omitempty"`
	TenantDomain       *string                            `json:"tenant_domain,omitempty"`
	DomainAliases      []interface{}                      `json:"domain_aliases,omitempty"`
	SignInEndpoint     *string                            `json:"signInEndpoint,omitempty"`
	SignOutEndpoint    *string                            `json:"signOutEndpoint,omitempty"`
	SignatureAlgorithm *string                            `json:"signatureAlgorithm,omitempty"`
	DigestAglorithm    *string                            `json:"digestAlgorithm,omitempty"`
	MetadataXML        *string                            `json:"metadataXml,omitempty"`
	MetadataURL        *string                            `json:"metadataUrl,omitempty"`
	FieldsMap          map[string]interface{}             `json:"fieldsMap,omitempty"`
	Subject            map[string]interface{}             `json:"subject,omitempty"`
	SignSAMLRequest    *bool                              `json:"signSAMLRequest,omitempty"`
	RequestTemplate    *string                            `json:"requestTemplate,omitempty"`
	UserIDAttribute    *string                            `json:"user_id_attribute,omitempty"`
	LogoURL            *string                            `json:"icon_url,omitempty"`
}

type ConnectionOptionsSAMLIdpInitiated struct {
	Enabled              *bool   `json:"enabled,omitempty"`
	ClientID             *string `json:"client_id,omitempty"`
	ClientProtocol       *string `json:"client_protocol,omitempty"`
	ClientAuthorizeQuery *string `json:"client_authorizequery,omitempty"`
}

type ConnectionManager struct {
	*Management
}

type ConnectionList struct {
	List
	Connections []*Connection `json:"connections"`
}

func newConnectionManager(m *Management) *ConnectionManager {
	return &ConnectionManager{m}
}

// Create a new connection.
//
// See: https://auth0.com/docs/api/management/v2#!/Connections/post_connections
func (m *ConnectionManager) Create(c *Connection) error {
	return m.post(m.uri("connections"), c)
}

// Read retrieves a connection by its id.
//
// See: https://auth0.com/docs/api/management/v2#!/Connections/get_connections_by_id
func (m *ConnectionManager) Read(id string) (c *Connection, err error) {
	err = m.get(m.uri("connections", id), &c)
	return
}

// List all connections.
//
// See: https://auth0.com/docs/api/management/v2#!/Connections/get_connections
func (m *ConnectionManager) List(opts ...ListOption) (c *ConnectionList, err error) {
	opts = m.defaults(opts)
	err = m.get(m.uri("connections")+m.q(opts), &c)
	return
}

// Update a connection.
//
// Note: if you use the options parameter, the whole options object will be
// overridden, so ensure that all parameters are present.
//
// See: https://auth0.com/docs/api/management/v2#!/Connections/patch_connections_by_id
func (m *ConnectionManager) Update(id string, c *Connection) (err error) {
	return m.patch(m.uri("connections", id), c)
}

// Delete a connection and all its users.
//
// See: https://auth0.com/docs/api/management/v2#!/Connections/delete_connections_by_id
func (m *ConnectionManager) Delete(id string) (err error) {
	return m.delete(m.uri("connections", id))
}

// ReadByName retrieves a connection by its name. This is a helper method when a
// connection id is not readily available.
func (m *ConnectionManager) ReadByName(name string) (*Connection, error) {
	c, err := m.List(Parameter("name", name))
	if err != nil {
		return nil, err
	}
	if len(c.Connections) > 0 {
		return c.Connections[0], nil
	}
	return nil, &managementError{404, "Not Found", "Connection not found"}
}
