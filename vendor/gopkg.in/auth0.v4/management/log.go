package management

import (
	"time"
)

var logTypeName = map[string]string{
	"s":         "Success Login",
	"ssa":       "Success Silent Auth",
	"fsa":       "Failed Silent Auth",
	"seacft":    "Success Exchange (Authorization Code for Access Token)",
	"feacft":    "Failed Exchange (Authorization Code for Access Token)",
	"seccft":    "Success Exchange (Client Credentials for Access Token)",
	"feccft":    "Failed Exchange (Client Credentials for Access Token)",
	"sepft":     "Success Exchange (Password for Access Token)",
	"fepft":     "Failed Exchange (Password for Access Token)",
	"f":         "Failed Login",
	"w":         "Warnings During Login",
	"du":        "Deleted User",
	"fu":        "Failed Login (invalid email/username)",
	"fp":        "Failed Login (wrong password)",
	"fc":        "Failed by Connector",
	"fco":       "Failed by CORS",
	"con":       "Connector Online",
	"coff":      "Connector Offline",
	"fcpro":     "Failed Connector Provisioning",
	"ss":        "Success Signup",
	"fs":        "Failed Signup",
	"cs":        "Code Sent",
	"cls":       "Code/Link Sent",
	"sv":        "Success Verification Email",
	"fv":        "Failed Verification Email",
	"scp":       "Success Change Password",
	"fcp":       "Failed Change Password",
	"sce":       "Success Change Email",
	"fce":       "Failed Change Email",
	"scu":       "Success Change Username",
	"fcu":       "Failed Change Username",
	"scpn":      "Success Change Phone Number",
	"fcpn":      "Failed Change Phone Number",
	"svr":       "Success Verification Email Request",
	"fvr":       "Failed Verification Email Request",
	"scpr":      "Success Change Password Request",
	"fcpr":      "Failed Change Password Request",
	"fn":        "Failed Sending Notification",
	"sapi":      "API Operation",
	"fapi":      "Failed API Operation",
	"limit_wc":  "Blocked Account",
	"limit_mu":  "Blocked IP Address",
	"limit_ui":  "Too Many Calls to /userinfo",
	"api_limit": "Rate Limit On API",
	"sdu":       "Successful User Deletion",
	"fdu":       "Failed User Deletion",
	"slo":       "Success Logout",
	"flo":       "Failed Logout",
	"sd":        "Success Delegation",
	"fd":        "Failed Delegation",
	"fcoa":      "Failed Cross Origin Authentication",
	"scoa":      "Success Cross Origin Authentication",
}

type Log struct {
	ID    *string `json:"_id"`
	LogID *string `json:"log_id"`

	// The date when the event was created
	Date *time.Time `json:"date"`

	// The log event type
	Type *string `json:"type"`

	// The id of the client
	ClientID *string `json:"client_id"`

	// The name of the client
	ClientName *string `json:"client_name"`

	// The IP of the log event source
	IP *string `json:"ip"`

	LocationInfo map[string]interface{} `json:"location_info"`
	Details      map[string]interface{} `json:"details"`

	// The user's unique identifier
	UserID *string `json:"user_id"`
}

func (l *Log) TypeName() string {
	if l.Type == nil {
		return ""
	}
	if name, ok := logTypeName[*l.Type]; ok {
		return name
	}
	return ""
}

type LogManager struct {
	*Management
}

func newLogManager(m *Management) *LogManager {
	return &LogManager{m}
}

// Retrieves the data related to the log entry identified by id. This returns a
// single log entry representation as specified in the schema.
//
// See: https://auth0.com/docs/api/management/v2#!/Logs/get_logs_by_id
func (m *LogManager) Read(id string) (l *Log, err error) {
	err = m.get(m.uri("logs", id), &l)
	return
}

// List all log entries that match the specified search criteria (or lists all
// log entries if no criteria are used). Set custom search criteria using the
// `q` parameter, or search from a specific log id ("search from checkpoint").
//
// For more information on all possible event types, their respective acronyms
// and descriptions, Log Data Event Listing.
//
// See: https://auth0.com/docs/api/management/v2#!/Logs/get_logs
func (m *LogManager) List(opts ...ListOption) (l []*Log, err error) {
	err = m.get(m.uri("logs")+m.q(opts), &l)
	return
}

// Search is an alias for List
func (m *LogManager) Search(opts ...ListOption) ([]*Log, error) {
	return m.List(opts...)
}
