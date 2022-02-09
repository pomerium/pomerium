package sessions

// State is our object that keeps track of a user's session state
type State struct {
	// ID is the session id.
	ID string `json:"jti,omitempty"`
	// DatabrokerServerVersion tracks the last referenced databroker server version
	// for the saved session.
	DatabrokerServerVersion uint64 `json:"databroker_server_version,omitempty"`
	// DatabrokerRecordVersion tracks the last referenced databroker record version
	// for the saved session.
	DatabrokerRecordVersion uint64 `json:"databroker_record_version,omitempty"`
}
