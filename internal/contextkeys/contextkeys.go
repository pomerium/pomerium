// Package contextkeys defines common context keys shared between packages
package contextkeys

type contextKey int

const (
	// UpdateRecordsVersion identifies the uint64 databroker version of the config
	UpdateRecordsVersion contextKey = iota
)

func (x contextKey) String() string {
	return map[contextKey]string{
		UpdateRecordsVersion: "update_records_version",
	}[x]
}
