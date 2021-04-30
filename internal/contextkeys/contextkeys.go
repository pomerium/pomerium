// Package contextkeys defines common context keys shared between packages
package contextkeys

type contextKey int

const (
	// DatabrokerConfigVersion identifies uint64 databroker version of the config
	DatabrokerConfigVersion contextKey = iota
)

func (x contextKey) String() string {
	return map[contextKey]string{
		DatabrokerConfigVersion: "db_config_version",
	}[x]
}
