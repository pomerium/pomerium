package criteria

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestSourceIPs(t *testing.T) {
	t.Run("single IPv4 match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "1.2.3.4"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "1.2.3.4"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("single IPv4 no match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "1.2.3.4"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "1.2.3.5"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonSourceIPUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("IPv4 range match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "192.168.1.1/24"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "192.168.1.200"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("IPv4 range no match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "192.168.1.1/24"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "192.168.2.1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonSourceIPUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("single IPv6 match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "2001:db8::1"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "2001:db8::1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("single IPv6 no match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "2001:db8::1"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "2001:db8::2"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonSourceIPUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("IPv6 range match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "2001:db8::/32"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "2001:db8:1:2:3:4:5:6"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("IPv6 range no match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "2001:db8::/32"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "2001:ffff:1:2:3:4:5:6"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonSourceIPUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("list of IPs match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip:
        - "10.0.0.1"
        - "10.0.0.2"
        - "10.0.0.3"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "10.0.0.2"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("list of IPs no match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip:
        - "10.0.0.1"
        - "10.0.0.2"
        - "10.0.0.3"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "10.0.0.4"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonSourceIPUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("IPv4-mapped IPv6 range", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "::ffff:10.0.0.0/104"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "10.1.2.3"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("IPv4-mapped IPv6", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip: "::ffff:1.2.3.4"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "1.2.3.4"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("invalid IP address", func(t *testing.T) {
		_, err := generateRegoFromYAML(`
allow:
  and:
    - source_ip: not-an-ip-address
`)
		assert.ErrorContains(t, err, `expected IP or CIDR range, got: "not-an-ip-address"`)
	})
	t.Run("invalid input type", func(t *testing.T) {
		_, err := generateRegoFromYAML(`
allow:
  and:
    - source_ip:
        key: value
`)
		assert.ErrorContains(t, err, "expected string or array of strings, got: parser.Object")
	})
	t.Run("invalid list element type", func(t *testing.T) {
		_, err := generateRegoFromYAML(`
allow:
  and:
    - source_ip:
        - key: value
`)
		assert.ErrorContains(t, err, "xpected string value, got: parser.Object")
	})
}
