package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/policy/input"
)

func TestDevice(t *testing.T) {
	mkDeviceSession := func(sessionID, deviceType, deviceCredentialID string) *session.Session {
		return &session.Session{
			Id: sessionID,
			DeviceCredentials: []*session.Session_DeviceCredential{
				{TypeId: deviceType, Credential: &session.Session_DeviceCredential_Id{Id: deviceCredentialID}},
			},
		}
	}

	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        is: dc1
`, nil, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonUserUnauthenticated}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("no device credential", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        is: dc1
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "any", "dc1")),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonDeviceUnauthenticated}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("allowed by is", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        is: dc1
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "any", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1"}),
			makeRecord(&device.Enrollment{Id: "de1"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonDeviceOK}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("not allowed by is", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        is: dc2
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "any", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1"}),
			makeRecord(&device.Enrollment{Id: "de1"}),
			makeRecord(&device.Credential{Id: "dc2", EnrollmentId: "de2"}),
			makeRecord(&device.Enrollment{Id: "de2"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonDeviceUnauthorized}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("allowed by approved", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        approved: true
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "any", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1"}),
			makeRecord(&device.Enrollment{Id: "de1", ApprovedBy: "u1"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonDeviceOK}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("not allowed by approved", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        approved: true
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "any", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1"}),
			makeRecord(&device.Enrollment{Id: "de1"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonDeviceUnauthorized}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("allowed by not approved", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        approved: false
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "any", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1"}),
			makeRecord(&device.Enrollment{Id: "de1"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonDeviceOK}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("not allowed by not approved", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        approved: false
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "any", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1"}),
			makeRecord(&device.Enrollment{Id: "de1", ApprovedBy: "u1"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonDeviceUnauthorized}, M{"device_type": "any"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("allowed by type", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        type: t1
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "t1", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1", TypeId: "t1"}),
			makeRecord(&device.Enrollment{Id: "de1", ApprovedBy: "u1"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonDeviceOK}, M{"device_type": "t1"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("not allowed by type", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - device:
        type: t2
`, []*databroker.Record{
			makeRecord(mkDeviceSession("s1", "t1", "dc1")),
			makeRecord(&device.Credential{Id: "dc1", EnrollmentId: "de1", TypeId: "t1"}),
			makeRecord(&device.Enrollment{Id: "de1", ApprovedBy: "u1"}),
		}, input.PolicyRequest{Session: input.RequestSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonDeviceUnauthenticated}, M{"device_type": "t2"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
