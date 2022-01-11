package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/session"
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
`, []dataBrokerRecord{}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "any", "dc1"),
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "any", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1"},
			&device.Enrollment{Id: "de1"},
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "any", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1"},
			&device.Enrollment{Id: "de1"},
			&device.Credential{Id: "dc2", EnrollmentId: "de2"},
			&device.Enrollment{Id: "de2"},
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "any", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1"},
			&device.Enrollment{Id: "de1", ApprovedBy: "u1"},
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "any", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1"},
			&device.Enrollment{Id: "de1"},
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "any", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1"},
			&device.Enrollment{Id: "de1"},
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "any", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1"},
			&device.Enrollment{Id: "de1", ApprovedBy: "u1"},
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "t1", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1", TypeId: "t1"},
			&device.Enrollment{Id: "de1", ApprovedBy: "u1"},
		}, Input{Session: InputSession{ID: "s1"}})
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
`, []dataBrokerRecord{
			mkDeviceSession("s1", "t1", "dc1"),
			&device.Credential{Id: "dc1", EnrollmentId: "de1", TypeId: "t1"},
			&device.Enrollment{Id: "de1", ApprovedBy: "u1"},
		}, Input{Session: InputSession{ID: "s1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonDeviceUnauthenticated}, M{"device_type": "t2"}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
