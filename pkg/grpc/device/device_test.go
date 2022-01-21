package device

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShrinkCredential(t *testing.T) {
	t.Run("authenticate response", func(t *testing.T) {
		credential := &Credential{
			Id:           "c1",
			TypeId:       "t1",
			EnrollmentId: "e1",
			UserId:       "u1",
			Specifier: &Credential_Webauthn{
				Webauthn: &Credential_WebAuthn{
					Id:        []byte{0, 1, 2},
					PublicKey: []byte{3, 4, 5},

					RegisterOptions:  bytes.Repeat([]byte{1}, 10),
					RegisterResponse: bytes.Repeat([]byte{2}, 10),
					AuthenticateResponse: [][]byte{
						bytes.Repeat([]byte{3}, 64*1024),
						bytes.Repeat([]byte{4}, 64*1024),
						bytes.Repeat([]byte{5}, 64*1024),
						bytes.Repeat([]byte{6}, 64*1024),
						bytes.Repeat([]byte{7}, 64*1024),
						bytes.Repeat([]byte{8}, 64*1024),
					},
				},
			},
		}
		shrinkCredential(credential)

		assert.Equal(t, "c1", credential.GetId())
		assert.Equal(t, "t1", credential.GetTypeId())
		assert.Equal(t, "e1", credential.GetEnrollmentId())
		assert.Equal(t, "u1", credential.GetUserId())
		assert.Equal(t, []byte{0, 1, 2}, credential.GetWebauthn().GetId())
		assert.Equal(t, []byte{3, 4, 5}, credential.GetWebauthn().GetPublicKey())
		assert.Equal(t, bytes.Repeat([]byte{1}, 10), credential.GetWebauthn().GetRegisterOptions())
		assert.Equal(t, bytes.Repeat([]byte{2}, 10), credential.GetWebauthn().GetRegisterResponse())
		assert.Equal(t, [][]byte{
			bytes.Repeat([]byte{6}, 64*1024),
			bytes.Repeat([]byte{7}, 64*1024),
			bytes.Repeat([]byte{8}, 64*1024),
		}, credential.GetWebauthn().GetAuthenticateResponse())
	})
	t.Run("register response", func(t *testing.T) {
		credential := &Credential{
			Id:           "c1",
			TypeId:       "t1",
			EnrollmentId: "e1",
			UserId:       "u1",
			Specifier: &Credential_Webauthn{
				Webauthn: &Credential_WebAuthn{
					Id:        []byte{0, 1, 2},
					PublicKey: []byte{3, 4, 5},

					RegisterOptions:  bytes.Repeat([]byte{1}, 10),
					RegisterResponse: bytes.Repeat([]byte{2}, 256*1024),
				},
			},
		}
		shrinkCredential(credential)

		assert.Equal(t, "c1", credential.GetId())
		assert.Equal(t, "t1", credential.GetTypeId())
		assert.Equal(t, "e1", credential.GetEnrollmentId())
		assert.Equal(t, "u1", credential.GetUserId())
		assert.Equal(t, []byte{0, 1, 2}, credential.GetWebauthn().GetId())
		assert.Equal(t, []byte{3, 4, 5}, credential.GetWebauthn().GetPublicKey())
		assert.Equal(t, bytes.Repeat([]byte{1}, 10), credential.GetWebauthn().GetRegisterOptions())
		assert.Empty(t, credential.GetWebauthn().GetRegisterResponse())
		assert.Empty(t, credential.GetWebauthn().GetAuthenticateResponse())
	})
	t.Run("register options", func(t *testing.T) {
		credential := &Credential{
			Id:           "c1",
			TypeId:       "t1",
			EnrollmentId: "e1",
			UserId:       "u1",
			Specifier: &Credential_Webauthn{
				Webauthn: &Credential_WebAuthn{
					Id:        []byte{0, 1, 2},
					PublicKey: []byte{3, 4, 5},

					RegisterOptions: bytes.Repeat([]byte{1}, 256*1024),
				},
			},
		}
		shrinkCredential(credential)

		assert.Equal(t, "c1", credential.GetId())
		assert.Equal(t, "t1", credential.GetTypeId())
		assert.Equal(t, "e1", credential.GetEnrollmentId())
		assert.Equal(t, "u1", credential.GetUserId())
		assert.Equal(t, []byte{0, 1, 2}, credential.GetWebauthn().GetId())
		assert.Equal(t, []byte{3, 4, 5}, credential.GetWebauthn().GetPublicKey())
		assert.Empty(t, credential.GetWebauthn().GetRegisterOptions())
		assert.Empty(t, credential.GetWebauthn().GetRegisterResponse())
		assert.Empty(t, credential.GetWebauthn().GetAuthenticateResponse())
	})
}
