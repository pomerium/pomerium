package criteria

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestSSHPublicKey(t *testing.T) {
	t.Parallel()

	key1, _ := base64.StdEncoding.DecodeString("AAAAC3NzaC1lZDI1NTE5AAAAIIeAQ7VbiYJdPaxsMYTW/q5QpqtyHMtHHRBUJOcQMaLE")

	t.Run("single ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_publickey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIeAQ7VbiYJdPaxsMYTW/q5QpqtyHMtHHRBUJOcQMaLE key-1'
`, []*databroker.Record{}, Input{SSH: InputSSH{PublicKey: key1}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHPublickeyOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("single unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_publickey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPzK2WQZ0NU52W8Bk/8po+4V4oUEdCklf3GtQmiYQB/9 key-2'
`, []*databroker.Record{}, Input{SSH: InputSSH{PublicKey: key1}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHPublickeyUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("multiple ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_publickey:
        - 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIeAQ7VbiYJdPaxsMYTW/q5QpqtyHMtHHRBUJOcQMaLE key-1'
        - 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPzK2WQZ0NU52W8Bk/8po+4V4oUEdCklf3GtQmiYQB/9 key-2'
`, []*databroker.Record{}, Input{SSH: InputSSH{PublicKey: key1}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHPublickeyOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("multiple unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_publickey:
      - 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPzK2WQZ0NU52W8Bk/8po+4V4oUEdCklf3GtQmiYQB/9 key-2'
      - 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMC+uqlilwtfsI5koXGKSBU4vQRZUrse8w4+ea9BsK2v key-3'
`, []*databroker.Record{}, Input{SSH: InputSSH{PublicKey: key1}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHPublickeyUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
}

func TestSSHUserCA(t *testing.T) {
	t.Parallel()

	user1key, _ := base64.StdEncoding.DecodeString(
		"AAAAC3NzaC1lZDI1NTE5AAAAICRpwMbj13mXdSMzHJBiMLln0Wx0iCepff5N/W8vi0ta")
	user1cert, _ := base64.StdEncoding.DecodeString(
		"AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIKNKPd0B1q9Jx7h/" +
			"tnFFBtbMybwlSmxGoE308BkWuJIrAAAAICRpwMbj13mXdSMzHJBiMLln0Wx0iCepff5N" +
			"/W8vi0taAAAAAAAAAAAAAAABAAAABXVzZXIxAAAAAAAAAAAAAAAA//////////8AAAAA" +
			"AAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1m" +
			"b3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJt" +
			"aXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQy" +
			"NTUxOQAAACBIntPLN0pEWLpPTktfLuUeKloK97ysMJRvf0f1FigxJQAAAFMAAAALc3No" +
			"LWVkMjU1MTkAAABABkLudnDsTEw3aPbgqP5NvuAtZrqzknCadFMjIL+hXoFXFitJq+u9" +
			"cAl9KIE+2ZQTf2ISbrQDh8Vw+5pivxGZBA==")

	t.Run("single ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_ca: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEie08s3SkRYuk9OS18u5R4qWgr3vKwwlG9/R/UWKDEl ca_user_key'
`, []*databroker.Record{}, Input{SSH: InputSSH{
			PublicKey: user1cert,
		}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHPublickeyOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("single unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_ca: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJjxHDM2CpDj4QfY5NxhDPQaOtAebNXzzFsn61kX0LCF other_key'
`, []*databroker.Record{}, Input{SSH: InputSSH{
			PublicKey: user1cert,
		}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHPublickeyUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("not a cert", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_ca: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJjxHDM2CpDj4QfY5NxhDPQaOtAebNXzzFsn61kX0LCF other_key'
`, []*databroker.Record{}, Input{SSH: InputSSH{
			PublicKey: user1key,
		}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHPublickeyUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("multiple ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_ca:
        - 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJjxHDM2CpDj4QfY5NxhDPQaOtAebNXzzFsn61kX0LCF other_key'
        - 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEie08s3SkRYuk9OS18u5R4qWgr3vKwwlG9/R/UWKDEl ca_user_key'
`, []*databroker.Record{}, Input{SSH: InputSSH{
			PublicKey: user1cert,
		}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHPublickeyOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
}
