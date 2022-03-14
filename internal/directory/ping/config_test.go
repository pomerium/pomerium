package ping

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseServiceAccount(t *testing.T) {
	tests := []struct {
		name              string
		rawServiceAccount string
		serviceAccount    *ServiceAccount
		wantErr           bool
	}{
		{
			"json",
			`{"client_id":"CLIENT_ID","client_secret":"CLIENT_SECRET","environment_id":"ENVIRONMENT_ID"}`,
			&ServiceAccount{ClientID: "CLIENT_ID", ClientSecret: "CLIENT_SECRET", EnvironmentID: "ENVIRONMENT_ID"},
			false,
		},
		{
			"base64 json",
			`eyJjbGllbnRfaWQiOiJDTElFTlRfSUQiLCJjbGllbnRfc2VjcmV0IjoiQ0xJRU5UX1NFQ1JFVCIsImVudmlyb25tZW50X2lkIjoiRU5WSVJPTk1FTlRfSUQifQ==`,
			&ServiceAccount{ClientID: "CLIENT_ID", ClientSecret: "CLIENT_SECRET", EnvironmentID: "ENVIRONMENT_ID"},
			false,
		},
		{
			"empty",
			"",
			nil,
			true,
		},
		{
			"invalid",
			"Zm9v---",
			nil,
			true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseServiceAccount(tc.rawServiceAccount)
			require.True(t, (err != nil) == tc.wantErr)
			assert.Equal(t, tc.serviceAccount, got)
		})
	}
}
