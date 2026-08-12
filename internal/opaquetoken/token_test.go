package opaquetoken

import (
	"crypto/cipher"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestSeal(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	tests := []struct {
		name       string
		typ        Type
		id         string
		expires    time.Time
		ad         string
		cipher     cipher.AEAD
		wantErr    bool
		errMessage string
	}{
		{
			name:    "valid authorization token",
			typ:     TypeAuthorization,
			id:      "test-id",
			expires: time.Now().Add(time.Hour),
			ad:      "test-ad",
			cipher:  testCipher,
			wantErr: false,
		},
		{
			name:    "valid refresh token",
			typ:     TypeRefresh,
			id:      "test-id",
			expires: time.Now().Add(time.Hour),
			ad:      "test-ad",
			cipher:  testCipher,
			wantErr: false,
		},
		{
			name:    "valid access token",
			typ:     TypeAccess,
			id:      "test-id",
			expires: time.Now().Add(time.Hour),
			ad:      "test-ad",
			cipher:  testCipher,
			wantErr: false,
		},
		{
			name:       "empty id",
			typ:        TypeAuthorization,
			id:         "",
			expires:    time.Now().Add(time.Hour),
			ad:         "test-ad",
			cipher:     testCipher,
			wantErr:    true,
			errMessage: "validate",
		},
		{
			name:       "empty expires",
			typ:        TypeAuthorization,
			id:         "test-id",
			expires:    time.Time{},
			ad:         "test-ad",
			cipher:     testCipher,
			wantErr:    true,
			errMessage: "validate",
		},
		{
			name:       "invalid type",
			typ:        0, // Unspecified type
			id:         "test-id",
			expires:    time.Now().Add(time.Hour),
			ad:         "test-ad",
			cipher:     testCipher,
			wantErr:    true,
			errMessage: "validate",
		},
		{
			name:       "undefined type",
			typ:        99, // Undefined type
			id:         "test-id",
			expires:    time.Now().Add(time.Hour),
			ad:         "test-ad",
			cipher:     testCipher,
			wantErr:    true,
			errMessage: "validate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := Seal(tc.typ, tc.id, tc.expires, tc.ad, tc.cipher, 0)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errMessage != "" {
					assert.Contains(t, err.Error(), tc.errMessage)
				}
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)

				payload, err := Open(tc.typ, token, tc.cipher, tc.ad, time.Now())
				require.NoError(t, err)
				assert.Equal(t, tc.id, payload.Id)
				assert.Equal(t, tc.typ, payload.Type)
				assert.True(t, proto.Equal(timestamppb.New(tc.expires), payload.ExpiresAt))
			}
		})
	}
}

func TestOpen(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	validToken, err := Seal(TypeAuthorization, "test-id", future, "test-ad", testCipher, 0)
	require.NoError(t, err)

	validRefreshToken, err := Seal(TypeRefresh, "refresh-id", future, "test-ad", testCipher, 0)
	require.NoError(t, err)

	expiredToken, err := Seal(TypeAuthorization, "expired-id", past, "test-ad", testCipher, 0)
	require.NoError(t, err)

	payloadNoExpiry := &Payload{
		Id:   "no-expiry",
		Type: TypeAuthorization,
	}
	payloadBytes, err := proto.Marshal(payloadNoExpiry)
	require.NoError(t, err)
	ciphertext := cryptutil.Encrypt(testCipher, payloadBytes, []byte("test-ad"))
	tokenNoExpiry := base64.StdEncoding.EncodeToString(ciphertext)

	tests := []struct {
		name       string
		typ        Type
		token      string
		cipher     cipher.AEAD
		ad         string
		now        time.Time
		want       *Payload
		wantErr    bool
		errMessage string
	}{
		{
			name:    "valid token",
			typ:     TypeAuthorization,
			token:   validToken,
			cipher:  testCipher,
			ad:      "test-ad",
			now:     now,
			want:    &Payload{Id: "test-id", ExpiresAt: timestamppb.New(future), Type: TypeAuthorization},
			wantErr: false,
		},
		{
			name:    "valid refresh token",
			typ:     TypeRefresh,
			token:   validRefreshToken,
			cipher:  testCipher,
			ad:      "test-ad",
			now:     now,
			want:    &Payload{Id: "refresh-id", ExpiresAt: timestamppb.New(future), Type: TypeRefresh},
			wantErr: false,
		},
		{
			name:       "wrong type",
			typ:        TypeAccess, // Using wrong type
			token:      validToken, // minted with the authorization type
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "token type mismatch",
		},
		{
			name:       "expired token",
			typ:        TypeAuthorization,
			token:      expiredToken,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "token expired",
		},
		{
			name:       "nil expiration",
			typ:        TypeAuthorization,
			token:      tokenNoExpiry,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "expires_at: value is required",
		},
		{
			name:       "invalid base64",
			typ:        TypeAuthorization,
			token:      "not-base64",
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "base64 decode",
		},
		{
			name:       "wrong authentication data",
			typ:        TypeAuthorization,
			token:      validToken,
			cipher:     testCipher,
			ad:         "wrong-ad",
			now:        now,
			wantErr:    true,
			errMessage: "message authentication failed",
		},
		{
			name:       "unspecified type",
			typ:        0, // Unspecified type
			token:      validToken,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "token type mismatch",
		},
		{
			name:       "undefined type",
			typ:        99, // undefined type
			token:      validToken,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "token type mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Open(tc.typ, tc.token, tc.cipher, tc.ad, tc.now)

			if tc.wantErr {
				require.Error(t, err)
				if tc.errMessage != "" {
					assert.Contains(t, err.Error(), tc.errMessage)
				}
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)

				diff := cmp.Diff(tc.want, got, protocmp.Transform())
				assert.Empty(t, diff)
			}
		})
	}
}
