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
			token, err := Seal(tc.typ, tc.id, tc.expires, tc.ad, tc.cipher)

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

	validToken, err := Seal(TypeAuthorization, "test-id", future, "test-ad", testCipher)
	require.NoError(t, err)

	validRefreshToken, err := Seal(TypeRefresh, "refresh-id", future, "test-ad", testCipher)
	require.NoError(t, err)

	expiredToken, err := Seal(TypeAuthorization, "expired-id", past, "test-ad", testCipher)
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

func TestSealOptions(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	now := time.Now()
	expires := now.Add(time.Hour)

	tests := []struct {
		name              string
		options           []SealOption
		wantRecordVersion uint64
		wantIssuedAt      *time.Time
		wantIssuedAtNilOK bool
	}{
		{
			name:              "with record version",
			options:           []SealOption{WithRecordVersion(7)},
			wantRecordVersion: 7,
			wantIssuedAtNilOK: true,
		},
		{
			name:              "with issued at",
			options:           []SealOption{WithIssuedAt(now)},
			wantRecordVersion: 0,
			wantIssuedAt:      &now,
		},
		{
			name:              "with record version and issued at",
			options:           []SealOption{WithRecordVersion(42), WithIssuedAt(now)},
			wantRecordVersion: 42,
			wantIssuedAt:      &now,
		},
		{
			name:              "without options",
			options:           []SealOption{},
			wantRecordVersion: 0,
			wantIssuedAtNilOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := Seal(TypeAuthorization, "test-id", expires, "test-ad", testCipher, tc.options...)
			require.NoError(t, err)
			assert.NotEmpty(t, token)

			payload, err := Open(TypeAuthorization, token, testCipher, "test-ad", now)
			require.NoError(t, err)

			assert.Equal(t, tc.wantRecordVersion, payload.GetRecordVersion())

			if tc.wantIssuedAtNilOK {
				assert.Nil(t, payload.GetIssuedAt())
			} else {
				require.NotNil(t, payload.GetIssuedAt())
				assert.True(t, payload.GetIssuedAt().AsTime().Equal(*tc.wantIssuedAt),
					"expected %v, got %v", tc.wantIssuedAt, payload.GetIssuedAt().AsTime())
			}
		})
	}
}

func TestSealOptionsNanosecondPrecision(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	now := time.Now()
	expires := now.Add(time.Hour)
	issuedAt := time.Date(2026, 9, 11, 12, 30, 45, 123456789, time.UTC)

	token, err := Seal(TypeAuthorization, "test-id", expires, "test-ad", testCipher, WithIssuedAt(issuedAt))
	require.NoError(t, err)

	payload, err := Open(TypeAuthorization, token, testCipher, "test-ad", now)
	require.NoError(t, err)

	require.NotNil(t, payload.GetIssuedAt())
	assert.True(t, payload.GetIssuedAt().AsTime().Equal(issuedAt),
		"nanosecond precision lost: expected %v, got %v", issuedAt, payload.GetIssuedAt().AsTime())
}
