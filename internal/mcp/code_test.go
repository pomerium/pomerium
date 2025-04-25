package mcp

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

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestCreateCode(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	tests := []struct {
		name       string
		typ        oauth21proto.CodeType
		id         string
		expires    time.Time
		ad         string
		cipher     cipher.AEAD
		wantErr    bool
		errMessage string
	}{
		{
			name:    "valid authorization code",
			typ:     CodeTypeAuthorization,
			id:      "test-id",
			expires: time.Now().Add(time.Hour),
			ad:      "test-ad",
			cipher:  testCipher,
			wantErr: false,
		},
		{
			name:    "valid refresh code",
			typ:     CodeTypeRefresh,
			id:      "test-id",
			expires: time.Now().Add(time.Hour),
			ad:      "test-ad",
			cipher:  testCipher,
			wantErr: false,
		},
		{
			name:    "valid access code",
			typ:     CodeTypeAccess,
			id:      "test-id",
			expires: time.Now().Add(time.Hour),
			ad:      "test-ad",
			cipher:  testCipher,
			wantErr: false,
		},
		{
			name:       "empty id",
			typ:        CodeTypeAuthorization,
			id:         "",
			expires:    time.Now().Add(time.Hour),
			ad:         "test-ad",
			cipher:     testCipher,
			wantErr:    true,
			errMessage: "validate",
		},
		{
			name:       "empty expires",
			typ:        CodeTypeAuthorization,
			id:         "test-id",
			expires:    time.Time{},
			ad:         "test-ad",
			cipher:     testCipher,
			wantErr:    true,
			errMessage: "validate",
		},
		{
			name:       "invalid code type",
			typ:        0, // Unspecified type
			id:         "test-id",
			expires:    time.Now().Add(time.Hour),
			ad:         "test-ad",
			cipher:     testCipher,
			wantErr:    true,
			errMessage: "validate",
		},
		{
			name:       "undefined code type",
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
			code, err := CreateCode(tc.typ, tc.id, tc.expires, tc.ad, tc.cipher)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errMessage != "" {
					assert.Contains(t, err.Error(), tc.errMessage)
				}
				assert.Empty(t, code)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, code)

				decodedCode, err := DecryptCode(tc.typ, code, tc.cipher, tc.ad, time.Now())
				require.NoError(t, err)
				assert.Equal(t, tc.id, decodedCode.Id)
				assert.Equal(t, tc.typ, decodedCode.GrantType)
				assert.True(t, proto.Equal(timestamppb.New(tc.expires), decodedCode.ExpiresAt))
			}
		})
	}
}

func TestDecryptCode(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	validCode, err := CreateCode(CodeTypeAuthorization, "test-id", future, "test-ad", testCipher)
	require.NoError(t, err)

	validRefreshCode, err := CreateCode(CodeTypeRefresh, "refresh-id", future, "test-ad", testCipher)
	require.NoError(t, err)

	expiredCode, err := CreateCode(CodeTypeAuthorization, "expired-id", past, "test-ad", testCipher)
	require.NoError(t, err)

	codeNoExpiry := &oauth21proto.Code{
		Id:        "no-expiry",
		GrantType: CodeTypeAuthorization,
	}
	codeBytes, err := proto.Marshal(codeNoExpiry)
	require.NoError(t, err)
	ciphertext := cryptutil.Encrypt(testCipher, codeBytes, getAD("test-ad", CodeTypeAuthorization))
	codeNoExpiryStr := base64.StdEncoding.EncodeToString(ciphertext)

	tests := []struct {
		name       string
		typ        oauth21proto.CodeType
		code       string
		cipher     cipher.AEAD
		ad         string
		now        time.Time
		want       *oauth21proto.Code
		wantErr    bool
		errMessage string
	}{
		{
			name:    "valid code",
			typ:     CodeTypeAuthorization,
			code:    validCode,
			cipher:  testCipher,
			ad:      "test-ad",
			now:     now,
			want:    &oauth21proto.Code{Id: "test-id", ExpiresAt: timestamppb.New(future), GrantType: CodeTypeAuthorization},
			wantErr: false,
		},
		{
			name:    "valid refresh code",
			typ:     CodeTypeRefresh,
			code:    validRefreshCode,
			cipher:  testCipher,
			ad:      "test-ad",
			now:     now,
			want:    &oauth21proto.Code{Id: "refresh-id", ExpiresAt: timestamppb.New(future), GrantType: CodeTypeRefresh},
			wantErr: false,
		},
		{
			name:       "wrong code type",
			typ:        CodeTypeAccess, // Using wrong type
			code:       validCode,      // This was created with Authorization type
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "decrypt",
		},
		{
			name:       "expired code",
			typ:        CodeTypeAuthorization,
			code:       expiredCode,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "code expired",
		},
		{
			name:       "nil expiration",
			typ:        CodeTypeAuthorization,
			code:       codeNoExpiryStr,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "expiration is nil",
		},
		{
			name:       "invalid base64",
			typ:        CodeTypeAuthorization,
			code:       "not-base64",
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "base64 decode",
		},
		{
			name:       "wrong authentication data",
			typ:        CodeTypeAuthorization,
			code:       validCode,
			cipher:     testCipher,
			ad:         "wrong-ad",
			now:        now,
			wantErr:    true,
			errMessage: "decrypt",
		},
		{
			name:       "unspecified code type",
			typ:        0, // Unspecified type
			code:       validCode,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "decrypt",
		},
		{
			name:       "undefined code type",
			typ:        99, // undefined type
			code:       validCode,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "decrypt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecryptCode(tc.typ, tc.code, tc.cipher, tc.ad, tc.now)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errMessage != "" {
					assert.Contains(t, err.Error(), tc.errMessage)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, got)

				diff := cmp.Diff(tc.want, got, protocmp.Transform())
				assert.Empty(t, diff)
			}
		})
	}
}
