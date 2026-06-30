package mcp

import (
	"crypto/cipher"
	"encoding/base64"
	"net/url"
	"strings"
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

// TestCreateCodeFormURLEncodingSafe verifies that codes are emitted in a
// form-body-safe alphabet (base64url, no '+' '/' '=') and survive a round-trip
// through application/x-www-form-urlencoded, which is how an OAuth client sends
// the code back to the token endpoint. A '+' in the legacy StdEncoding alphabet
// is decoded to a space by form parsers when a client under-encodes it,
// corrupting the code and causing a spurious invalid_grant.
func TestCreateCodeFormURLEncodingSafe(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	// Run several iterations so we exercise ciphertexts that would have
	// contained '+' or '/' under StdEncoding.
	for i := 0; i < 100; i++ {
		code, err := CreateCode(CodeTypeAuthorization, "test-id", time.Now().Add(time.Hour), "test-ad", testCipher)
		require.NoError(t, err)

		assert.NotContains(t, code, "+", "code must not contain '+' (corrupted to space by form parsers)")
		assert.NotContains(t, code, "/", "code must not contain '/'")
		assert.NotContains(t, code, "=", "code must not contain '=' padding")

		// Simulate the client placing the code in a form body and the server
		// parsing it back out via url.Values, then decrypting it.
		form := url.Values{}
		form.Set("code", code)
		parsed, err := url.ParseQuery(form.Encode())
		require.NoError(t, err)
		require.Equal(t, code, parsed.Get("code"), "code must survive a form-urlencoded round-trip")

		decoded, err := DecryptCode(CodeTypeAuthorization, parsed.Get("code"), testCipher, "test-ad", time.Now())
		require.NoError(t, err)
		assert.Equal(t, "test-id", decoded.Id)
	}
}

// TestDecryptCodeLegacyStdEncoding verifies the backward-compatible decode path:
// a code encoded with the legacy StdEncoding alphabet still decrypts via the
// fallback, keeping in-flight codes redeemable across the cutover.
func TestDecryptCodeLegacyStdEncoding(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	future := time.Now().Add(time.Hour)

	// Build a code by hand using StdEncoding to emulate a pre-cutover issuance.
	v := &oauth21proto.Code{
		Id:        "legacy-id",
		ExpiresAt: timestamppb.New(future),
		GrantType: CodeTypeAuthorization,
	}
	b, err := proto.Marshal(v)
	require.NoError(t, err)
	ciphertext := cryptutil.Encrypt(testCipher, b, []byte("test-ad"))
	legacyCode := base64.StdEncoding.EncodeToString(ciphertext)

	decoded, err := DecryptCode(CodeTypeAuthorization, legacyCode, testCipher, "test-ad", time.Now())
	require.NoError(t, err)
	assert.Equal(t, "legacy-id", decoded.Id)
}

// TestDecryptCodeLegacyStdEncodingWithPlus exercises the fallback specifically
// for a StdEncoding code that contains a '+'. This is the exact failure mode the
// new encoding guards against, here proven still-decodable via the fallback.
func TestDecryptCodeLegacyStdEncodingWithPlus(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	future := time.Now().Add(time.Hour)

	// Keep generating until StdEncoding produces a code containing '+'.
	var legacyCode string
	for i := 0; i < 1000; i++ {
		v := &oauth21proto.Code{
			Id:        "legacy-plus-id",
			ExpiresAt: timestamppb.New(future),
			GrantType: CodeTypeAuthorization,
		}
		b, err := proto.Marshal(v)
		require.NoError(t, err)
		ciphertext := cryptutil.Encrypt(testCipher, b, []byte("test-ad"))
		candidate := base64.StdEncoding.EncodeToString(ciphertext)
		if strings.Contains(candidate, "+") {
			legacyCode = candidate
			break
		}
	}
	require.NotEmpty(t, legacyCode, "failed to generate a StdEncoding code containing '+'")

	decoded, err := DecryptCode(CodeTypeAuthorization, legacyCode, testCipher, "test-ad", time.Now())
	require.NoError(t, err)
	assert.Equal(t, "legacy-plus-id", decoded.Id)
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
	ciphertext := cryptutil.Encrypt(testCipher, codeBytes, []byte("test-ad"))
	codeNoExpiryStr := base64.RawURLEncoding.EncodeToString(ciphertext)

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
			errMessage: "code type mismatch",
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
			errMessage: "expires_at: value is required",
		},
		{
			name: "invalid base64",
			typ:  CodeTypeAuthorization,
			// '!' is not in either the StdEncoding or RawURLEncoding alphabet,
			// so both decode paths fail and the base64-decode error surfaces.
			code:       "not-base64!",
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
			errMessage: "message authentication failed",
		},
		{
			name:       "unspecified code type",
			typ:        0, // Unspecified type
			code:       validCode,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "code type mismatch",
		},
		{
			name:       "undefined code type",
			typ:        99, // undefined type
			code:       validCode,
			cipher:     testCipher,
			ad:         "test-ad",
			now:        now,
			wantErr:    true,
			errMessage: "code type mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecryptCode(tc.typ, tc.code, tc.cipher, tc.ad, tc.now)

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
