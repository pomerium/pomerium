package webauthnutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/webauthn"
	"github.com/pomerium/webauthn/cose"
)

func TestGenerateCreationOptions(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://www.example.com", nil)

	t.Run("random challenge", func(t *testing.T) {
		key := []byte{1, 2, 3}
		options1 := GenerateCreationOptions(r, key, predefinedDeviceTypes[DefaultDeviceType], &user.User{
			Id:    "example",
			Email: "test@example.com",
			Name:  "Test User",
		})
		options2 := GenerateCreationOptions(r, key, predefinedDeviceTypes[DefaultDeviceType], &user.User{
			Id:    "example",
			Email: "test@example.com",
			Name:  "Test User",
		})
		assert.NotEqual(t, options1.Challenge, options2.Challenge)
	})
	t.Run(DefaultDeviceType, func(t *testing.T) {
		key := []byte{1, 2, 3}
		options := GenerateCreationOptions(r, key, predefinedDeviceTypes[DefaultDeviceType], &user.User{
			Id:    "example",
			Email: "test@example.com",
			Name:  "Test User",
		})
		options.Challenge = nil
		assert.Equal(t, &webauthn.PublicKeyCredentialCreationOptions{
			RP: webauthn.PublicKeyCredentialRPEntity{
				Name: "Pomerium",
				ID:   "example.com",
			},
			User: webauthn.PublicKeyCredentialUserEntity{
				ID: []byte{
					0x14, 0x7b, 0x2e, 0x3b, 0xae, 0x95, 0x5b, 0x99,
					0xbb, 0x4e, 0x89, 0xdd, 0x03, 0xac, 0xae, 0x1d,
				},
				DisplayName: "Test User",
				Name:        "test@example.com",
			},
			Challenge: nil,
			PubKeyCredParams: []webauthn.PublicKeyCredentialParameters{
				{Type: "public-key", COSEAlgorithmIdentifier: -7},
				{Type: "public-key", COSEAlgorithmIdentifier: -257},
				{Type: "public-key", COSEAlgorithmIdentifier: -65535},
			},
			Timeout:            900000000000,
			ExcludeCredentials: nil,
			AuthenticatorSelection: &webauthn.AuthenticatorSelectionCriteria{
				UserVerification: "preferred",
			},
			Attestation: "direct",
		}, options)
	})
}

func TestGenerateRequestOptions(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://www.example.com", nil)

	t.Run("random challenge", func(t *testing.T) {
		key := []byte{1, 2, 3}
		options1 := GenerateRequestOptions(r, key, predefinedDeviceTypes[DefaultDeviceType], nil)
		options2 := GenerateRequestOptions(r, key, predefinedDeviceTypes[DefaultDeviceType], nil)
		assert.NotEqual(t, options1.Challenge, options2.Challenge)
	})
	t.Run(DefaultDeviceType, func(t *testing.T) {
		key := []byte{1, 2, 3}
		options := GenerateRequestOptions(r, key, predefinedDeviceTypes[DefaultDeviceType], []*device.Credential{
			{Id: "device1", TypeId: DefaultDeviceType, Specifier: &device.Credential_Webauthn{Webauthn: &device.Credential_WebAuthn{
				Id: []byte{4, 5, 6},
			}}},
			{Id: "device2", TypeId: "some-other-type", Specifier: &device.Credential_Webauthn{Webauthn: &device.Credential_WebAuthn{
				Id: []byte{7, 8, 9},
			}}},
		})
		options.Challenge = nil
		assert.Equal(t, &webauthn.PublicKeyCredentialRequestOptions{
			Timeout: 900000000000,
			RPID:    "example.com",
			AllowCredentials: []webauthn.PublicKeyCredentialDescriptor{
				{Type: "public-key", ID: []byte{4, 5, 6}},
			},
			UserVerification: "preferred",
		}, options)
	})
}

func TestFillAttestationConveyance(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		expect webauthn.AttestationConveyancePreference
		in     *device.WebAuthnOptions_AttestationConveyancePreference
	}{
		{"", nil},
		{"none", device.WebAuthnOptions_NONE.Enum()},
		{"indirect", device.WebAuthnOptions_INDIRECT.Enum()},
		{"direct", device.WebAuthnOptions_DIRECT.Enum()},
		{"enterprise", device.WebAuthnOptions_ENTERPRISE.Enum()},
	} {
		options := new(webauthn.PublicKeyCredentialCreationOptions)
		fillAttestationConveyance(options, testCase.in)
		actual := options.Attestation
		assert.Equal(t, testCase.expect, actual, "expected %v for %v", testCase.expect, testCase.in)
	}
}

func TestFillAuthenticatorSelection(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		expect webauthn.AuthenticatorAttachment
		in     *device.WebAuthnOptions_AuthenticatorAttachment
	}{
		{"", nil},
		{"cross-platform", device.WebAuthnOptions_CROSS_PLATFORM.Enum()},
		{"platform", device.WebAuthnOptions_PLATFORM.Enum()},
	} {
		criteria := new(webauthn.AuthenticatorSelectionCriteria)
		fillAuthenticatorAttachment(criteria, testCase.in)
		actual := criteria.AuthenticatorAttachment
		assert.Equal(t, testCase.expect, actual, "expected %v for %v", testCase.expect, testCase.in)
	}
}

func TestFillPublicKeyCredentialParameters(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		expectedType      webauthn.PublicKeyCredentialType
		expectedAlgorithm cose.Algorithm
		in                *device.WebAuthnOptions_PublicKeyCredentialParameters
	}{
		{"", 0, nil},
		{"public-key", -7, &device.WebAuthnOptions_PublicKeyCredentialParameters{
			Type: device.WebAuthnOptions_PUBLIC_KEY, Alg: -7,
		}},
	} {
		params := new(webauthn.PublicKeyCredentialParameters)
		fillPublicKeyCredentialParameters(params, testCase.in)
		actualType := params.Type
		assert.Equal(t, testCase.expectedType, actualType, "expected %v for %v", testCase.expectedType, testCase.in)
		actualAlgorithm := params.COSEAlgorithmIdentifier
		assert.Equal(t, testCase.expectedAlgorithm, actualAlgorithm, "expected %v for %v", testCase.expectedType, testCase.in)
	}
}

func TestFillResidentKeyRequirement(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		expect webauthn.ResidentKeyType
		in     *device.WebAuthnOptions_ResidentKeyRequirement
	}{
		{"", nil},
		{"discouraged", device.WebAuthnOptions_RESIDENT_KEY_DISCOURAGED.Enum()},
		{"preferred", device.WebAuthnOptions_RESIDENT_KEY_PREFERRED.Enum()},
		{"required", device.WebAuthnOptions_RESIDENT_KEY_REQUIRED.Enum()},
	} {
		criteria := new(webauthn.AuthenticatorSelectionCriteria)
		fillResidentKeyRequirement(criteria, testCase.in)
		actual := criteria.ResidentKey
		assert.Equal(t, testCase.expect, actual, "expected %v for %v", testCase.expect, testCase.in)
	}
}

func TestFillUserVerificationRequirement(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		expect webauthn.UserVerificationRequirement
		in     *device.WebAuthnOptions_UserVerificationRequirement
	}{
		{"", nil},
		{"discouraged", device.WebAuthnOptions_USER_VERIFICATION_DISCOURAGED.Enum()},
		{"preferred", device.WebAuthnOptions_USER_VERIFICATION_PREFERRED.Enum()},
		{"required", device.WebAuthnOptions_USER_VERIFICATION_REQUIRED.Enum()},
	} {
		criteria := new(webauthn.AuthenticatorSelectionCriteria)
		fillUserVerificationRequirement(criteria, testCase.in)
		actual := criteria.UserVerification
		assert.Equal(t, testCase.expect, actual, "expected %v for %v", testCase.expect, testCase.in)
	}
}
