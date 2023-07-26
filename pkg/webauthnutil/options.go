package webauthnutil

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/slices"
	"github.com/pomerium/webauthn"
	"github.com/pomerium/webauthn/cose"
)

const (
	ceremonyTimeout = time.Minute * 15
	rpName          = "Pomerium"
)

// GenerateChallenge generates a new Challenge.
func GenerateChallenge(key []byte, expiry time.Time) cryptutil.SecureToken {
	return cryptutil.GenerateSecureToken(key, expiry, cryptutil.NewRandomToken())
}

// GenerateCreationOptions generates creation options for WebAuthn.
func GenerateCreationOptions(
	r *http.Request,
	key []byte,
	deviceType *device.Type,
	user *user.User,
) *webauthn.PublicKeyCredentialCreationOptions {
	expiry := time.Now().Add(ceremonyTimeout)
	return newCreationOptions(
		r,
		GenerateChallenge(key, expiry).Bytes(),
		deviceType,
		user,
	)
}

// GenerateRequestOptions generates request options for WebAuthn.
func GenerateRequestOptions(
	r *http.Request,
	key []byte,
	deviceType *device.Type,
	knownDeviceCredentials []*device.Credential,
) *webauthn.PublicKeyCredentialRequestOptions {
	expiry := time.Now().Add(ceremonyTimeout)
	return newRequestOptions(
		r,
		GenerateChallenge(key, expiry).Bytes(),
		deviceType,
		knownDeviceCredentials,
	)
}

// GetCreationOptionsForCredential gets the creation options for the public key creation credential. An error may be
// returned if the challenge used to generate the credential is invalid.
func GetCreationOptionsForCredential(
	r *http.Request,
	key []byte,
	deviceType *device.Type,
	user *user.User,
	credential *webauthn.PublicKeyCreationCredential,
) (*webauthn.PublicKeyCredentialCreationOptions, error) {
	clientData, err := credential.Response.UnmarshalClientData()
	if err != nil {
		return nil, fmt.Errorf("invalid client data: %w", err)
	}

	rawChallenge, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		return nil, fmt.Errorf("invalid challenge: %w", err)
	}
	var challenge cryptutil.SecureToken
	copy(challenge[:], rawChallenge)

	err = challenge.Verify(key, time.Now())
	if err != nil {
		return nil, err
	}

	return newCreationOptions(r, challenge.Bytes(), deviceType, user), nil
}

// GetRequestOptionsForCredential gets the request options for the public key request credential. An error may be
// returned if the challenge used to generate the credential is invalid.
func GetRequestOptionsForCredential(
	r *http.Request,
	key []byte,
	deviceType *device.Type,
	knownDeviceCredentials []*device.Credential,
	credential *webauthn.PublicKeyAssertionCredential,
) (*webauthn.PublicKeyCredentialRequestOptions, error) {
	clientData, err := credential.Response.UnmarshalClientData()
	if err != nil {
		return nil, fmt.Errorf("invalid client data: %w", err)
	}

	rawChallenge, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		return nil, fmt.Errorf("invalid challenge: %w", err)
	}
	var challenge cryptutil.SecureToken
	copy(challenge[:], rawChallenge)

	err = challenge.Verify(key, time.Now())
	if err != nil {
		return nil, err
	}

	return newRequestOptions(r, challenge.Bytes(), deviceType, knownDeviceCredentials), nil
}

// newCreationOptions gets the creation options for WebAuthn with the provided challenge.
func newCreationOptions(
	r *http.Request,
	challenge []byte,
	deviceType *device.Type,
	user *user.User,
) *webauthn.PublicKeyCredentialCreationOptions {
	options := &webauthn.PublicKeyCredentialCreationOptions{
		RP: webauthn.PublicKeyCredentialRPEntity{
			Name: rpName,
			ID:   GetEffectiveDomain(r),
		},
		User:      GetUserEntity(user),
		Challenge: challenge,
		Timeout:   ceremonyTimeout,
	}

	if deviceOptions := deviceType.GetWebauthn().GetOptions(); deviceOptions != nil {
		fillAllPublicKeyCredentialParameters(options, deviceOptions.GetPubKeyCredParams())
		fillAuthenticatorSelection(options, deviceOptions.GetAuthenticatorSelection())
		fillAttestationConveyance(options, deviceOptions.Attestation)
	}

	return options
}

// newRequestOptions gets the request options for WebAuthn with the provided challenge.
func newRequestOptions(
	r *http.Request,
	challenge []byte,
	deviceType *device.Type,
	knownDeviceCredentials []*device.Credential,
) *webauthn.PublicKeyCredentialRequestOptions {
	options := &webauthn.PublicKeyCredentialRequestOptions{
		Challenge: challenge,
		Timeout:   ceremonyTimeout,
		RPID:      GetEffectiveDomain(r),
	}
	fillRequestUserVerificationRequirement(
		options,
		deviceType.GetWebauthn().GetOptions().GetAuthenticatorSelection().UserVerification,
	)
	knownDeviceCredentialsForType := slices.Filter(knownDeviceCredentials, func(c *device.Credential) bool {
		return c.GetTypeId() == deviceType.GetId()
	})
	for _, knownDeviceCredential := range knownDeviceCredentialsForType {
		if publicKey := knownDeviceCredential.GetWebauthn(); publicKey != nil {
			options.AllowCredentials = append(options.AllowCredentials, webauthn.PublicKeyCredentialDescriptor{
				Type: webauthn.PublicKeyCredentialTypePublicKey,
				ID:   publicKey.GetId(),
			})
		}
	}
	return options
}

func fillAllPublicKeyCredentialParameters(
	options *webauthn.PublicKeyCredentialCreationOptions,
	allDeviceParams []*device.WebAuthnOptions_PublicKeyCredentialParameters,
) {
	options.PubKeyCredParams = nil
	for _, deviceParams := range allDeviceParams {
		p := webauthn.PublicKeyCredentialParameters{}
		fillPublicKeyCredentialParameters(&p, deviceParams)
		options.PubKeyCredParams = append(options.PubKeyCredParams, p)
	}
}

func fillAttestationConveyance(
	options *webauthn.PublicKeyCredentialCreationOptions,
	attestationConveyance *device.WebAuthnOptions_AttestationConveyancePreference,
) {
	options.Attestation = ""
	if attestationConveyance == nil {
		return
	}

	switch *attestationConveyance {
	case device.WebAuthnOptions_NONE:
		options.Attestation = webauthn.AttestationConveyanceNone
	case device.WebAuthnOptions_INDIRECT:
		options.Attestation = webauthn.AttestationConveyanceIndirect
	case device.WebAuthnOptions_DIRECT:
		options.Attestation = webauthn.AttestationConveyanceDirect
	case device.WebAuthnOptions_ENTERPRISE:
		options.Attestation = webauthn.AttestationConveyanceEnterprise
	}
}

func fillAuthenticatorAttachment(
	criteria *webauthn.AuthenticatorSelectionCriteria,
	authenticatorAttachment *device.WebAuthnOptions_AuthenticatorAttachment,
) {
	criteria.AuthenticatorAttachment = ""
	if authenticatorAttachment == nil {
		return
	}

	switch *authenticatorAttachment {
	case device.WebAuthnOptions_CROSS_PLATFORM:
		criteria.AuthenticatorAttachment = webauthn.AuthenticatorAttachmentCrossPlatform
	case device.WebAuthnOptions_PLATFORM:
		criteria.AuthenticatorAttachment = webauthn.AuthenticatorAttachmentPlatform
	}
}

func fillAuthenticatorSelection(
	options *webauthn.PublicKeyCredentialCreationOptions,
	deviceCriteria *device.WebAuthnOptions_AuthenticatorSelectionCriteria,
) {
	options.AuthenticatorSelection = new(webauthn.AuthenticatorSelectionCriteria)
	fillAuthenticatorAttachment(options.AuthenticatorSelection, deviceCriteria.AuthenticatorAttachment)
	fillResidentKeyRequirement(options.AuthenticatorSelection, deviceCriteria.ResidentKeyRequirement)
	options.AuthenticatorSelection.RequireResidentKey = deviceCriteria.GetRequireResidentKey()
	fillUserVerificationRequirement(options.AuthenticatorSelection, deviceCriteria.UserVerification)
}

func fillPublicKeyCredentialParameters(
	params *webauthn.PublicKeyCredentialParameters,
	deviceParams *device.WebAuthnOptions_PublicKeyCredentialParameters,
) {
	params.Type = ""
	params.COSEAlgorithmIdentifier = 0
	if deviceParams == nil {
		return
	}

	switch deviceParams.Type {
	case device.WebAuthnOptions_PUBLIC_KEY:
		params.Type = webauthn.PublicKeyCredentialTypePublicKey
	}
	params.COSEAlgorithmIdentifier = cose.Algorithm(deviceParams.GetAlg())
}

func fillRequestUserVerificationRequirement(
	options *webauthn.PublicKeyCredentialRequestOptions,
	userVerificationRequirement *device.WebAuthnOptions_UserVerificationRequirement,
) {
	options.UserVerification = ""
	if userVerificationRequirement == nil {
		return
	}

	switch *userVerificationRequirement {
	case device.WebAuthnOptions_USER_VERIFICATION_DISCOURAGED:
		options.UserVerification = webauthn.UserVerificationDiscouraged
	case device.WebAuthnOptions_USER_VERIFICATION_PREFERRED:
		options.UserVerification = webauthn.UserVerificationPreferred
	case device.WebAuthnOptions_USER_VERIFICATION_REQUIRED:
		options.UserVerification = webauthn.UserVerificationRequired
	}
}

func fillResidentKeyRequirement(
	criteria *webauthn.AuthenticatorSelectionCriteria,
	residentKeyRequirement *device.WebAuthnOptions_ResidentKeyRequirement,
) {
	criteria.ResidentKey = ""
	if residentKeyRequirement == nil {
		return
	}

	switch *residentKeyRequirement {
	case device.WebAuthnOptions_RESIDENT_KEY_DISCOURAGED:
		criteria.ResidentKey = webauthn.ResidentKeyDiscouraged
	case device.WebAuthnOptions_RESIDENT_KEY_PREFERRED:
		criteria.ResidentKey = webauthn.ResidentKeyPreferred
	case device.WebAuthnOptions_RESIDENT_KEY_REQUIRED:
		criteria.ResidentKey = webauthn.ResidentKeyRequired
	}
}

func fillUserVerificationRequirement(
	criteria *webauthn.AuthenticatorSelectionCriteria,
	userVerificationRequirement *device.WebAuthnOptions_UserVerificationRequirement,
) {
	criteria.UserVerification = ""
	if userVerificationRequirement == nil {
		return
	}

	switch *userVerificationRequirement {
	case device.WebAuthnOptions_USER_VERIFICATION_DISCOURAGED:
		criteria.UserVerification = webauthn.UserVerificationDiscouraged
	case device.WebAuthnOptions_USER_VERIFICATION_PREFERRED:
		criteria.UserVerification = webauthn.UserVerificationPreferred
	case device.WebAuthnOptions_USER_VERIFICATION_REQUIRED:
		criteria.UserVerification = webauthn.UserVerificationRequired
	}
}
