package webauthnutil

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/webauthn/cose"
)

// DefaultDeviceType is the default device type when none is specified.
const DefaultDeviceType = urlutil.DefaultDeviceType

var supportedPublicKeyCredentialParameters = []*device.WebAuthnOptions_PublicKeyCredentialParameters{
	{Type: device.WebAuthnOptions_PUBLIC_KEY, Alg: int64(cose.AlgorithmES256)},
	{Type: device.WebAuthnOptions_PUBLIC_KEY, Alg: int64(cose.AlgorithmRS256)},
	{Type: device.WebAuthnOptions_PUBLIC_KEY, Alg: int64(cose.AlgorithmRS1)},
}

var predefinedDeviceTypes = map[string]*device.Type{
	"any": {
		Id:   "any",
		Name: "Any",
		Specifier: &device.Type_Webauthn{
			Webauthn: &device.Type_WebAuthn{
				Options: &device.WebAuthnOptions{
					Attestation: device.WebAuthnOptions_DIRECT.Enum(),
					AuthenticatorSelection: &device.WebAuthnOptions_AuthenticatorSelectionCriteria{
						UserVerification: device.WebAuthnOptions_USER_VERIFICATION_PREFERRED.Enum(),
					},
					PubKeyCredParams: supportedPublicKeyCredentialParameters,
				},
			},
		},
	},
	"enclave_only": {
		Id:   "enclave_only",
		Name: "Secure Enclave Only",
		Specifier: &device.Type_Webauthn{
			Webauthn: &device.Type_WebAuthn{
				Options: &device.WebAuthnOptions{
					Attestation: device.WebAuthnOptions_DIRECT.Enum(),
					AuthenticatorSelection: &device.WebAuthnOptions_AuthenticatorSelectionCriteria{
						UserVerification:        device.WebAuthnOptions_USER_VERIFICATION_PREFERRED.Enum(),
						RequireResidentKey:      proto.Bool(true),
						AuthenticatorAttachment: device.WebAuthnOptions_PLATFORM.Enum(),
					},
					PubKeyCredParams: supportedPublicKeyCredentialParameters,
				},
			},
		},
	},
}

// GetDeviceType gets the device type from the databroker. If the device type does not exist in the databroker
// a pre-defined device type may be returned.
func GetDeviceType(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	deviceTypeID string,
) *device.Type {
	deviceType, err := device.GetType(ctx, client, deviceTypeID)
	if status.Code(err) == codes.NotFound {
		deviceType = predefinedDeviceTypes[deviceTypeID]
	}
	if deviceType == nil {
		deviceType = proto.Clone(predefinedDeviceTypes[DefaultDeviceType]).(*device.Type)
		deviceType.Id = deviceTypeID
	}
	return deviceType
}
