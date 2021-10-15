package webauthnutil

import (
	"context"

	"github.com/pomerium/webauthn/cose"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
)

var predefinedDeviceTypes = map[string]*device.Type{
	"default": {
		Id:   "default",
		Name: "default",
		Specifier: &device.Type_Webauthn{
			Webauthn: &device.Type_WebAuthn{
				Options: &device.WebAuthnOptions{
					Attestation: device.WebAuthnOptions_DIRECT.Enum(),
					AuthenticatorSelection: &device.WebAuthnOptions_AuthenticatorSelectionCriteria{
						UserVerification: device.WebAuthnOptions_USER_VERIFICATION_PREFERRED.Enum(),
					},
					PubKeyCredParams: []*device.WebAuthnOptions_PublicKeyCredentialParameters{
						{Type: device.WebAuthnOptions_PUBLIC_KEY, Alg: int64(cose.AlgorithmES256)},
						{Type: device.WebAuthnOptions_PUBLIC_KEY, Alg: int64(cose.AlgorithmRS256)},
						{Type: device.WebAuthnOptions_PUBLIC_KEY, Alg: int64(cose.AlgorithmRS1)},
					},
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
) (*device.Type, error) {
	deviceType, err := device.GetType(ctx, client, deviceTypeID)
	if status.Code(err) == codes.NotFound {
		var ok bool
		deviceType, ok = predefinedDeviceTypes[deviceTypeID]
		if ok {
			err = nil
		}
	}
	return deviceType, err
}
