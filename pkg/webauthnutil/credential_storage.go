package webauthnutil

import (
	"context"

	"github.com/akamensky/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/webauthn"
)

// CredentialStorage stores credentials in the databroker.
type CredentialStorage struct {
	client databroker.DataBrokerServiceClient
}

// NewCredentialStorage creates a new CredentialStorage.
func NewCredentialStorage(client databroker.DataBrokerServiceClient) *CredentialStorage {
	return &CredentialStorage{
		client: client,
	}
}

// GetCredential gets a credential from the databroker.
func (storage *CredentialStorage) GetCredential(
	ctx context.Context,
	credentialID []byte,
) (*webauthn.Credential, error) {
	record, err := device.GetOwnerCredentialRecord(ctx, storage.client, credentialID)
	if status.Code(err) == codes.NotFound {
		return nil, webauthn.ErrCredentialNotFound
	} else if err != nil {
		return nil, err
	}
	return &webauthn.Credential{
		ID:        record.GetId(),
		OwnerID:   record.GetOwnerId(),
		PublicKey: record.GetPublicKey(),
	}, nil
}

// SetCredential sets the credential for the enrollment.
func (storage *CredentialStorage) SetCredential(
	ctx context.Context,
	credential *webauthn.Credential,
) error {
	record := &device.OwnerCredentialRecord{
		Id:        credential.ID,
		OwnerId:   credential.OwnerID,
		PublicKey: credential.PublicKey,
	}
	return device.PutOwnerCredentialRecord(ctx, storage.client, record)
}

// GetDeviceCredentialID gets the device credential id from a public key credential id.
func GetDeviceCredentialID(credentialID []byte) string {
	return base58.Encode(credentialID)
}
