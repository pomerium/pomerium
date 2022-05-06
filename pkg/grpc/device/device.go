// Package device contains protobuf types for devices.
package device

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/encoding/base58"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// DeleteCredential deletes a credential from the databroker.
func DeleteCredential(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	credentialID string,
) (*Credential, error) {
	credential, err := GetCredential(ctx, client, credentialID)
	if status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	any := protoutil.NewAny(credential)
	_, err = client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type:      any.GetTypeUrl(),
			Id:        credentialID,
			Data:      any,
			DeletedAt: timestamppb.Now(),
		}},
	})
	return credential, err
}

// DeleteEnrollment deletes an enrollment from the databroker.
func DeleteEnrollment(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	enrollmentID string,
) (*Enrollment, error) {
	enrollment, err := GetEnrollment(ctx, client, enrollmentID)
	if status.Code(err) == codes.NotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	any := protoutil.NewAny(enrollment)
	_, err = client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type:      any.GetTypeUrl(),
			Id:        enrollmentID,
			Data:      any,
			DeletedAt: timestamppb.Now(),
		}},
	})
	return enrollment, err
}

// GetCredential gets a credential from the databroker.
func GetCredential(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	credentialID string,
) (*Credential, error) {
	any := protoutil.NewAny(new(Credential))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   credentialID,
	})
	if err != nil {
		return nil, err
	}

	var obj Credential
	err = res.GetRecord().GetData().UnmarshalTo(&obj)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling device credential from databroker: %w", err)
	}

	return &obj, nil
}

// GetEnrollment gets an enrollment from the databroker.
func GetEnrollment(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	enrollmentID string,
) (*Enrollment, error) {
	any := protoutil.NewAny(new(Enrollment))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   enrollmentID,
	})
	if err != nil {
		return nil, err
	}

	var obj Enrollment
	err = res.GetRecord().GetData().UnmarshalTo(&obj)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling device enrollment from databroker: %w", err)
	}

	return &obj, nil
}

// GetOwnerCredentialRecord gets an OwnerCredentialRecord from the databroker.
func GetOwnerCredentialRecord(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	credentialID []byte,
) (*OwnerCredentialRecord, error) {
	any := protoutil.NewAny(new(OwnerCredentialRecord))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   base58.Encode(credentialID),
	})
	if err != nil {
		return nil, err
	}

	var obj OwnerCredentialRecord
	err = res.GetRecord().GetData().UnmarshalTo(&obj)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling device owner credential record from databroker: %w", err)
	}

	return &obj, nil
}

// GetType gets a type from the databroker.
func GetType(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	typeID string,
) (*Type, error) {
	any := protoutil.NewAny(new(Type))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   typeID,
	})
	if err != nil {
		return nil, err
	}

	var obj Type
	err = res.GetRecord().GetData().UnmarshalTo(&obj)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling device type from databroker: %w", err)
	}

	return &obj, nil
}

// PutCredential puts a Credential in the databroker.
func PutCredential(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	credential *Credential,
) error {
	shrinkCredential(credential)

	any := protoutil.NewAny(credential)
	_, err := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: any.GetTypeUrl(),
			Id:   credential.GetId(),
			Data: any,
		}},
	})
	return err
}

// PutEnrollment puts an Entrollment in the databroker.
func PutEnrollment(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	enrollment *Enrollment,
) error {
	any := protoutil.NewAny(enrollment)
	_, err := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: any.GetTypeUrl(),
			Id:   enrollment.GetId(),
			Data: any,
		}},
	})
	return err
}

// PutOwnerCredentialRecord puts an OwnerCredentialRecord in the databroker.
func PutOwnerCredentialRecord(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	ownerCredentialRecord *OwnerCredentialRecord,
) error {
	any := protoutil.NewAny(ownerCredentialRecord)
	_, err := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: any.GetTypeUrl(),
			Id:   base58.Encode(ownerCredentialRecord.GetId()),
			Data: any,
		}},
	})
	return err
}

var maxCredentialSize = 256 * 1024

// shrinkCredential shrinks a credential object by removing unnecessary responses and options
// until its within the max credential size
func shrinkCredential(credential *Credential) {
	for len(protoutil.NewAny(credential).GetValue()) > maxCredentialSize {
		if specifier := credential.Specifier.(*Credential_Webauthn); specifier != nil {
			// (1) remove authenticate responses
			if len(specifier.Webauthn.AuthenticateResponse) > 0 {
				specifier.Webauthn.AuthenticateResponse = specifier.Webauthn.AuthenticateResponse[1:]
				continue
			}

			// (2) remove register response
			if len(specifier.Webauthn.RegisterResponse) > 0 {
				specifier.Webauthn.RegisterResponse = nil
				continue
			}

			// (3) remove register options
			if len(specifier.Webauthn.RegisterOptions) > 0 {
				specifier.Webauthn.RegisterOptions = nil
				continue
			}
		}

		break
	}
}
