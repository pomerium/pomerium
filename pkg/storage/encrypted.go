package storage

import (
	"context"
	"crypto/cipher"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type encryptedBackend struct {
	Backend
	cipher cipher.AEAD
}

// NewEncryptedBackend creates a new encrypted backend.
func NewEncryptedBackend(secret []byte, underlying Backend) (Backend, error) {
	c, err := cryptutil.NewAEADCipher(secret)
	if err != nil {
		return nil, err
	}

	return &encryptedBackend{
		Backend: underlying,
		cipher:  c,
	}, nil
}

func (e *encryptedBackend) Put(ctx context.Context, id string, data *anypb.Any) error {
	encrypted, err := e.encrypt(data)
	if err != nil {
		return err
	}
	return e.Backend.Put(ctx, id, encrypted)
}

func (e *encryptedBackend) Get(ctx context.Context, id string) (*databroker.Record, error) {
	record, err := e.Backend.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	record, err = e.decryptRecord(record)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func (e *encryptedBackend) GetAll(ctx context.Context) ([]*databroker.Record, error) {
	records, err := e.Backend.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i], err = e.decryptRecord(records[i])
		if err != nil {
			return nil, err
		}
	}
	return records, nil
}

func (e *encryptedBackend) List(ctx context.Context, sinceVersion string) ([]*databroker.Record, error) {
	records, err := e.Backend.List(ctx, sinceVersion)
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i], err = e.decryptRecord(records[i])
		if err != nil {
			return nil, err
		}
	}
	return records, nil
}

func (e *encryptedBackend) decryptRecord(in *databroker.Record) (out *databroker.Record, err error) {
	data, err := e.decrypt(in.Data)
	if err != nil {
		return nil, err
	}
	// Create a new record so that we don't re-use any internal state
	return &databroker.Record{
		Version:    in.Version,
		Type:       data.TypeUrl,
		Id:         in.Id,
		Data:       data,
		CreatedAt:  in.CreatedAt,
		ModifiedAt: in.ModifiedAt,
		DeletedAt:  in.DeletedAt,
	}, nil
}

func (e *encryptedBackend) decrypt(in *anypb.Any) (out *anypb.Any, err error) {
	var encrypted wrapperspb.BytesValue
	err = in.UnmarshalTo(&encrypted)
	if err != nil {
		return nil, err
	}

	plaintext, err := cryptutil.Decrypt(e.cipher, encrypted.Value, nil)
	if err != nil {
		return nil, err
	}

	out = new(anypb.Any)
	err = proto.Unmarshal(plaintext, out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (e *encryptedBackend) encrypt(in *anypb.Any) (out *anypb.Any, err error) {
	plaintext, err := proto.Marshal(in)
	if err != nil {
		return nil, err
	}

	encrypted := cryptutil.Encrypt(e.cipher, plaintext, nil)

	out, err = anypb.New(&wrapperspb.BytesValue{
		Value: encrypted,
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}
