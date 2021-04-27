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

type encryptedRecordStream struct {
	underlying RecordStream
	backend    *encryptedBackend
	err        error
}

func (e *encryptedRecordStream) Close() error {
	return e.underlying.Close()
}

func (e *encryptedRecordStream) Next(wait bool) bool {
	return e.underlying.Next(wait)
}

func (e *encryptedRecordStream) Record() *databroker.Record {
	r := e.underlying.Record()
	if r != nil {
		var err error
		r, err = e.backend.decryptRecord(r)
		if err != nil {
			e.err = err
		}
	}
	return r
}

func (e *encryptedRecordStream) Err() error {
	if e.err == nil {
		e.err = e.underlying.Err()
	}
	return e.err
}

type encryptedBackend struct {
	underlying Backend
	cipher     cipher.AEAD
}

// NewEncryptedBackend creates a new encrypted backend.
func NewEncryptedBackend(secret []byte, underlying Backend) (Backend, error) {
	c, err := cryptutil.NewAEADCipher(secret)
	if err != nil {
		return nil, err
	}

	return &encryptedBackend{
		underlying: underlying,
		cipher:     c,
	}, nil
}

func (e *encryptedBackend) Close() error {
	return e.underlying.Close()
}

func (e *encryptedBackend) Get(ctx context.Context, recordType, id string) (*databroker.Record, error) {
	record, err := e.underlying.Get(ctx, recordType, id)
	if err != nil {
		return nil, err
	}
	record, err = e.decryptRecord(record)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func (e *encryptedBackend) GetAll(ctx context.Context) ([]*databroker.Record, *databroker.Versions, error) {
	records, versions, err := e.underlying.GetAll(ctx)
	if err != nil {
		return nil, versions, err
	}
	for i := range records {
		records[i], err = e.decryptRecord(records[i])
		if err != nil {
			return nil, versions, err
		}
	}
	return records, versions, nil
}

func (e *encryptedBackend) GetOptions(ctx context.Context, recordType string) (*databroker.Options, error) {
	return e.underlying.GetOptions(ctx, recordType)
}

func (e *encryptedBackend) Put(ctx context.Context, record *databroker.Record) (uint64, error) {
	encrypted, err := e.encrypt(record.GetData())
	if err != nil {
		return 0, err
	}

	newRecord := proto.Clone(record).(*databroker.Record)
	newRecord.Data = encrypted

	serverVersion, err := e.underlying.Put(ctx, newRecord)
	if err != nil {
		return 0, err
	}

	record.ModifiedAt = newRecord.ModifiedAt
	record.Version = newRecord.Version

	return serverVersion, nil
}

func (e *encryptedBackend) SetOptions(ctx context.Context, recordType string, options *databroker.Options) error {
	return e.underlying.SetOptions(ctx, recordType, options)
}

func (e *encryptedBackend) Sync(ctx context.Context, serverVersion, recordVersion uint64) (RecordStream, error) {
	stream, err := e.underlying.Sync(ctx, serverVersion, recordVersion)
	if err != nil {
		return nil, err
	}
	return &encryptedRecordStream{
		underlying: stream,
		backend:    e,
	}, nil
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
		ModifiedAt: in.ModifiedAt,
		DeletedAt:  in.DeletedAt,
	}, nil
}

func (e *encryptedBackend) decrypt(in *anypb.Any) (out *anypb.Any, err error) {
	if in == nil {
		return nil, nil
	}

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
