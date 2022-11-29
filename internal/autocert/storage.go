package autocert

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

const certMagicStorageRecordType = "pomerium.io/CertMagicStorageRecord"

type dataBrokerStorage struct {
	client *atomicutil.Value[databroker.DataBrokerServiceClient]

	lockersMu sync.Mutex
	lockers   map[string]*dataBrokerLocker
}

func newDataBrokerStorage(client *atomicutil.Value[databroker.DataBrokerServiceClient]) *dataBrokerStorage {
	return &dataBrokerStorage{
		client:  client,
		lockers: make(map[string]*dataBrokerLocker),
	}
}

func (s *dataBrokerStorage) Lock(ctx context.Context, name string) error {
	name = fmt.Sprintf("autocert/%s", name)

	s.lockersMu.Lock()
	l, ok := s.lockers[name]
	if !ok {
		l = newDataBrokerLocker(name, s.client)
		s.lockers[name] = l
	}
	s.lockersMu.Unlock()

	return l.Lock(ctx)
}

func (s *dataBrokerStorage) Unlock(ctx context.Context, name string) error {
	name = fmt.Sprintf("autocert/%s", name)

	s.lockersMu.Lock()
	l, ok := s.lockers[name]
	delete(s.lockers, name)
	s.lockersMu.Unlock()

	if !ok {
		return nil
	}
	return l.Unlock(ctx)
}

func (s *dataBrokerStorage) Store(ctx context.Context, key string, value []byte) error {
	_, err := s.client.Load().Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			{Type: certMagicStorageRecordType, Id: key, Data: protoutil.NewAny(wrapperspb.Bytes(value))},
		},
	})
	return err
}

func (s *dataBrokerStorage) Load(ctx context.Context, key string) ([]byte, error) {
	value, _, err := s.load(ctx, key)
	return value, err
}

func (s *dataBrokerStorage) Delete(ctx context.Context, key string) error {
	res, err := s.client.Load().Get(ctx, &databroker.GetRequest{
		Type: certMagicStorageRecordType,
		Id:   key,
	})
	if storage.IsNotFound(err) {
		// delete should not return an error if the key is already deleted
		return nil
	} else if err != nil {
		return err
	}

	record := res.GetRecord()
	record.DeletedAt = timestamppb.Now()

	_, err = s.client.Load().Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{record},
	})
	return err
}

func (s *dataBrokerStorage) Exists(ctx context.Context, key string) bool {
	_, _, err := s.load(ctx, key)
	return err == nil
}

func (s *dataBrokerStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	records, _, _, err := databroker.InitialSync(ctx, s.client.Load(), &databroker.SyncLatestRequest{
		Type: certMagicStorageRecordType,
	})
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, record := range records {
		key := record.GetId()

		if !strings.HasPrefix(key, prefix) {
			continue
		}

		if !recursive && strings.Contains(key[len(prefix):], "/") {
			continue
		}

		keys = append(keys, key)
	}
	return keys, nil
}

func (s *dataBrokerStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	value, modifiedAt, err := s.load(ctx, key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   modifiedAt,
		Size:       int64(len(value)),
		IsTerminal: true,
	}, nil
}

func (s *dataBrokerStorage) load(ctx context.Context, key string) (value []byte, modifiedAt time.Time, err error) {
	res, err := s.client.Load().Get(ctx, &databroker.GetRequest{
		Type: certMagicStorageRecordType,
		Id:   key,
	})
	if storage.IsNotFound(err) {
		return nil, time.Time{}, fs.ErrNotExist
	} else if err != nil {
		return nil, time.Time{}, err
	}

	var data wrapperspb.BytesValue
	err = res.GetRecord().GetData().UnmarshalTo(&data)
	if err != nil {
		// if the stored value isn't what we expect, just treat it like it doesn't exist
		return nil, time.Time{}, fs.ErrNotExist
	}

	return data.GetValue(), res.GetRecord().GetModifiedAt().AsTime(), nil
}
