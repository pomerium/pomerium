package evaluator

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A Store stores data for the OPA rego policy evaluation.
type Store struct {
	opaStore storage.Store
}

// NewStore creates a new Store.
func NewStore() *Store {
	return &Store{
		opaStore: inmem.New(),
	}
}

// ClearRecords removes all the records from the store.
func (s *Store) ClearRecords(typeURL string) {
	rawPath := fmt.Sprintf("/databroker_data/%s", typeURL)
	s.delete(rawPath)
}

// UpdateRoutePolicies updates the route policies in the store.
func (s *Store) UpdateRoutePolicies(routePolicies []config.Policy) {
	s.write("/route_policies", routePolicies)
}

// UpdateRecord updates a record in the store.
func (s *Store) UpdateRecord(record *databroker.Record) {
	rawPath := fmt.Sprintf("/databroker_data/%s/%s", record.GetType(), record.GetId())

	if record.GetDeletedAt() != nil {
		s.delete(rawPath)
		return
	}

	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		log.Error().Err(err).
			Str("path", rawPath).
			Msg("opa-store: error unmarshaling record data, ignoring")
		return
	}

	s.write(rawPath, msg)
}

func (s *Store) delete(rawPath string) {
	p, ok := storage.ParsePath(rawPath)
	if !ok {
		log.Error().
			Str("path", rawPath).
			Msg("opa-store: invalid path, ignoring data")
		return
	}

	err := storage.Txn(context.Background(), s.opaStore, storage.WriteParams, func(txn storage.Transaction) error {
		_, err := s.opaStore.Read(context.Background(), txn, p)
		if storage.IsNotFound(err) {
			return nil
		} else if err != nil {
			return err
		}

		err = s.opaStore.Write(context.Background(), txn, storage.RemoveOp, p, nil)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		log.Error().Err(err).Msg("opa-store: error deleting data")
		return
	}
}

func (s *Store) write(rawPath string, value interface{}) {
	p, ok := storage.ParsePath(rawPath)
	if !ok {
		log.Error().
			Str("path", rawPath).
			Msg("opa-store: invalid path, ignoring data")
		return
	}

	err := storage.Txn(context.Background(), s.opaStore, storage.WriteParams, func(txn storage.Transaction) error {
		if len(p) > 1 {
			err := storage.MakeDir(context.Background(), s.opaStore, txn, p[:len(p)-1])
			if err != nil {
				return err
			}
		}

		var op storage.PatchOp = storage.ReplaceOp
		_, err := s.opaStore.Read(context.Background(), txn, p)
		if storage.IsNotFound(err) {
			op = storage.AddOp
		} else if err != nil {
			return err
		}

		return s.opaStore.Write(context.Background(), txn, op, p, value)
	})
	if err != nil {
		log.Error().Err(err).Msg("opa-store: error writing data")
		return
	}
}
