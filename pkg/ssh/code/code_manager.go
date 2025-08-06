package code

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/google/btree"
	"github.com/rs/zerolog/log"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type Status struct {
	Code       string
	BindingKey string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	State      session.SessionBindingRequestState
}

type codeManager struct {
	client           databroker.DataBrokerServiceClient
	accessMu         *sync.RWMutex
	codeByExpiration *btree.BTreeG[Status]
}

var _ databroker.SyncerHandler = (*codeManager)(nil)

func (c *codeManager) ClearRecords(_ context.Context) {
	c.accessMu.Lock()
	defer c.accessMu.Unlock()
	c.codeByExpiration.Clear(false)
}

func (c *codeManager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.client
}

func newCodeManager(
	client databroker.DataBrokerServiceClient,
) *codeManager {
	return &codeManager{
		client:   client,
		accessMu: &sync.RWMutex{},
		codeByExpiration: btree.NewG(2, func(a, b Status) bool {
			return cmp.Or(
				a.ExpiresAt.Compare(b.ExpiresAt),
				cmp.Compare(a.Code, b.Code),
				cmp.Compare(a.BindingKey, b.BindingKey),
			) < 0
		}),
	}
}

func (c *codeManager) GetByCodeID(codeID string) (Status, bool) {
	toFilter := []Status{}
	c.accessMu.RLock()
	c.codeByExpiration.AscendGreaterOrEqual(Status{
		Code: codeID,
	}, func(item Status) bool {
		if item.Code == codeID {
			toFilter = append(toFilter, item)
			return false
		}
		return true
	})
	c.accessMu.RUnlock()

	if len(toFilter) == 0 {
		return Status{}, false
	}

	slices.SortFunc(toFilter, func(a, b Status) int {
		return a.IssuedAt.Compare(b.IssuedAt)
	})

	n := len(toFilter) - 1
	return toFilter[n], true
}

func (c *codeManager) clearExpiredLocked() {
	toRemove := []Status{}
	c.codeByExpiration.AscendLessThan(Status{
		ExpiresAt: time.Now().Add(-DefaultCodeTTL),
	}, func(item Status) bool {
		toRemove = append(toRemove, item)
		return true
	})

	for _, el := range toRemove {
		c.codeByExpiration.Delete(el)
	}
}

func (c *codeManager) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	c.accessMu.Lock()
	defer c.accessMu.Unlock()
	c.clearExpiredLocked()
	for _, record := range records {
		codeID := record.GetId()

		s := &session.SessionBindingRequest{}
		if err := record.GetData().UnmarshalTo(s); err != nil {
			log.Err(err).
				Ctx(ctx).
				Str("component", "code-manager").
				Msg("UpdateRecords : failed to unmarshall session binding request")
			continue
		}
		c.codeByExpiration.ReplaceOrInsert(Status{
			Code:       codeID,
			BindingKey: s.GetKey(),
			IssuedAt:   s.GetCreatedAt().AsTime(),
			ExpiresAt:  s.GetExpiresAt().AsTime(),
			State:      s.State,
		})
	}
}
