package store

import (
	"encoding/binary"
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"google.golang.org/protobuf/types/known/structpb"
)

var queryRequestPool = sync.Pool{
	New: func() any {
		idOrIndex := &structpb.Value_StringValue{}
		pqr := &PooledQueryRequest{
			qr: &databroker.QueryRequest{
				Limit: 1,
				Filter: &structpb.Struct{Fields: map[string]*structpb.Value{
					"$or": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
						structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
							"id": {Kind: idOrIndex},
						}}),
						structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
							"$index": {Kind: idOrIndex},
						}}),
					}}),
				}},
			},
			idOrIndex: idOrIndex,
		}
		return pqr
	},
}

type PooledQueryRequest struct {
	qr       *databroker.QueryRequest
	cacheKey [16]byte

	idOrIndex *structpb.Value_StringValue
}

func (pqr *PooledQueryRequest) SetRecordType(recordType string) {
	pqr.qr.Type = recordType
	binary.LittleEndian.PutUint64(pqr.cacheKey[0:8], xxhash.Sum64String(recordType))
}

func (pqr *PooledQueryRequest) SetIDOrIndex(idOrIndex string) {
	pqr.idOrIndex.StringValue = idOrIndex
	binary.LittleEndian.PutUint64(pqr.cacheKey[8:16], xxhash.Sum64String(idOrIndex))
}

func (pqr *PooledQueryRequest) Request() *databroker.QueryRequest {
	return pqr.qr
}

func (pqr *PooledQueryRequest) CacheKey() []byte {
	return pqr.cacheKey[:]
}

func (pqr *PooledQueryRequest) Release() {
	queryRequestPool.Put(pqr)
}

func GetPooledQueryRequest() *PooledQueryRequest {
	pqr := queryRequestPool.Get().(*PooledQueryRequest)
	pqr.qr.Type = ""
	pqr.idOrIndex.StringValue = ""
	clear(pqr.cacheKey[:])
	return pqr
}
