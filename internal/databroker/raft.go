package databroker

import (
	"cmp"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/btree"
	"github.com/hashicorp/raft"
	hclogzerolog "github.com/weastur/hclog-zerolog"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// NewRaft creates a new Raft node from the given config.
func NewRaft(options config.DataBrokerOptions) (*raft.Raft, error) {
	if !options.ClusterNodeID.IsValid() {
		return nil, databrokerpb.ErrNoClusterNodeID
	}
	nodeID := options.ClusterNodeID.String

	if !options.RaftBindAddress.IsValid() {
		return nil, fmt.Errorf("databroker-raft: no raft bind address is defined")
	}
	nodeRaftBindAddress, err := net.ResolveTCPAddr("tcp", options.RaftBindAddress.String)
	if err != nil {
		return nil, fmt.Errorf("databroker-raft: invalid raft bind address: %w", err)
	}

	nodeRaftAdvertiseAddress := nodeRaftBindAddress
	for _, n := range options.ClusterNodes {
		if n.ID == nodeID && n.RaftAddress.IsValid() {
			nodeRaftAdvertiseAddress, err = net.ResolveTCPAddr("tcp", n.RaftAddress.String)
			if err != nil {
				return nil, fmt.Errorf("databroker-raft: invalid raft advertise address: %w", err)
			}
		}
	}

	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(nodeID)
	conf.Logger = hclogzerolog.NewWithCustomNameField(log.Logger().With().Str("component", "raft").Logger(), "name")

	fsm := newRaftFSM()
	logs := newRaftLogStore()
	stable := newRaftStableStore()
	snaps := newRaftSnapshotStore()
	trans, err := raft.NewTCPTransportWithLogger(
		nodeRaftBindAddress.String(),
		nodeRaftAdvertiseAddress,
		2,
		10*time.Second,
		hclogzerolog.NewWithCustomNameField(log.Logger().With().Str("component", "raft-net").Logger(), ""),
	)
	if err != nil {
		return nil, fmt.Errorf("databroker-raft: error creating network transport: %w", err)
	}

	r, err := raft.NewRaft(conf, fsm, logs, stable, snaps, trans)
	if err != nil {
		log.Error().Err(err).Msg("databroker-raft: error creating raft node")
		return nil, err
	}

	var configuration raft.Configuration
	for _, n := range options.ClusterNodes {
		configuration.Servers = append(configuration.Servers, raft.Server{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(n.ID),
			Address:  raft.ServerAddress(n.RaftAddress.String),
		})
	}
	err = r.BootstrapCluster(configuration).Error()
	if err != nil {
		log.Error().Err(err).Msg("databroker-raft: error bootstrapping cluster")
		return nil, err
	}

	return r, nil
}

type raftFSM struct{}

func newRaftFSM() raft.FSM {
	return &raftFSM{}
}

func (fsm *raftFSM) Apply(*raft.Log) any {
	return nil
}

func (fsm *raftFSM) Snapshot() (raft.FSMSnapshot, error) {
	return newRaftFSMSnapshot(), nil
}

func (fsm *raftFSM) Restore(snapshot io.ReadCloser) error {
	_, _ = io.Copy(io.Discard, snapshot)
	_ = snapshot.Close()
	return nil
}

type raftFSMSnapshot struct{}

func newRaftFSMSnapshot() raft.FSMSnapshot {
	return &raftFSMSnapshot{}
}

func (snapshot *raftFSMSnapshot) Persist(sink raft.SnapshotSink) error {
	return sink.Close()
}

func (snapshot *raftFSMSnapshot) Release() {
	// do nothing
}

type raftLogStore struct {
	mu   sync.RWMutex
	logs *btree.BTreeG[*raft.Log]
}

func newRaftLogStore() raft.LogStore {
	return &raftLogStore{
		logs: btree.NewG(8, func(log1, log2 *raft.Log) bool {
			return cmp.Compare(log1.Index, log2.Index) < 0
		}),
	}
}

func (store *raftLogStore) FirstIndex() (uint64, error) {
	store.mu.RLock()
	log, ok := store.logs.Min()
	store.mu.RUnlock()
	if !ok {
		return 0, nil
	}
	return log.Index, nil
}

func (store *raftLogStore) LastIndex() (uint64, error) {
	store.mu.RLock()
	log, ok := store.logs.Max()
	store.mu.RUnlock()
	if !ok {
		return 0, nil
	}
	return log.Index, nil
}

func (store *raftLogStore) GetLog(index uint64, log *raft.Log) error {
	store.mu.RLock()
	l, ok := store.logs.Get(&raft.Log{Index: index})
	store.mu.RUnlock()
	if !ok {
		return raft.ErrLogNotFound
	}
	*log = *l
	return nil
}

func (store *raftLogStore) StoreLog(log *raft.Log) error {
	store.mu.Lock()
	store.logs.ReplaceOrInsert(log)
	store.mu.Unlock()
	return nil
}

func (store *raftLogStore) StoreLogs(logs []*raft.Log) error {
	store.mu.Lock()
	for _, log := range logs {
		store.logs.ReplaceOrInsert(log)
	}
	store.mu.Unlock()
	return nil
}

func (store *raftLogStore) DeleteRange(minIndex, maxIndex uint64) error {
	store.mu.Lock()
	for i := minIndex; i <= maxIndex; i++ {
		_, _ = store.logs.Delete(&raft.Log{Index: i})
	}
	store.mu.Unlock()
	return nil
}

type raftStableStore struct {
	mu           sync.RWMutex
	bytesLookup  map[string][]byte
	uint64Lookup map[string]uint64
}

func newRaftStableStore() raft.StableStore {
	return &raftStableStore{
		bytesLookup:  make(map[string][]byte),
		uint64Lookup: make(map[string]uint64),
	}
}

func (store *raftStableStore) Set(key []byte, val []byte) error {
	store.mu.Lock()
	store.bytesLookup[string(key)] = val
	store.mu.Unlock()
	return nil
}

func (store *raftStableStore) Get(key []byte) ([]byte, error) {
	store.mu.RLock()
	val, ok := store.bytesLookup[string(key)]
	store.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return val, nil
}

func (store *raftStableStore) SetUint64(key []byte, val uint64) error {
	store.mu.Lock()
	store.uint64Lookup[string(key)] = val
	store.mu.Unlock()
	return nil
}

func (store *raftStableStore) GetUint64(key []byte) (uint64, error) {
	store.mu.RLock()
	val, ok := store.uint64Lookup[string(key)]
	store.mu.RUnlock()
	if !ok {
		return val, fmt.Errorf("not found")
	}
	return val, nil
}

type raftSnapshotStore struct {
	discardSnapshotStore raft.SnapshotStore
}

func newRaftSnapshotStore() raft.SnapshotStore {
	return &raftSnapshotStore{
		discardSnapshotStore: raft.NewDiscardSnapshotStore(),
	}
}

func (store *raftSnapshotStore) Create(version raft.SnapshotVersion, index, term uint64, configuration raft.Configuration, configurationIndex uint64, trans raft.Transport) (raft.SnapshotSink, error) {
	return store.discardSnapshotStore.Create(version, index, term, configuration, configurationIndex, trans)
}

func (store *raftSnapshotStore) List() ([]*raft.SnapshotMeta, error) {
	return store.discardSnapshotStore.List()
}

func (store *raftSnapshotStore) Open(id string) (*raft.SnapshotMeta, io.ReadCloser, error) {
	return store.discardSnapshotStore.Open(id)
}
