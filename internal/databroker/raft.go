package databroker

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/btree"
	"github.com/hashicorp/raft"
	"github.com/volatiletech/null/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type raftDialFunc func(address raft.ServerAddress, timeout time.Duration) (net.Conn, error)

// NewRaft creates a new Raft node from the given config.
func NewRaft(cfg *config.Config, li databrokerpb.ByteStreamListener) (*raft.Raft, error) {
	clusterNodeID := cfg.Options.DataBroker.ClusterNodeID
	if !clusterNodeID.IsValid() {
		return nil, fmt.Errorf("raft: no cluster node id defined")
	}
	var clusterNodeURL null.String
	for _, n := range cfg.Options.DataBroker.ClusterNodes {
		if n.ID == clusterNodeID.String {
			clusterNodeURL = null.StringFrom(n.URL)
		}
	}
	if !clusterNodeURL.IsValid() {
		return nil, fmt.Errorf("raft: no cluster node url defined")
	}

	dial := func(address raft.ServerAddress, _ time.Duration) (net.Conn, error) {
		cc, err := grpc.NewClient(string(address), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		return databrokerpb.NewByteStreamConn(context.Background(), databrokerpb.NewByteStreamClient(cc))
	}

	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(clusterNodeID.String)

	r, err := raft.NewRaft(
		conf,
		newRaftFSM(),
		newRaftLogStore(),
		newRaftStableStore(),
		newRaftSnapshotStore(),
		newRaftTransport(li, dial),
	)
	if err != nil {
		return nil, err
	}

	raftConfig := raft.Configuration{}
	for _, n := range cfg.Options.DataBroker.ClusterNodes {
		raftConfig.Servers = append(raftConfig.Servers, raft.Server{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(n.ID),
			Address:  raft.ServerAddress(n.URL),
		})
	}
	err = r.BootstrapCluster(raftConfig).Error()
	if err != nil {
		_ = r.Shutdown().Error()
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

type raftTransport struct {
	networkTransport raft.Transport
}

func newRaftTransport(listener net.Listener, dial raftDialFunc) raft.Transport {
	return &raftTransport{
		networkTransport: raft.NewNetworkTransport(newRaftStreamLayer(listener, dial), 1, time.Minute, nil),
	}
}

func (transport *raftTransport) Consumer() <-chan raft.RPC {
	return transport.networkTransport.Consumer()
}

func (transport *raftTransport) LocalAddr() raft.ServerAddress {
	return transport.networkTransport.LocalAddr()
}

func (transport *raftTransport) AppendEntriesPipeline(id raft.ServerID, target raft.ServerAddress) (raft.AppendPipeline, error) {
	return transport.networkTransport.AppendEntriesPipeline(id, target)
}

func (transport *raftTransport) AppendEntries(id raft.ServerID, target raft.ServerAddress, args *raft.AppendEntriesRequest, resp *raft.AppendEntriesResponse) error {
	return transport.networkTransport.AppendEntries(id, target, args, resp)
}

func (transport *raftTransport) RequestVote(id raft.ServerID, target raft.ServerAddress, args *raft.RequestVoteRequest, resp *raft.RequestVoteResponse) error {
	return transport.networkTransport.RequestVote(id, target, args, resp)
}

func (transport *raftTransport) InstallSnapshot(id raft.ServerID, target raft.ServerAddress, args *raft.InstallSnapshotRequest, resp *raft.InstallSnapshotResponse, data io.Reader) error {
	return transport.networkTransport.InstallSnapshot(id, target, args, resp, data)
}

func (transport *raftTransport) EncodePeer(id raft.ServerID, addr raft.ServerAddress) []byte {
	return transport.networkTransport.EncodePeer(id, addr)
}

func (transport *raftTransport) DecodePeer(bs []byte) raft.ServerAddress {
	return transport.networkTransport.DecodePeer(bs)
}

func (transport *raftTransport) SetHeartbeatHandler(cb func(rpc raft.RPC)) {
	transport.networkTransport.SetHeartbeatHandler(cb)
}

func (transport *raftTransport) TimeoutNow(id raft.ServerID, target raft.ServerAddress, args *raft.TimeoutNowRequest, resp *raft.TimeoutNowResponse) error {
	return transport.networkTransport.TimeoutNow(id, target, args, resp)
}

type raftStreamLayer struct {
	listener net.Listener
	dial     raftDialFunc
}

func newRaftStreamLayer(listener net.Listener, dial raftDialFunc) raft.StreamLayer {
	return &raftStreamLayer{listener: listener, dial: dial}
}

func (layer *raftStreamLayer) Accept() (net.Conn, error) {
	return layer.listener.Accept()
}

func (layer *raftStreamLayer) Addr() net.Addr {
	return layer.listener.Addr()
}

func (layer *raftStreamLayer) Close() error {
	return layer.listener.Close()
}

func (layer *raftStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	return layer.dial(address, timeout)
}
